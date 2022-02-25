use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocols::thresholdsig::bitcoin_schnorr as party_i;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::traits::*;
use curv::BigInt;

use crate::protocols::threshold_schnorr::state_machine::keygen::{BroadcastPhase1, LocalKey};

type BlindFactor = BigInt;
type KeyGenCom = party_i::KeyGenBroadcastMessage1;
type KeyGenDecomn = BlindFactor;

pub struct Round0 {
    pub private_key: LocalKey,
    pub message: Vec<u8>,
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
    pub parties: Vec<usize>,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<BroadcastPhase1>>,
    {
        let keys = party_i::Keys::phase1_create(usize::from(self.party_i) - 1);
        let (comm, decom) = keys.phase1_broadcast();

        let mybroadcast = BroadcastPhase1 {
            comm,
            decom,
            y_i: keys.y_i,
            index: keys.party_index,
        };

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: mybroadcast.clone(),
        });
        Ok(Round1 {
            keys,
            mybroadcast,

            private_key: self.private_key,
            message: self.message,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
            parties: self.parties,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    keys: party_i::Keys,
    mybroadcast: BroadcastPhase1,

    pub private_key: LocalKey,
    pub message: Vec<u8>,
    party_i: u16,
    t: u16,
    n: u16,
    parties: Vec<usize>,
}

impl Round1 {
    pub fn proceed<O>(self, input: BroadcastMsgs<BroadcastPhase1>, mut output: O) -> Result<Round2>
    where
        O: Push<Msg<(VerifiableSS<GE>, FE)>>,
    {
        let params = party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_decom = input.into_vec_including_me(self.mybroadcast);
        let boardcast_received: Vec<((KeyGenCom, KeyGenDecomn), (GE, usize))> = received_decom
            .into_iter()
            .map(
                |BroadcastPhase1 {
                     comm,
                     decom,
                     y_i,
                     index,
                 }| ((comm, decom), (y_i, index)),
            )
            .collect();

        let ((a, b), (c, d)): ((Vec<KeyGenCom>, Vec<KeyGenDecomn>), (Vec<GE>, Vec<usize>)) =
            boardcast_received.iter().cloned().unzip();

        let d: Vec<_> = d.into_iter().map(|i| usize::from(i) + 1).collect();
        println!("{:?}", d);

        let (vss_scheme, secret_shares, index) = self
            .keys
            .phase1_verify_com_phase2_distribute(&params, &b, &c, &a, &d)
            .map_err(ProceedError::Round1)?;
        for (i, share) in secret_shares.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: (vss_scheme.clone(), share.clone()),
            })
        }

        Ok(Round2 {
            keys: self.keys,
            index,
            own_vss: vss_scheme,
            own_share: secret_shares[usize::from(self.party_i - 1)],
            y_vec: c,

            private_key: self.private_key,
            message: self.message,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
            parties: d,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<BroadcastPhase1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    keys: party_i::Keys,
    index: usize,
    own_vss: VerifiableSS<GE>,
    own_share: FE,
    y_vec: Vec<GE>,

    private_key: LocalKey,
    message: Vec<u8>,
    party_i: u16,
    t: u16,
    n: u16,
    parties: Vec<usize>,
}

impl Round2 {
    pub fn proceed<O>(self, input: P2PMsgs<(VerifiableSS<GE>, FE)>, mut output: O) -> Result<Round3>
    where
        O: Push<Msg<party_i::LocalSig>>,
    {
        let params = party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_data = input.into_vec_including_me((self.own_vss.clone(), self.own_share));
        let (a, b): (Vec<VerifiableSS<GE>>, Vec<FE>) = received_data.iter().cloned().unzip();
        let shared_keys = self
            .keys
            .phase2_verify_vss_construct_keypair(
                &params,
                &self.y_vec.clone(),
                &b,
                &a,
                &(self.index + 1),
            )
            .map_err(ProceedError::Round2)?;

        let local_sig =
            party_i::LocalSig::compute(&self.message, &shared_keys, &self.private_key.shared_keys);
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: local_sig.clone(),
        });
        let temp_key = LocalKey {
            shared_keys,
            vss_scheme: self.own_vss,
            vk_vec: self.y_vec.clone(),
            vss_scheme_vec: a,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        };
        Ok(Round3 {
            tmpkey: temp_key,
            local_sig,
            y_vec: self.y_vec,

            private_key: self.private_key,
            message: self.message,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
            parties: self.parties,
        })
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(VerifiableSS<GE>, FE)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

pub struct Round3 {
    tmpkey: LocalKey,
    local_sig: party_i::LocalSig,
    y_vec: Vec<GE>,

    private_key: LocalKey,
    message: Vec<u8>,
    party_i: u16,
    t: u16,
    n: u16,
    parties: Vec<usize>,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<party_i::LocalSig>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<GE>>,
    {
        let gamma_vec = input.into_vec_including_me(self.local_sig.clone());

        let vss_private_keys = self.private_key.clone().vss_scheme_vec;
        let vss_ephemeral_keys = self.tmpkey.clone().vss_scheme_vec;
        let i = usize::from(self.party_i) - 1;

        println!("{:?} {:?} ",vss_private_keys.len(),vss_ephemeral_keys.len());

        println!("{:?} {:?} ",vss_private_keys[0].commitments.len(),vss_ephemeral_keys[0].commitments.len());

        let mut key_gen_comm_i_vec = (0..vss_private_keys.len())
            .map(|j| vss_private_keys[j].commitments[i].clone() * &gamma_vec[i].e)
            .collect::<Vec<GE>>();
        let mut eph_comm_i_vec = (0..vss_ephemeral_keys.len())
            .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
            .collect::<Vec<GE>>();
        key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
        let mut comm_i_vec_iter = key_gen_comm_i_vec.iter();
        let comm_i_0 = comm_i_vec_iter.next().unwrap();
        let comm_to_broadcast = comm_i_vec_iter.fold(comm_i_0.clone(), |acc, x| acc + x);

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: comm_to_broadcast.clone(),
        });

        Ok(Round4 {
            tmpkey: self.tmpkey,
            local_sig: self.local_sig,
            y_vec: self.y_vec,
            comm: comm_to_broadcast,
            local_sig_vec: gamma_vec,

            private_key: self.private_key,
            message: self.message,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
            parties: self.parties,
        })
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<party_i::LocalSig>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    tmpkey: LocalKey,
    local_sig: party_i::LocalSig,
    y_vec: Vec<GE>,
    comm: GE,
    local_sig_vec: Vec<party_i::LocalSig>,

    private_key: LocalKey,
    message: Vec<u8>,
    party_i: u16,
    t: u16,
    n: u16,
    parties: Vec<usize>,
}

impl Round4 {
    pub fn proceed<O>(self, input: BroadcastMsgs<GE>, mut output: O) -> Result<Round5>
    where
        O: Push<Msg<bool>>,
    {
        let comm_vec = input.into_vec_including_me(self.comm);

        let vss_sum = VerifiableSS {
            parameters: self.private_key.vss_scheme.parameters.clone(),
            commitments: comm_vec,
        };

        let gamma_i_g = &GE::generator() * &self.local_sig.gamma_i;
        let validate_result = vss_sum
            .validate_share_public(&gamma_i_g, usize::from(self.party_i))
            .is_ok();

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: validate_result,
        });

        Ok(Round5 {
            tmpkey: self.tmpkey,
            local_sig: self.local_sig,
            y_vec: self.y_vec,
            own_result: validate_result,
            local_sig_vec: self.local_sig_vec,
            vss_sum,

            private_key: self.private_key,
            message: self.message,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
            parties: self.parties,
        })
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<GE>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round5 {
    tmpkey: LocalKey,
    local_sig: party_i::LocalSig,
    y_vec: Vec<GE>,
    own_result: bool,
    local_sig_vec: Vec<party_i::LocalSig>,
    vss_sum: VerifiableSS<GE>,

    private_key: LocalKey,
    message: Vec<u8>,
    party_i: u16,
    t: u16,
    n: u16,
    parties: Vec<usize>,
}

impl Round5 {
    pub fn proceed(self, input: BroadcastMsgs<bool>) -> Result<SigRes> {
        let params = party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let comm_vec = input.into_vec_including_me(self.own_result);
        use Error::InvalidSig;
        let res = comm_vec.iter().all(|x| x.clone() == true);
        if res == false {
            return Err(ProceedError::Round5(InvalidSig));
        }

        let signature = party_i::Signature::generate(
            &self.vss_sum,
            &self.local_sig_vec,
            &self.parties,
            self.tmpkey.public_key(),
        );

        Ok(SigRes { signature })
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<bool>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

#[derive(Clone, PartialEq)]
pub struct SigRes {
    pub signature: party_i::Signature,
}

// Errors

type Result<T> = std::result::Result<T, ProceedError>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 0: unknown : {0:?}")]
    Round0(crate::Error),
    #[error("round 1: verify_com_phase2_distribute : {0:?}")]
    Round1(crate::Error),
    #[error("round 2: verify_vss_construct : {0:?}")]
    Round2(crate::Error),
    #[error("round 3: verify_vss_construct : {0:?}")]
    Round3(crate::Error),
    #[error("round 4: verify_vss_construct : {0:?}")]
    Round4(crate::Error),
    #[error("round 5: verify_vss_construct : {0:?}")]
    Round5(crate::Error),
}
