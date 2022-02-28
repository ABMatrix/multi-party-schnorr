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
use curv::BigInt;

type BlindFactor = BigInt;
type KeyGenCom = party_i::KeyGenBroadcastMessage1;
type KeyGenDecomn = BlindFactor;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastPhase1 {
    pub comm: KeyGenCom,
    pub decom: KeyGenDecomn,
    pub y_i: GE,
    pub index: usize,
}

pub struct Round0 {
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

            party_i: self.party_i,
            t: self.t,
            n: self.n,
            parties: self.parties,
            y_vec: c,
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

    party_i: u16,
    t: u16,
    n: u16,
    parties: Vec<usize>,
}

impl Round2 {
    pub fn proceed(self, input: P2PMsgs<(VerifiableSS<GE>, FE)>) -> Result<LocalKey> {
        let params = party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_data = input.into_vec_including_me((self.own_vss.clone(), self.own_share));
        let (a, b): (Vec<VerifiableSS<GE>>, Vec<FE>) = received_data.iter().cloned().unzip();
        let shared_keys = self
            .keys
            .phase2_verify_vss_construct_keypair(&params, &self.y_vec, &b, &a, &(self.index + 1))
            .map_err(ProceedError::Round2)?;
        Ok(LocalKey {
            shared_keys,
            vss_scheme: self.own_vss,
            vk_vec: self.y_vec,
            vss_scheme_vec: a,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(VerifiableSS<GE>, FE)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalKey {
    pub shared_keys: party_i::SharedKeys,
    pub vss_scheme: VerifiableSS<GE>,
    pub vk_vec: Vec<GE>,
    pub vss_scheme_vec: Vec<VerifiableSS<GE>>,

    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl LocalKey {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> GE {
        self.shared_keys.y
    }
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
}
