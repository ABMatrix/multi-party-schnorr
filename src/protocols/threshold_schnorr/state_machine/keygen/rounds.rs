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

pub struct BroadcastPhase1{
    pub comm: KeyGenCom,
    pub decom: KeyGenDecomn,
    pub y_i: GE,
}

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
    pub parties: Vec<u8>,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
        where
            O: Push<Msg<KeyGenCom>>,
    {
        let keys = party_i::Keys::phase1_create(usize::from(self.party_i) - 1);
        let (comm, decom) = keys.phase1_broadcast();

        let mybroadcast = BroadcastPhase1{
            comm,
            decom,
            y_i: keys.y_i
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
    parties: Vec<u8>,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<BroadcastPhase1>,
        mut output: O,
    ) -> Result<Round3>
        where
            O: Push<Msg<(VerifiableSS<GE>, FE)>>,
    {
        let params = party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_decom = input.into_vec_including_me(self.mybroadcast);
        let sep: Vec<(KeyGenCom,(KeyGenDecomn,GE))> = received_decom.into_iter().map(|BroadcastPhase1{comm,decom,y_i}|{
            (comm,(decom,y_i))
        }).collect();

        let (a, (b, c)): (Vec<KeyGenCom>, (Vec<KeyGenDecomn>, Vec<GE>)) = sep.iter().cloned().unzip();

        let (vss_scheme, secret_shares, index) = self
            .keys
            .phase1_verify_com_phase2_distribute(&params,
                                                 &b,
                                                 &c,
                                                 &a,
                                                 &parties)
            .map_err(ProceedError::Round2VerifyCommitments)?;
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

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),

            index,
            own_vss: vss_scheme,
            own_share: secret_shares[usize::from(self.party_i - 1)],

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<party_i::KeyGenDecom>> {
        containers::BroadcastMsgsStore::new(i, n)
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
        #[error("round 2: verify commitments: {0:?}")]
        Round2VerifyCommitments(crate::Error),
        #[error("round 3: verify vss construction: {0:?}")]
        Round3VerifyVssConstruct(crate::Error),
        #[error("round 4: verify dlog proof: {0:?}")]
        Round4VerifyDLogProof(crate::Error),
    }
