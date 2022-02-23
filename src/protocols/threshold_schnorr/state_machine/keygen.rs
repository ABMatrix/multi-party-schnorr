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

mod rounds;
pub use self::rounds::{BroadcastPhase1, LocalKey, ProceedError};
use self::rounds::{Round0, Round1, Round2};

/// Keygen protocol state machine
///
/// Successfully completed keygen protocol produces [LocalKey] that can be used in further
/// [signing](super::sign::Sign) protocol.
pub struct Keygen {
    round: R,

    msgs1: Option<Store<BroadcastMsgs<BroadcastPhase1>>>,
    msgs2: Option<Store<P2PMsgs<(VerifiableSS<GE>, FE)>>>,

    msgs_queue: Vec<Msg<ProtocolMessage>>,

    party_i: u16,
    party_n: u16,
}

enum R {
    Round0(Round0),
    Round1(Round1),
    Round2(Round2),
    Final(LocalKey),
    Gone,
}

// Messages

/// Protocol message which parties send on wire
///
/// Hides actual messages structure so it could be changed without breaking semver policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage(M);

#[derive(Clone, Debug, Serialize, Deserialize)]
enum M {
    Round1(BroadcastPhase1),
    Round2((VerifiableSS<GE>, FE)),
}
