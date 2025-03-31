//! JSON serialization

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use ergotree_interpreter::sigma_protocol::prover::ProofBytes;

pub(crate) mod hint;
pub(crate) mod transaction;

/// Serde remote type
#[cfg_attr(
    feature = "json",
    derive(Serialize, Deserialize),
    serde(into = "String", try_from = "String"),
    serde(remote = "ProofBytes")
)]
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub enum ProofBytesSerde {
    /// Empty proof
    Empty,
    /// Non-empty proof
    Some(Vec<u8>),
}
