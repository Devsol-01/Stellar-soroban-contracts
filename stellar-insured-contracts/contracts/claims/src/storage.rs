use soroban_sdk::{contracttype, Address};

use crate::types::ClaimStatus;

#[contracttype]
#[derive(Clone)]
pub struct Claim {
    pub id: u64,
    pub claimant: Address,
    pub status: ClaimStatus,
    pub decision_ts: Option<u64>,
    pub dispute_window_end: Option<u64>,
}
