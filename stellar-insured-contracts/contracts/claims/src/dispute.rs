use soroban_sdk::{contracttype, Address};

#[contracttype]
#[derive(Clone)]
pub struct Dispute {
    pub claim_id: u64,
    pub raised_by: Address,
    pub reason: soroban_sdk::String,
    pub resolved: bool,
}
