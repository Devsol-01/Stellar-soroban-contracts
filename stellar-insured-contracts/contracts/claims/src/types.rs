use soroban_sdk::contracttype;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimStatus {
    Submitted,
    Approved,
    Rejected,
    PendingSettlement,
    Disputed,
    Settled,
}
