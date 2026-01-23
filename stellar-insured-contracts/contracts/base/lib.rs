#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Env, Symbol,
};

/// -------------------------
/// Storage Keys
/// -------------------------
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
    PolicyContract,
    Claim(u64),
    NextClaimId,
}

/// -------------------------
/// Claim Data Structure
/// -------------------------
#[derive(Clone)]
#[contracttype]
pub struct Claim {
    pub id: u64,
    pub claimant: Address,
    pub policy_id: u64,
    pub amount: i128,
    pub approved: bool,
}

/// -------------------------
/// Claims Contract
/// -------------------------
#[contract]
pub struct ClaimsContract;

#[contractimpl]
impl ClaimsContract {
    /// -----------------------------------
    /// Admin initialization
    /// -----------------------------------
    pub fn init(env: Env, admin: Address, policy_contract: Address) {
        // Prevent re-initialization
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("Contract already initialized");
        }

        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::PolicyContract, &policy_contract);
        env.storage()
            .instance()
            .set(&DataKey::NextClaimId, &0u64);
    }

    /// -----------------------------------
    /// Create a new claim
    /// -----------------------------------
    pub fn create_claim(
        env: Env,
        claimant: Address,
        policy_id: u64,
        amount: i128,
    ) -> u64 {
        claimant.require_auth();

        let mut next_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextClaimId)
            .unwrap();

        let claim = Claim {
            id: next_id,
            claimant,
            policy_id,
            amount,
            approved: false,
        };

        env.storage()
            .instance()
            .set(&DataKey::Claim(next_id), &claim);

        next_id += 1;
        env.storage()
            .instance()
            .set(&DataKey::NextClaimId, &next_id);

        claim.id
    }

    /// -----------------------------------
    /// Getter: admin address
    /// -----------------------------------
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap()
    }

    /// -----------------------------------
    /// Getter: policy contract reference
    /// -----------------------------------
    pub fn get_policy_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::PolicyContract)
            .unwrap()
    }

    /// -----------------------------------
    /// Getter: single claim by ID
    /// -----------------------------------
    pub fn get_claim(env: Env, claim_id: u64) -> Claim {
        env.storage()
            .instance()
            .get(&DataKey::Claim(claim_id))
            .unwrap()
    }

    /// -----------------------------------
    /// Getter: next claim ID
    /// -----------------------------------
    pub fn get_next_claim_id(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::NextClaimId)
            .unwrap()
    }
}
