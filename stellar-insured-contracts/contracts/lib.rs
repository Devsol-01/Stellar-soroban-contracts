#![no_std]
//! Shared library for Stellar Insured Soroban contracts
//!
//! This module contains common types, utilities, and error handling
//! used across all insurance contracts in the Stellar Insured ecosystem.

#![no_std]

use soroban_sdk::{contracttype, Address, Env, Symbol, String, BytesN};

/// Re-export authorization module for easy access
/// Import authorization functions like: use insurance_contracts::authorization::*;
pub mod authorization {
    pub use authorization::{
        Role, RoleKey, AuthError,
        initialize_admin, get_admin, grant_role, revoke_role, get_role,
        has_role, require_role, require_admin, has_any_role, require_any_role,
        require_policy_management, require_claim_processing,
        require_risk_pool_management, require_governance_permission,
        register_trusted_contract, unregister_trusted_contract,
        is_trusted_contract, require_trusted_contract,
        verify_and_require_role, verify_and_check_permission,
    };
}

/// Common contract types shared across all insurance contracts
pub mod types {
    use super::*;

    /// Policy status enumeration
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum PolicyStatus {
        Active,
        Expired,
        Cancelled,
        Claimed,
    }

    /// Claim status enumeration
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ClaimStatus {
        Submitted,
        UnderReview,
        Approved,
        Rejected,
        Settled,
    }

    /// Governance proposal status
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ProposalStatus {
        Active,
        Passed,
        Rejected,
        Executed,
    }

    /// Vote type for governance
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum VoteType {
        Yes,
        No,
    }

    /// Evidence record (hash-only, immutable)
    #[contracttype]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ClaimEvidence {
        pub claim_id: BytesN<32>,
        pub evidence_hash: BytesN<32>, // SHA-256
        pub submitter: Address,
    }

    /// Common data keys for contract storage
    #[contracttype]
    #[derive(Clone, Debug)]
    pub enum DataKey {
        Admin,
        Paused,
        Config,
        Counter(Symbol),

        /// Claim evidence storage
        ClaimEvidence(BytesN<32>), // claim_id → evidence
    }
}

/// Common error types for insurance contracts
pub mod errors {
    use soroban_sdk::{contracterror, Error};

    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub enum ContractError {
        Unauthorized = 1,
        Paused = 2,
        InvalidInput = 3,
        InsufficientFunds = 4,
        NotFound = 5,
        AlreadyExists = 6,
        InvalidState = 7,
        Overflow = 8,
        NotInitialized = 9,
        AlreadyInitialized = 10,
        /// Invalid role or permission
        InvalidRole = 11,
        /// Role not found
        RoleNotFound = 12,
        /// Contract not trusted for cross-contract calls
        NotTrustedContract = 13,
    }
    
    /// Convert authorization errors to contract errors
    impl From<super::authorization::AuthError> for ContractError {
        fn from(err: super::authorization::AuthError) -> Self {
            match err {
                super::authorization::AuthError::Unauthorized => ContractError::Unauthorized,
                super::authorization::AuthError::InvalidRole => ContractError::InvalidRole,
                super::authorization::AuthError::RoleNotFound => ContractError::RoleNotFound,
                super::authorization::AuthError::NotTrustedContract => ContractError::NotTrustedContract,
            }
        }

        /// 🔐 Evidence-specific errors
        EvidenceAlreadyExists = 20,
        EvidenceNotFound = 21,
        InvalidEvidenceHash = 22,
    }
}

/// Utility functions for contract operations
pub mod utils {
    use super::*;
    use crate::{errors::ContractError, types::*};
    use soroban_sdk::Vec;

    /// Validate that an address is valid
    pub fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
        Ok(())
    }

    /// Check if contract is paused
    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Set contract pause status
    pub fn set_paused(env: &Env, paused: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::Paused, &paused);
    }

    /// Get next ID for a given counter
    pub fn next_id(env: &Env, counter_name: &str) -> u64 {
        let key = DataKey::Counter(Symbol::new(env, counter_name));
        let current_id = env.storage().persistent().get(&key).unwrap_or(0u64);
        let next_id = current_id + 1;
        env.storage().persistent().set(&key, &next_id);
        next_id
    }

    /// 🔐 Store claim evidence hash (immutable)
    pub fn store_claim_evidence(
        env: &Env,
        claim_id: BytesN<32>,
        evidence_hash: BytesN<32>,
        submitter: Address,
    ) -> Result<(), ContractError> {
        let key = DataKey::ClaimEvidence(claim_id.clone());

        if env.storage().persistent().has(&key) {
            return Err(ContractError::EvidenceAlreadyExists);
        }

        submitter.require_auth();

        let record = ClaimEvidence {
            claim_id,
            evidence_hash,
            submitter,
        };

        env.storage().persistent().set(&key, &record);
        Ok(())
    }

    /// 🔍 Verify supplied hash against stored hash
    pub fn verify_claim_evidence(
        env: &Env,
        claim_id: BytesN<32>,
        provided_hash: BytesN<32>,
    ) -> Result<bool, ContractError> {
        let key = DataKey::ClaimEvidence(claim_id);

        let record: ClaimEvidence = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::EvidenceNotFound)?;

        Ok(record.evidence_hash == provided_hash)
    }

    /// Fetch stored evidence (read-only)
    pub fn get_claim_evidence(
        env: &Env,
        claim_id: BytesN<32>,
    ) -> Result<ClaimEvidence, ContractError> {
        let key = DataKey::ClaimEvidence(claim_id);

        env.storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::EvidenceNotFound)
    }

    /// Create a simple event log entry
    pub fn log_event(env: &Env, event_type: &str, data: Vec<String>) {
        env.events().publish((event_type, ()), data);
    }
}
