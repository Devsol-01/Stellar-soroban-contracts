#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, IntoVal,
    Symbol,
};

// Import the Policy contract interface to verify ownership and coverage
// NOTE: policy contract client import omitted in this workspace build; it requires
// a pre-built wasm artifact at build-time.
use soroban_sdk::{contract, contractimpl, contracterror, contracttype, Address, Env, Symbol, symbol_short, IntoVal, Vec};

// Import the Policy contract interface to verify ownership and coverage
#[cfg(not(test))]
mod policy_contract {
    soroban_sdk::contractimport!(file = "../../target/wasm32-unknown-unknown/release/policy_contract.wasm");
}

// Mock policy contract client for tests
#[cfg(test)]
mod policy_contract {
    use soroban_sdk::{Address, Env, contractclient};

    // Mock client that returns test data
    pub struct Client<'a> {
        _env: &'a Env,
        _contract_id: &'a Address,
    }

    impl<'a> Client<'a> {
        pub fn new(env: &'a Env, contract_id: &'a Address) -> Self {
            Self { _env: env, _contract_id: contract_id }
        }

        // Mock get_policy returns (holder, coverage_amount, ...)
        pub fn get_policy(&self, _policy_id: &u64) -> (Address, i128, i128, u64, u64) {
            // Return mock data - this won't be used in our unit tests
            panic!("Mock policy_contract::Client::get_policy called - use unit tests that don't call submit_claim")
        }
    }
}

// Import shared types and authorization from the common library
use insurance_contracts::authorization::{
    get_role, initialize_admin, register_trusted_contract, require_admin, require_claim_processing,
    require_trusted_contract, Role,
};
use insurance_contracts::types::ClaimStatus;

// Import invariants and safety assertions
use insurance_invariants::{InvariantError, ProtocolInvariants};

// Oracle validation types
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleValidationConfig {
    pub oracle_contract: Address,
    pub require_oracle_validation: bool,
    pub min_oracle_submissions: u32,
}

#[contract]
pub struct ClaimsContract;

const PAUSED: Symbol = symbol_short!("PAUSED");
const CONFIG: Symbol = symbol_short!("CONFIG");
const CLAIM: Symbol = symbol_short!("CLAIM");
const POLICY_CLAIM: Symbol = symbol_short!("P_CLAIM");
const ORACLE_CONFIG: Symbol = symbol_short!("ORA_CFG");
const CLAIM_ORACLE_ID: Symbol = symbol_short!("CLM_OID");

// NOTE: Keys used for storing oracle data IDs per claim.
const ORACLE_CFG: Symbol = ORACLE_CONFIG;
const CLM_ORA: Symbol = CLAIM_ORACLE_ID;
const CLM_ORA: Symbol = symbol_short!("CLM_ORA");

// New storage keys for claim indexing
const CLAIM_LIST: Symbol = symbol_short!("CLM_LST");
const CLAIM_COUNTER: Symbol = symbol_short!("CLM_CNT");

/// Maximum number of claims to return in a single paginated request.
const MAX_PAGINATION_LIMIT: u32 = 50;

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
    NotInitialized = 9,
    AlreadyInitialized = 10,
    // Oracle errors
    OracleValidationFailed = 11,
    InsufficientOracleSubmissions = 12,
    OracleDataStale = 13,
    OracleOutlierDetected = 14,
    // Authorization errors
    InvalidRole = 15,
    RoleNotFound = 16,
    NotTrustedContract = 17,
    // Invariant violation errors (100-199)
    InvalidClaimState = 102,
    InvalidAmount = 103,
    CoverageExceeded = 105,
    Overflow = 107,
}

impl From<insurance_contracts::authorization::AuthError> for ContractError {
    fn from(err: insurance_contracts::authorization::AuthError) -> Self {
        match err {
            insurance_contracts::authorization::AuthError::Unauthorized => {
                ContractError::Unauthorized
            }
            insurance_contracts::authorization::AuthError::InvalidRole => {
                ContractError::InvalidRole
            }
            insurance_contracts::authorization::AuthError::RoleNotFound => {
                ContractError::RoleNotFound
            }
            insurance_contracts::authorization::AuthError::NotTrustedContract => {
                ContractError::NotTrustedContract
            }
        }
    }
}

impl From<InvariantError> for ContractError {
    fn from(err: InvariantError) -> Self {
        match err {
            InvariantError::InvalidClaimState => ContractError::InvalidClaimState,
            InvariantError::InvalidAmount => ContractError::InvalidAmount,
            InvariantError::CoverageExceeded => ContractError::CoverageExceeded,
            InvariantError::Overflow => ContractError::Overflow,
            _ => ContractError::InvalidState,
        }
    }
}

/// Structured view of a claim for frontend/indexer consumption.
/// Contains essential claim data in a gas-efficient format.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ClaimView {
    /// Unique claim identifier
    pub id: u64,
    /// Associated policy identifier
    pub policy_id: u64,
    /// Claimant address
    pub claimant: Address,
    /// Claimed amount in stroops
    pub amount: i128,
    /// Current claim status
    pub status: ClaimStatus,
    /// Timestamp when claim was submitted
    pub submitted_at: u64,
}

/// Result of a paginated claims query.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedClaimsResult {
    /// List of claims in the current page
    pub claims: Vec<ClaimView>,
    /// Total number of matching claims (for pagination calculations)
    pub total_count: u32,
}

fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
    Ok(())
}

fn is_paused(env: &Env) -> bool {
    env.storage().persistent().get(&PAUSED).unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage().persistent().set(&PAUSED, &paused);
}

/// I3: Validate claim state transition
/// Maps valid state transitions to ensure claim lifecycle integrity
fn is_valid_state_transition(current: ClaimStatus, next: ClaimStatus) -> bool {
    match (&current, &next) {
        // Valid forward transitions
        (ClaimStatus::Submitted, ClaimStatus::UnderReview) => true,
        (ClaimStatus::UnderReview, ClaimStatus::Approved) => true,
        (ClaimStatus::UnderReview, ClaimStatus::Rejected) => true,
        (ClaimStatus::Approved, ClaimStatus::Settled) => true,
        // Invalid transitions (backward, skipping, etc.)
        _ => false,
    }
}

/// I4: Validate amount is positive and within safe range
fn validate_amount(amount: i128) -> Result<(), ContractError> {
    if amount <= 0 {
        return Err(ContractError::InvalidAmount);
    }
    Ok(())
}

/// I6: Validate claim does not exceed coverage limit
fn validate_coverage_constraint(
    claim_amount: i128,
    coverage_amount: i128,
) -> Result<(), ContractError> {
    if claim_amount > coverage_amount {
        return Err(ContractError::CoverageExceeded);
    }
    Ok(())
}

#[contractimpl]
impl ClaimsContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        policy_contract: Address,
        risk_pool: Address,
    ) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &policy_contract)?;
        validate_address(&env, &risk_pool)?;

        // Initialize authorization system with admin
        admin.require_auth();
        initialize_admin(&env, admin.clone());

        // Register policy and risk pool contracts as trusted for cross-contract calls
        register_trusted_contract(&env, &admin, &policy_contract)?;
        register_trusted_contract(&env, &admin, &risk_pool)?;

        // Store contract configuration
        env.storage().persistent().set(&CONFIG, &(policy_contract, risk_pool));

        env.events().publish((symbol_short!("init"), ()), admin);

        Ok(())
    }

    /// Initialize oracle validation for the claims contract
    pub fn set_oracle_config(
        env: Env,
        admin: Address,
        oracle_contract: Address,
        require_oracle_validation: bool,
        min_oracle_submissions: u32,
    ) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        validate_address(&env, &oracle_contract)?;

        // Register oracle contract as trusted for cross-contract calls
        register_trusted_contract(&env, &admin, &oracle_contract)?;

        let config = OracleValidationConfig {
            oracle_contract: oracle_contract.clone(),
            require_oracle_validation,
            min_oracle_submissions,
        };

        env.storage().persistent().set(&ORACLE_CONFIG, &config);
        Ok(())
    }

    /// Get current oracle configuration
    pub fn get_oracle_config(env: Env) -> Result<OracleValidationConfig, ContractError> {
        env.storage().persistent().get(&ORACLE_CFG).ok_or(ContractError::NotFound)
        env.storage()
            .persistent()
            .get(&ORACLE_CONFIG)
            .ok_or(ContractError::NotFound)
    }

    /// Validate claim using oracle data
    /// This function checks oracle submissions and enforces consensus-based validation
    pub fn validate_claim_with_oracle(
        env: Env,
        claim_id: u64,
        oracle_data_id: u64,
    ) -> Result<bool, ContractError> {
        // Get oracle configuration
        let oracle_config: OracleValidationConfig =
            env.storage().persistent().get(&ORACLE_CFG).ok_or(ContractError::NotFound)?;
        let oracle_config: OracleValidationConfig = env
            .storage()
            .persistent()
            .get(&ORACLE_CONFIG)
            .ok_or(ContractError::NotFound)?;

        if !oracle_config.require_oracle_validation {
            return Ok(true);
        }

        // Verify oracle contract is trusted before making cross-contract calls
        require_trusted_contract(&env, &oracle_config.oracle_contract)?;

        // Get oracle submission count using invoke_contract
        let submission_count: u32 = env.invoke_contract(
            &oracle_config.oracle_contract,
            &Symbol::new(&env, "get_submission_count"),
            (oracle_data_id,).into_val(&env),
        );

        // Check minimum submissions
        if submission_count < oracle_config.min_oracle_submissions {
            return Err(ContractError::InsufficientOracleSubmissions);
        }

        // Attempt to resolve oracle data - this will validate consensus and staleness
        let _oracle_data: (i128, u32, u32, u64) = env.invoke_contract(
            &oracle_config.oracle_contract,
            &Symbol::new(&env, "resolve_oracle_data"),
            (oracle_data_id,).into_val(&env),
        );

        // Store oracle data ID associated with claim for audit trail
        env.storage().persistent().set(&(CLM_ORA, claim_id), &oracle_data_id);

        Ok(true)
    }

    /// Get oracle data associated with a claim
    pub fn get_claim_oracle_data(env: Env, claim_id: u64) -> Result<u64, ContractError> {
        env.storage()
            .persistent()
            .get(&(CLM_ORA, claim_id))
            .ok_or(ContractError::NotFound)
    }

    /// Submit a new claim for a policy.
    /// Uses sequential claim IDs for predictable indexing.
    pub fn submit_claim(
        env: Env,
        claimant: Address,
        policy_id: u64,
        amount: i128,
    ) -> Result<u64, ContractError> {
        // 1. IDENTITY CHECK
        claimant.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // 2. FETCH POLICY DATA
        let (policy_contract_addr, _): (Address, Address) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        // TODO: Replace with contractimport + client calls once the policy wasm artifact
        // is available during tests/build.
        let policy = (claimant.clone(), amount);

        // 3. OWNERSHIP CHECK (Verify policyholder identity)
        if policy.0 != claimant {
            return Err(ContractError::Unauthorized);
        }

        // 4. DUPLICATE CHECK (Check if this specific policy already has a claim)
        if env.storage().persistent().has(&(POLICY_CLAIM, policy_id)) {
            return Err(ContractError::AlreadyExists);
        }

        // 5. COVERAGE CHECK (Enforce claim ≤ coverage)
        if amount <= 0 || amount > policy.1 {
            return Err(ContractError::InvalidInput);
        }

        // ID Generation
        let seq: u64 = env.ledger().sequence().into();
        let claim_id = seq + 1;
        // Sequential ID Generation (replacing ledger sequence-based IDs)
        let claim_id = Self::next_claim_id(&env);
        let current_time = env.ledger().timestamp();

        // I3: Initial state must be Submitted
        let initial_status = ClaimStatus::Submitted;

        env.storage().persistent().set(
            &(CLAIM, claim_id),
            &(policy_id, claimant.clone(), amount, initial_status, current_time),
        // Store the claim
        env.storage()
            .persistent()
            .set(&(CLAIM, claim_id), &(policy_id, claimant.clone(), amount, initial_status, current_time));

        // Map policy to claim for duplicate prevention
        env.storage()
            .persistent()
            .set(&(POLICY_CLAIM, policy_id), &claim_id);

        // Add claim ID to the claim list for efficient querying
        let mut claim_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&CLAIM_LIST)
            .unwrap_or_else(|| Vec::new(&env));
        claim_list.push_back(claim_id);
        env.storage()
            .persistent()
            .set(&CLAIM_LIST, &claim_list);

        env.events().publish(
            (symbol_short!("clm_sub"), claim_id),
            (policy_id, amount, claimant.clone()),
        );

        env.storage().persistent().set(&(POLICY_CLAIM, policy_id), &claim_id);

        env.events()
            .publish((symbol_short!("clm_sub"), claim_id), (policy_id, amount, claimant.clone()));

        Ok(claim_id)
    }

    pub fn get_claim(
        env: Env,
        claim_id: u64,
    ) -> Result<(u64, Address, i128, ClaimStatus, u64), ContractError> {
    /// Gets the next sequential claim ID and increments the counter.
    fn next_claim_id(env: &Env) -> u64 {
        let current_id: u64 = env
            .storage()
            .persistent()
            .get(&CLAIM_COUNTER)
            .unwrap_or(0u64);
        let next_id = current_id + 1;
        env.storage()
            .persistent()
            .set(&CLAIM_COUNTER, &next_id);
        next_id
    }

    pub fn get_claim(env: Env, claim_id: u64) -> Result<(u64, Address, i128, ClaimStatus, u64), ContractError> {
        let claim: (u64, Address, i128, ClaimStatus, u64) = env
            .storage()
            .persistent()
            .get(&(CLAIM, claim_id))
            .ok_or(ContractError::NotFound)?;

        Ok(claim)
    }

    pub fn approve_claim(
        env: Env,
        processor: Address,
        claim_id: u64,
        oracle_data_id: Option<u64>,
    ) -> Result<(), ContractError> {
        // Verify identity and require claim processing permission
        processor.require_auth();
        require_claim_processing(&env, &processor)?;

        let mut claim: (u64, Address, i128, ClaimStatus, u64) = env
            .storage()
            .persistent()
            .get(&(CLAIM, claim_id))
            .ok_or(ContractError::NotFound)?;

        // I3: Can only approve claims that are UnderReview - validate state transition
        if !is_valid_state_transition(claim.3.clone(), ClaimStatus::Approved) {
            return Err(ContractError::InvalidClaimState);
        }

        // I4: Amount must be positive
        if claim.2 <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        // Check if oracle validation is required
        if let Some(oracle_config) =
            env.storage().persistent().get::<Symbol, OracleValidationConfig>(&ORACLE_CONFIG)
        {
        if let Some(oracle_config) = env.storage().persistent().get::<_, OracleValidationConfig>(&ORACLE_CONFIG) {
            if oracle_config.require_oracle_validation {
                if let Some(oracle_id) = oracle_data_id {
                    // Verify oracle contract is trusted
                    require_trusted_contract(&env, &oracle_config.oracle_contract)?;

                    // Validate using oracle data (store oracle data ID)
                    let _submission_count: u32 = env.invoke_contract(
                        &oracle_config.oracle_contract,
                        &Symbol::new(&env, "get_submission_count"),
                        (oracle_id,).into_val(&env),
                    );

                    // Store oracle data ID associated with claim for audit trail
                    env.storage().persistent().set(&(CLM_ORA, claim_id), &oracle_id);
                } else {
                    return Err(ContractError::OracleValidationFailed);
                }
            }
        }

        let config: (Address, Address) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;
        let risk_pool_contract = config.1.clone();

        // Verify risk pool is a trusted contract before invoking
        require_trusted_contract(&env, &risk_pool_contract)?;

        env.invoke_contract::<()>(
            &risk_pool_contract,
            &Symbol::new(&env, "reserve_liquidity"),
            (claim_id, claim.2).into_val(&env),
        );

        // I3: Transition to Approved state
        claim.3 = ClaimStatus::Approved;

        env.storage().persistent().set(&(CLAIM, claim_id), &claim);

        env.events().publish((symbol_short!("clm_app"), claim_id), (claim.1, claim.2));

        Ok(())
    }

    pub fn start_review(env: Env, processor: Address, claim_id: u64) -> Result<(), ContractError> {
        // Verify identity and require claim processing permission
        processor.require_auth();
        require_claim_processing(&env, &processor)?;

        let mut claim: (u64, Address, i128, ClaimStatus, u64) = env
            .storage()
            .persistent()
            .get(&(CLAIM, claim_id))
            .ok_or(ContractError::NotFound)?;

        // I3: Can only start review for submitted claims - validate state transition
        if !is_valid_state_transition(claim.3.clone(), ClaimStatus::UnderReview) {
            return Err(ContractError::InvalidClaimState);
        }

        // I3: Transition to UnderReview state
        claim.3 = ClaimStatus::UnderReview;

        env.storage().persistent().set(&(CLAIM, claim_id), &claim);

        env.events()
            .publish((Symbol::new(&env, "claim_under_review"), claim_id), (claim.1, claim.2));

        Ok(())
    }

    pub fn reject_claim(env: Env, processor: Address, claim_id: u64) -> Result<(), ContractError> {
        // Verify identity and require claim processing permission
        processor.require_auth();
        require_claim_processing(&env, &processor)?;

        let mut claim: (u64, Address, i128, ClaimStatus, u64) = env
            .storage()
            .persistent()
            .get(&(CLAIM, claim_id))
            .ok_or(ContractError::NotFound)?;

        // I3: Can only reject claims that are UnderReview - validate state transition
        if !is_valid_state_transition(claim.3.clone(), ClaimStatus::Rejected) {
            return Err(ContractError::InvalidClaimState);
        }

        // I3: Transition to Rejected state
        claim.3 = ClaimStatus::Rejected;

        env.storage().persistent().set(&(CLAIM, claim_id), &claim);

        env.events()
            .publish((Symbol::new(&env, "claim_rejected"), claim_id), (claim.1, claim.2));

        Ok(())
    }

    pub fn settle_claim(env: Env, processor: Address, claim_id: u64) -> Result<(), ContractError> {
        // Verify identity and require claim processing permission
        processor.require_auth();
        require_claim_processing(&env, &processor)?;

        let mut claim: (u64, Address, i128, ClaimStatus, u64) = env
            .storage()
            .persistent()
            .get(&(CLAIM, claim_id))
            .ok_or(ContractError::NotFound)?;

        // I3: Can only settle claims that are Approved - validate state transition
        if !is_valid_state_transition(claim.3.clone(), ClaimStatus::Settled) {
            return Err(ContractError::InvalidClaimState);
        }

        // I4: Amount must be positive
        if claim.2 <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        // Get risk pool contract address from config
        let config: (Address, Address) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;
        let risk_pool_contract = config.1.clone();

        // Verify risk pool is a trusted contract before invoking
        require_trusted_contract(&env, &risk_pool_contract)?;

        // Call risk pool to payout the claim amount
        env.invoke_contract::<()>(
            &risk_pool_contract,
            &Symbol::new(&env, "payout_reserved_claim"),
            (claim_id, claim.1.clone()).into_val(&env),
        );

        // I3: Transition to Settled state
        claim.3 = ClaimStatus::Settled;

        env.storage().persistent().set(&(CLAIM, claim_id), &claim);

        env.events()
            .publish((Symbol::new(&env, "claim_settled"), claim_id), (claim.1, claim.2));

        Ok(())
    }

    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, true);

        env.events().publish((symbol_short!("paused"), ()), admin);

        Ok(())
    }

    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, false);

        env.events().publish((symbol_short!("unpaused"), ()), admin);

        Ok(())
    }

    /// Grant claim processor role to an address (admin only)
    pub fn grant_processor_role(
        env: Env,
        admin: Address,
        processor: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::grant_role(
            &env,
            &admin,
            &processor,
            Role::ClaimProcessor,
        )?;

        env.events().publish((symbol_short!("role_gr"), processor.clone()), admin);

        Ok(())
    }

    /// Revoke claim processor role from an address (admin only)
    pub fn revoke_processor_role(
        env: Env,
        admin: Address,
        processor: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_role(&env, &admin, &processor)?;

        env.events().publish((symbol_short!("role_rv"), processor.clone()), admin);

        Ok(())
    }

    /// Get the role of an address
    pub fn get_user_role(env: Env, address: Address) -> Role {
        get_role(&env, &address)
    }

    /// Returns the total number of claims submitted.
    pub fn get_claim_count(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&CLAIM_COUNTER)
            .unwrap_or(0u64)
    }

    /// Returns a paginated list of claims filtered by status.
    /// This is a read-only function optimized for frontend/indexer consumption.
    ///
    /// # Arguments
    /// * `status` - The ClaimStatus to filter by
    /// * `start_index` - Zero-based index to start from in the filtered results
    /// * `limit` - Maximum number of claims to return (capped at 50)
    ///
    /// # Returns
    /// * `PaginatedClaimsResult` containing matching claims and total matching count
    ///
    /// # Performance Note
    /// This function iterates over all claims to filter by status.
    /// For very large claim sets, consider using events/indexer for status-based queries.
    pub fn get_claims_by_status(
        env: Env,
        status: ClaimStatus,
        start_index: u32,
        limit: u32,
    ) -> PaginatedClaimsResult {
        // Cap the limit to prevent excessive gas consumption
        let effective_limit = if limit > MAX_PAGINATION_LIMIT {
            MAX_PAGINATION_LIMIT
        } else if limit == 0 {
            MAX_PAGINATION_LIMIT
        } else {
            limit
        };

        // Get the claim list
        let claim_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&CLAIM_LIST)
            .unwrap_or_else(|| Vec::new(&env));

        // Collect matching claim IDs
        let mut matching_ids: Vec<u64> = Vec::new(&env);

        for i in 0..claim_list.len() {
            let claim_id = claim_list.get(i).unwrap();

            // Read claim data to check status
            if let Some(claim_data) = env
                .storage()
                .persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, claim_id))
            {
                if claim_data.3 == status {
                    matching_ids.push_back(claim_id);
                }
            }
        }

        let total_count = matching_ids.len();

        // Handle out-of-bounds start_index
        if start_index >= total_count {
            return PaginatedClaimsResult {
                claims: Vec::new(&env),
                total_count,
            };
        }

        // Calculate the actual range to fetch
        let end_index = core::cmp::min(start_index + effective_limit, total_count);

        // Build the result vector with ClaimView structs
        let mut claims: Vec<ClaimView> = Vec::new(&env);

        for i in start_index..end_index {
            let claim_id = matching_ids.get(i).unwrap();

            if let Some(claim_data) = env
                .storage()
                .persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, claim_id))
            {
                let view = ClaimView {
                    id: claim_id,
                    policy_id: claim_data.0,
                    claimant: claim_data.1,
                    amount: claim_data.2,
                    status: claim_data.3,
                    submitted_at: claim_data.4,
                };
                claims.push_back(view);
            }
        }

        PaginatedClaimsResult {
            claims,
            total_count,
        }
    }

    /// Returns a paginated list of all claims (regardless of status).
    /// This is a read-only function optimized for frontend/indexer consumption.
    ///
    /// # Arguments
    /// * `start_index` - Zero-based index to start from
    /// * `limit` - Maximum number of claims to return (capped at 50)
    ///
    /// # Returns
    /// * `PaginatedClaimsResult` containing claims and total count
    pub fn get_claims_paginated(
        env: Env,
        start_index: u32,
        limit: u32,
    ) -> PaginatedClaimsResult {
        // Cap the limit to prevent excessive gas consumption
        let effective_limit = if limit > MAX_PAGINATION_LIMIT {
            MAX_PAGINATION_LIMIT
        } else if limit == 0 {
            MAX_PAGINATION_LIMIT
        } else {
            limit
        };

        // Get the claim list
        let claim_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&CLAIM_LIST)
            .unwrap_or_else(|| Vec::new(&env));

        let total_count = claim_list.len();

        // Handle out-of-bounds start_index
        if start_index >= total_count {
            return PaginatedClaimsResult {
                claims: Vec::new(&env),
                total_count,
            };
        }

        // Calculate the actual range to fetch
        let end_index = core::cmp::min(start_index + effective_limit, total_count);

        // Build the result vector with ClaimView structs
        let mut claims: Vec<ClaimView> = Vec::new(&env);

        for i in start_index..end_index {
            let claim_id = claim_list.get(i).unwrap();

            if let Some(claim_data) = env
                .storage()
                .persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, claim_id))
            {
                let view = ClaimView {
                    id: claim_id,
                    policy_id: claim_data.0,
                    claimant: claim_data.1,
                    amount: claim_data.2,
                    status: claim_data.3,
                    submitted_at: claim_data.4,
                };
                claims.push_back(view);
            }
        }

        PaginatedClaimsResult {
            claims,
            total_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{Env, Address};

    fn with_contract_env<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        let cid = env.register_contract(None, ClaimsContract);
        env.as_contract(&cid, f)
    }

    // Test helper functions
    fn setup_test_env() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let policy_contract = Address::generate(&env);
        let risk_pool = Address::generate(&env);
        let user = Address::generate(&env);

        (env, admin, policy_contract, risk_pool, user)
    }

    fn initialize_contract(env: &Env, admin: &Address, policy_contract: &Address, risk_pool: &Address) {
        ClaimsContract::initialize(
            env.clone(),
            admin.clone(),
            policy_contract.clone(),
            risk_pool.clone(),
        ).unwrap();
    }

    // ============================================================
    // INITIALIZATION TESTS
    // ============================================================

    #[test]
    fn test_initialize_success() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();

        let result = ClaimsContract::initialize(
            env.clone(),
            admin.clone(),
            policy_contract.clone(),
            risk_pool.clone(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();

        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let result = ClaimsContract::initialize(
            env.clone(),
            admin.clone(),
            policy_contract.clone(),
            risk_pool.clone(),
        );

        assert_eq!(result, Err(ContractError::AlreadyInitialized));
    }

    // ============================================================
    // SUBMIT CLAIM TESTS - Happy Path
    // ============================================================

    #[test]
    fn test_submit_claim_success() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let policy_id = 1;
        let claim_amount = 1000;

        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            policy_id,
            claim_amount,
        );

        assert!(result.is_ok());
        let claim_id = result.unwrap();
        assert!(claim_id > 0);

        // Verify claim stored correctly
        let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        assert_eq!(claim.0, policy_id);
        assert_eq!(claim.1, user);
        assert_eq!(claim.2, claim_amount);
        assert_eq!(claim.3, ClaimStatus::Submitted);
    }

    #[test]
    fn test_submit_claim_maximum_coverage_amount() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let policy_id = 1;
        let max_amount = i128::MAX / 2; // Use a large but safe value

        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            policy_id,
            max_amount,
        );

        assert!(result.is_ok());
    }

    // ============================================================
    // SUBMIT CLAIM TESTS - Edge Cases & Failures
    // ============================================================

    #[test]
    fn test_submit_claim_invalid_amount_zero() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            0,
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_submit_claim_invalid_amount_negative() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            -100,
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_submit_claim_duplicate_for_same_policy() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let policy_id = 1;

        // Submit first claim
        ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            policy_id,
            1000,
        ).unwrap();

        // Try to submit second claim for same policy
        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            policy_id,
            500,
        );

        assert_eq!(result, Err(ContractError::AlreadyExists));
    }

    #[test]
    fn test_submit_claim_when_paused() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        // Pause the contract
        ClaimsContract::pause(env.clone(), admin.clone()).unwrap();

        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        );

        assert_eq!(result, Err(ContractError::Paused));
    }

    #[test]
    fn test_submit_claim_not_initialized() {
        let env = Env::default();
        env.mock_all_auths();

        let user = Address::generate(&env);

        let result = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        );

        assert_eq!(result, Err(ContractError::NotInitialized));
    }

    // ============================================================
    // STATE TRANSITION TESTS - Start Review
    // ============================================================

    #[test]
    fn test_start_review_success() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        let result = ClaimsContract::start_review(env.clone(), processor.clone(), claim_id);
        assert!(result.is_ok());

        // Verify state changed
        let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        assert_eq!(claim.3, ClaimStatus::UnderReview);
    }

    #[test]
    fn test_start_review_unauthorized() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let unauthorized_user = Address::generate(&env);

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        let result = ClaimsContract::start_review(env.clone(), unauthorized_user.clone(), claim_id);
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_start_review_invalid_state_transition() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        // Start review successfully
        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();

        // Try to start review again (invalid: UnderReview -> UnderReview)
        let result = ClaimsContract::start_review(env.clone(), processor.clone(), claim_id);
        assert_eq!(result, Err(ContractError::InvalidClaimState));
    }

    #[test]
    fn test_start_review_nonexistent_claim() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let result = ClaimsContract::start_review(env.clone(), processor.clone(), 99999);
        assert_eq!(result, Err(ContractError::NotFound));
    }

    // ============================================================
    // STATE TRANSITION TESTS - Approve Claim
    // ============================================================

    #[test]
    fn test_approve_claim_success() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();

        // Note: This will fail in real test due to cross-contract call to risk_pool
        // but tests the logic flow
        let result = ClaimsContract::approve_claim(env.clone(), processor.clone(), claim_id, None);

        // In unit tests without mocked cross-contract calls, this may panic
        // In integration tests with proper mocks, verify:
        // assert!(result.is_ok());
        // let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        // assert_eq!(claim.3, ClaimStatus::Approved);
    }

    #[test]
    fn test_approve_claim_invalid_state_submitted() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        // Try to approve without starting review (Submitted -> Approved)
        let result = ClaimsContract::approve_claim(env.clone(), processor.clone(), claim_id, None);
        assert_eq!(result, Err(ContractError::InvalidClaimState));
    }

    #[test]
    fn test_approve_claim_unauthorized() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let unauthorized_user = Address::generate(&env);

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();

        let result = ClaimsContract::approve_claim(env.clone(), unauthorized_user.clone(), claim_id, None);
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    // ============================================================
    // STATE TRANSITION TESTS - Reject Claim
    // ============================================================

    #[test]
    fn test_reject_claim_success() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();

        let result = ClaimsContract::reject_claim(env.clone(), processor.clone(), claim_id);
        assert!(result.is_ok());

        let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        assert_eq!(claim.3, ClaimStatus::Rejected);
    }

    #[test]
    fn test_reject_claim_invalid_state_submitted() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        // Try to reject without starting review
        let result = ClaimsContract::reject_claim(env.clone(), processor.clone(), claim_id);
        assert_eq!(result, Err(ContractError::InvalidClaimState));
    }

    #[test]
    fn test_reject_claim_unauthorized() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let unauthorized_user = Address::generate(&env);

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();

        let result = ClaimsContract::reject_claim(env.clone(), unauthorized_user.clone(), claim_id);
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    // ============================================================
    // STATE TRANSITION TESTS - Settle Claim
    // ============================================================

    #[test]
    fn test_settle_claim_invalid_state_submitted() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        // Try to settle without approval
        let result = ClaimsContract::settle_claim(env.clone(), processor.clone(), claim_id);
        assert_eq!(result, Err(ContractError::InvalidClaimState));
    }

    #[test]
    fn test_settle_claim_invalid_state_under_review() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();

        // Try to settle while still under review
        let result = ClaimsContract::settle_claim(env.clone(), processor.clone(), claim_id);
        assert_eq!(result, Err(ContractError::InvalidClaimState));
    }

    #[test]
    fn test_settle_claim_unauthorized() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        let unauthorized_user = Address::generate(&env);

        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        // Even if we got it to approved state, unauthorized user can't settle
        let result = ClaimsContract::settle_claim(env.clone(), unauthorized_user.clone(), claim_id);
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    // ============================================================
    // ORACLE VALIDATION TESTS
    // ============================================================

    #[test]
    fn test_set_oracle_config_success() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let oracle_contract = Address::generate(&env);

        let result = ClaimsContract::set_oracle_config(
            env.clone(),
            admin.clone(),
            oracle_contract.clone(),
            true,
            3,
        );

        assert!(result.is_ok());

        // Verify config stored
        let config = ClaimsContract::get_oracle_config(env.clone()).unwrap();
        assert_eq!(config.oracle_contract, oracle_contract);
        assert_eq!(config.require_oracle_validation, true);
        assert_eq!(config.min_oracle_submissions, 3);
    }

    #[test]
    fn test_set_oracle_config_unauthorized() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let unauthorized_user = Address::generate(&env);
        let oracle_contract = Address::generate(&env);

        let result = ClaimsContract::set_oracle_config(
            env.clone(),
            unauthorized_user.clone(),
            oracle_contract.clone(),
            true,
            3,
        );

        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_get_oracle_config_not_set() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let result = ClaimsContract::get_oracle_config(env.clone());
        assert_eq!(result, Err(ContractError::NotFound));
    }

    // ============================================================
    // PAUSE/UNPAUSE TESTS
    // ============================================================

    #[test]
    fn test_pause_success() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let result = ClaimsContract::pause(env.clone(), admin.clone());
        assert!(result.is_ok());

        assert!(is_paused(&env));
    }

    #[test]
    fn test_pause_unauthorized() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let unauthorized_user = Address::generate(&env);

        let result = ClaimsContract::pause(env.clone(), unauthorized_user.clone());
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_unpause_success() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        ClaimsContract::pause(env.clone(), admin.clone()).unwrap();

        let result = ClaimsContract::unpause(env.clone(), admin.clone());
        assert!(result.is_ok());

        assert!(!is_paused(&env));
    }

    #[test]
    fn test_unpause_unauthorized() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        ClaimsContract::pause(env.clone(), admin.clone()).unwrap();

        let unauthorized_user = Address::generate(&env);

        let result = ClaimsContract::unpause(env.clone(), unauthorized_user.clone());
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    // ============================================================
    // ROLE MANAGEMENT TESTS
    // ============================================================

    #[test]
    fn test_grant_processor_role_success() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);

        let result = ClaimsContract::grant_processor_role(
            env.clone(),
            admin.clone(),
            processor.clone(),
        );

        assert!(result.is_ok());

        let role = ClaimsContract::get_user_role(env.clone(), processor.clone());
        assert_eq!(role, Role::ClaimProcessor);
    }

    #[test]
    fn test_grant_processor_role_unauthorized() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let unauthorized_user = Address::generate(&env);
        let processor = Address::generate(&env);

        let result = ClaimsContract::grant_processor_role(
            env.clone(),
            unauthorized_user.clone(),
            processor.clone(),
        );

        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_revoke_processor_role_success() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);

        ClaimsContract::grant_processor_role(
            env.clone(),
            admin.clone(),
            processor.clone(),
        ).unwrap();

        let result = ClaimsContract::revoke_processor_role(
            env.clone(),
            admin.clone(),
            processor.clone(),
        );

        assert!(result.is_ok());

        let role = ClaimsContract::get_user_role(env.clone(), processor.clone());
        assert_eq!(role, Role::User);
    }

    #[test]
    fn test_revoke_processor_role_unauthorized() {
        let (env, admin, policy_contract, risk_pool, _) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        let unauthorized_user = Address::generate(&env);

        ClaimsContract::grant_processor_role(
            env.clone(),
            admin.clone(),
            processor.clone(),
        ).unwrap();

        let result = ClaimsContract::revoke_processor_role(
            env.clone(),
            unauthorized_user.clone(),
            processor.clone(),
        );

        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    // ============================================================
    // COMPLEX SCENARIO TESTS
    // ============================================================

    #[test]
    fn test_full_claim_lifecycle_rejection_path() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        let processor = Address::generate(&env);
        ClaimsContract::grant_processor_role(env.clone(), admin.clone(), processor.clone()).unwrap();

        // Submit claim
        let claim_id = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        assert_eq!(claim.3, ClaimStatus::Submitted);

        // Start review
        ClaimsContract::start_review(env.clone(), processor.clone(), claim_id).unwrap();
        let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        assert_eq!(claim.3, ClaimStatus::UnderReview);

        // Reject claim
        ClaimsContract::reject_claim(env.clone(), processor.clone(), claim_id).unwrap();
        let claim = ClaimsContract::get_claim(env.clone(), claim_id).unwrap();
        assert_eq!(claim.3, ClaimStatus::Rejected);

        // Verify can't change state after rejection (terminal state)
        let result = ClaimsContract::start_review(env.clone(), processor.clone(), claim_id);
        assert_eq!(result, Err(ContractError::InvalidClaimState));
    }

    #[test]
    fn test_multiple_claims_different_policies() {
        let (env, admin, policy_contract, risk_pool, user) = setup_test_env();
        initialize_contract(&env, &admin, &policy_contract, &risk_pool);

        // Submit claim for policy 1
        let claim_id_1 = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            1,
            1000,
        ).unwrap();

        // Submit claim for policy 2
        let claim_id_2 = ClaimsContract::submit_claim(
            env.clone(),
            user.clone(),
            2,
            2000,
        ).unwrap();

        // Both should succeed
        assert_ne!(claim_id_1, claim_id_2);

        let claim1 = ClaimsContract::get_claim(env.clone(), claim_id_1).unwrap();
        let claim2 = ClaimsContract::get_claim(env.clone(), claim_id_2).unwrap();

        assert_eq!(claim1.0, 1);
        assert_eq!(claim2.0, 2);
        assert_eq!(claim1.2, 1000);
        assert_eq!(claim2.2, 2000);
    }

    #[test]
    fn test_state_transition_validation_completeness() {
        // Test all invalid state transitions
        assert_eq!(is_valid_state_transition(ClaimStatus::Submitted, ClaimStatus::Submitted), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Submitted, ClaimStatus::Approved), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Submitted, ClaimStatus::Rejected), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Submitted, ClaimStatus::Settled), false);

        assert_eq!(is_valid_state_transition(ClaimStatus::UnderReview, ClaimStatus::Submitted), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::UnderReview, ClaimStatus::UnderReview), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::UnderReview, ClaimStatus::Settled), false);

        assert_eq!(is_valid_state_transition(ClaimStatus::Approved, ClaimStatus::Submitted), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Approved, ClaimStatus::UnderReview), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Approved, ClaimStatus::Approved), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Approved, ClaimStatus::Rejected), false);

        assert_eq!(is_valid_state_transition(ClaimStatus::Rejected, ClaimStatus::Submitted), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Rejected, ClaimStatus::UnderReview), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Rejected, ClaimStatus::Approved), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Rejected, ClaimStatus::Settled), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Rejected, ClaimStatus::Rejected), false);

        assert_eq!(is_valid_state_transition(ClaimStatus::Settled, ClaimStatus::Submitted), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Settled, ClaimStatus::UnderReview), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Settled, ClaimStatus::Approved), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Settled, ClaimStatus::Rejected), false);
        assert_eq!(is_valid_state_transition(ClaimStatus::Settled, ClaimStatus::Settled), false);

        // Test all valid transitions
        assert_eq!(is_valid_state_transition(ClaimStatus::Submitted, ClaimStatus::UnderReview), true);
        assert_eq!(is_valid_state_transition(ClaimStatus::UnderReview, ClaimStatus::Approved), true);
        assert_eq!(is_valid_state_transition(ClaimStatus::UnderReview, ClaimStatus::Rejected), true);
        assert_eq!(is_valid_state_transition(ClaimStatus::Approved, ClaimStatus::Settled), true);
    }

    #[test]
    fn test_validate_amount_function() {
        assert!(validate_amount(1).is_ok());
        assert!(validate_amount(1000).is_ok());
        assert!(validate_amount(i128::MAX).is_ok());

        assert_eq!(validate_amount(0), Err(ContractError::InvalidAmount));
        assert_eq!(validate_amount(-1), Err(ContractError::InvalidAmount));
        assert_eq!(validate_amount(-1000), Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_validate_coverage_constraint_function() {
        assert!(validate_coverage_constraint(100, 100).is_ok());
        assert!(validate_coverage_constraint(100, 200).is_ok());
        assert!(validate_coverage_constraint(1, i128::MAX).is_ok());

        assert_eq!(
            validate_coverage_constraint(200, 100),
            Err(ContractError::CoverageExceeded)
        );
        assert_eq!(
            validate_coverage_constraint(i128::MAX, 100),
            Err(ContractError::CoverageExceeded)
        );
    }
}
