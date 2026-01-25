#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror, Address, Env, Symbol, symbol_short, IntoVal};

// Import the Policy contract interface to verify ownership and coverage
mod policy_contract {
    soroban_sdk::contractimport!(file = "../../target/wasm32-unknown-unknown/release/policy_contract.wasm");
}

// Import shared types and authorization from the common library
use insurance_contracts::types::ClaimStatus;
use insurance_contracts::authorization::{
    initialize_admin, require_admin, require_claim_processing, 
    require_trusted_contract, register_trusted_contract, Role, get_role
};

// Import invariants and safety assertions
use insurance_invariants::{InvariantError, ProtocolInvariants};

// Oracle validation types
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
const ORACLE_CONFIG: Symbol = symbol_short!("ORACLE_CFG");
const CLAIM_ORACLE_ID: Symbol = symbol_short!("CLM_ORA_ID");

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
            insurance_contracts::authorization::AuthError::Unauthorized => ContractError::Unauthorized,
            insurance_contracts::authorization::AuthError::InvalidRole => ContractError::InvalidRole,
            insurance_contracts::authorization::AuthError::RoleNotFound => ContractError::RoleNotFound,
            insurance_contracts::authorization::AuthError::NotTrustedContract => ContractError::NotTrustedContract,
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

fn validate_address(_env: &Env, _address: &Address) -> Result<(), ContractError> {
    Ok(())
}

fn is_paused(env: &Env) -> bool {
    env.storage()
        .persistent()
        .get(&PAUSED)
        .unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage()
        .persistent()
        .set(&PAUSED, &paused);
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
fn validate_coverage_constraint(claim_amount: i128, coverage_amount: i128) -> Result<(), ContractError> {
    if claim_amount > coverage_amount {
        return Err(ContractError::CoverageExceeded);
    }
    Ok(())
}

#[contractimpl]
impl ClaimsContract {
    pub fn initialize(env: Env, admin: Address, policy_contract: Address, risk_pool: Address) -> Result<(), ContractError> {
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
        
        env.events().publish(
            (symbol_short!("init"), ()),
            admin,
        );
        
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
        env.storage()
            .persistent()
            .get(&ORACLE_CFG)
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
        let oracle_config: OracleValidationConfig = env
            .storage()
            .persistent()
            .get(&ORACLE_CFG)
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
        env.storage()
            .persistent()
            .set(&(CLM_ORA, claim_id), &oracle_data_id);

        Ok(true)
    }

    /// Get oracle data associated with a claim
    pub fn get_claim_oracle_data(env: Env, claim_id: u64) -> Result<u64, ContractError> {
        env.storage()
            .persistent()
            .get(&(CLM_ORA, claim_id))
            .ok_or(ContractError::NotFound)
    }
        // 1. IDENTITY CHECK
        claimant.require_auth();

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // 2. FETCH POLICY DATA
        let (policy_contract_addr, _): (Address, Address) = env.storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        let policy_client = policy_contract::Client::new(&env, &policy_contract_addr);
        let policy = policy_client.get_policy(&policy_id);

        // 3. OWNERSHIP CHECK (Verify policyholder identity)
        if policy.0 != claimant {
            return Err(ContractError::Unauthorized); 
        }

        // 3. DUPLICATE CHECK (Check if this specific policy already has a claim)
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
        let current_time = env.ledger().timestamp();

        // I3: Initial state must be Submitted
        let initial_status = ClaimStatus::Submitted;

        env.storage()
            .persistent()
            .set(&(CLAIM, claim_id), &(policy_id, claimant.clone(), amount, initial_status, current_time));
        
        env.storage()
            .persistent()
            .set(&(POLICY_CLAIM, policy_id), &claim_id);

        env.events().publish(
            (symbol_short!("clm_sub"), claim_id),
            (policy_id, amount, claimant.clone()),
        );

        Ok(claim_id)
    }

    pub fn get_claim(env: Env, claim_id: u64) -> Result<(u64, Address, i128, ClaimStatus, u64), ContractError> {
        let claim: (u64, Address, i128, ClaimStatus, u64) = env
            .storage()
            .persistent()
            .get(&(CLAIM, claim_id))
            .ok_or(ContractError::NotFound)?;

        Ok(claim)
    }

    pub fn approve_claim(env: Env, processor: Address, claim_id: u64, oracle_data_id: Option<u64>) -> Result<(), ContractError> {
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
        if let Ok(oracle_config) = env.storage().persistent().get::<_, OracleValidationConfig>(&ORACLE_CONFIG) {
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
                    env.storage()
                        .persistent()
                        .set(&(CLM_ORA, claim_id), &oracle_id);
                } else {
                    return Err(ContractError::OracleValidationFailed);
                }
            }
        }

        let config: (Address, Address) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;
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

        env.storage()
            .persistent()
            .set(&(CLAIM, claim_id), &claim);

        env.events().publish(
            (symbol_short!("clm_app"), claim_id),
            (claim.1, claim.2),
        );

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

        env.storage()
            .persistent()
            .set(&(CLAIM, claim_id), &claim);

        env.events().publish(
            (Symbol::new(&env, "claim_under_review"), claim_id),
            (claim.1, claim.2),
        );

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

        env.storage()
            .persistent()
            .set(&(CLAIM, claim_id), &claim);

        env.events().publish(
            (Symbol::new(&env, "claim_rejected"), claim_id),
            (claim.1, claim.2),
        );

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
        let config: (Address, Address) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;
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

        env.storage()
            .persistent()
            .set(&(CLAIM, claim_id), &claim);

        env.events().publish(
            (Symbol::new(&env, "claim_settled"), claim_id),
            (claim.1, claim.2),
        );

        Ok(())
    }

    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        set_paused(&env, true);
        
        env.events().publish(
            (symbol_short!("paused"), ()),
            admin,
        );
        
        Ok(())
    }

    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        set_paused(&env, false);
        
        env.events().publish(
            (symbol_short!("unpaused"), ()),
            admin,
        );
        
        Ok(())
    }
    
    /// Grant claim processor role to an address (admin only)
    pub fn grant_processor_role(env: Env, admin: Address, processor: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::grant_role(&env, &admin, &processor, Role::ClaimProcessor)?;
        
        env.events().publish(
            (symbol_short!("role_gr"), processor.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Revoke claim processor role from an address (admin only)
    pub fn revoke_processor_role(env: Env, admin: Address, processor: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::revoke_role(&env, &admin, &processor)?;
        
        env.events().publish(
            (symbol_short!("role_rv"), processor.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Get the role of an address
    pub fn get_user_role(env: Env, address: Address) -> Role {
        get_role(&env, &address)
    }
}
mod test;