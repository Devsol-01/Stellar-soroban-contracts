#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror, Address, Env, Symbol};

// Import authorization from the common library
use insurance_contracts::authorization::{
    initialize_admin, require_admin, require_risk_pool_management,
    require_trusted_contract, register_trusted_contract, Role, get_role
};

// Import invariant checks and error types
use insurance_invariants::{InvariantError, ProtocolInvariants};

#[contract]
pub struct RiskPoolContract;

const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const POOL_STATS: Symbol = Symbol::short("POOL_ST");
const PROVIDER: Symbol = Symbol::short("PROVIDER");
const RESERVED_TOTAL: Symbol = Symbol::short("RSV_TOT");
const CLAIM_RESERVATION: Symbol = Symbol::short("CLM_RSV");

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
    InvalidRole = 11,
    RoleNotFound = 12,
    NotTrustedContract = 13,
    // Invariant violation errors (100-199)
    LiquidityViolation = 100,
    InvalidAmount = 103,
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
            InvariantError::LiquidityViolation => ContractError::LiquidityViolation,
            InvariantError::InvalidAmount => ContractError::InvalidAmount,
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

/// I1: Check liquidity preservation invariant
/// Ensures: total_liquidity >= reserved_for_claims
fn check_liquidity_invariant(env: &Env) -> Result<(), ContractError> {
    let stats: (i128, i128, i128, u64) = env
        .storage()
        .persistent()
        .get(&POOL_STATS)
        .ok_or(ContractError::NotFound)?;

    let reserved_total: i128 = env
        .storage()
        .persistent()
        .get(&RESERVED_TOTAL)
        .unwrap_or(0i128);

    // I1: Liquidity Preservation: available_liquidity >= reserved_claims
    if stats.0 < reserved_total {
        return Err(ContractError::LiquidityViolation);
    }

    Ok(())
}

/// I4: Validate amount is positive and within safe range
fn validate_amount(amount: i128) -> Result<(), ContractError> {
    if amount <= 0 {
        return Err(ContractError::InvalidAmount);
    }
    Ok(())
}

#[contractimpl]
impl RiskPoolContract {
    pub fn initialize(env: Env, admin: Address, xlm_token: Address, min_provider_stake: i128, claims_contract: Address) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &xlm_token)?;
        validate_address(&env, &claims_contract)?;

        if min_provider_stake <= 0 {
            return Err(ContractError::InvalidInput);
        }

        // Initialize authorization system with admin
        admin.require_auth();
        initialize_admin(&env, admin.clone());
        
        // Register claims contract as trusted for cross-contract calls
        register_trusted_contract(&env, &admin, &claims_contract)?;

        env.storage().persistent().set(&CONFIG, &(xlm_token, min_provider_stake));
        
        let stats = (0i128, 0i128, 0i128, 0u64);
        env.storage().persistent().set(&POOL_STATS, &stats);
        
        env.events().publish(
            (Symbol::new(&env, "initialized"), ()),
            admin,
        );
        
        Ok(())
    }

    pub fn deposit_liquidity(env: Env, provider: Address, amount: i128) -> Result<(), ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &provider)?;
        
        // I4: Amount Non-Negativity - amount must be positive
        validate_amount(amount)?;

        let config: (Address, i128) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        let mut provider_info: (i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&(PROVIDER, provider.clone()))
            .unwrap_or((0i128, 0i128, env.ledger().timestamp()));

        if provider_info.1 + amount < config.1 {
            return Err(ContractError::InvalidInput);
        }

        let mut stats: (i128, i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&POOL_STATS)
            .ok_or(ContractError::NotFound)?;

        // Safe arithmetic with overflow check
        provider_info.0 = provider_info.0.checked_add(amount).ok_or(ContractError::Overflow)?;
        provider_info.1 = provider_info.1.checked_add(amount).ok_or(ContractError::Overflow)?;
        stats.0 = stats.0.checked_add(amount).ok_or(ContractError::Overflow)?;
        stats.2 = stats.2.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage()
            .persistent()
            .set(&(PROVIDER, provider.clone()), &provider_info);
        env.storage()
            .persistent()
            .set(&POOL_STATS, &stats);

        // I1: Assert liquidity invariant holds after deposit
        check_liquidity_invariant(&env)?;

        env.events().publish(
            (Symbol::new(&env, "liquidity_deposited"), provider.clone()),
            (amount, provider_info.1),
        );

        Ok(())
    }

    pub fn get_pool_stats(env: Env) -> Result<(i128, i128, i128, u64), ContractError> {
        let stats: (i128, i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&POOL_STATS)
            .ok_or(ContractError::NotFound)?;
        
        Ok(stats)
    }

    pub fn get_provider_info(env: Env, provider: Address) -> Result<(i128, i128, u64), ContractError> {
        validate_address(&env, &provider)?;
        
        let provider_info: (i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&(PROVIDER, provider))
            .ok_or(ContractError::NotFound)?;
        
        Ok(provider_info)
    }

    pub fn reserve_liquidity(env: Env, caller_contract: Address, claim_id: u64, amount: i128) -> Result<(), ContractError> {
        // Verify that the caller is a trusted contract (e.g., claims contract)
        caller_contract.require_auth();
        require_trusted_contract(&env, &caller_contract)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        // I4: Amount Non-Negativity - amount must be positive
        validate_amount(amount)?;

        if env
            .storage()
            .persistent()
            .has(&(CLAIM_RESERVATION, claim_id))
        {
            return Err(ContractError::AlreadyExists);
        }

        let stats: (i128, i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&POOL_STATS)
            .ok_or(ContractError::NotFound)?;

        let reserved_total: i128 = env
            .storage()
            .persistent()
            .get(&RESERVED_TOTAL)
            .unwrap_or(0i128);

        let available = stats.0.checked_sub(reserved_total).ok_or(ContractError::Overflow)?;
        if available < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Safe arithmetic for reservation
        let new_reserved_total = reserved_total.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage()
            .persistent()
            .set(&RESERVED_TOTAL, &new_reserved_total);
        env.storage()
            .persistent()
            .set(&(CLAIM_RESERVATION, claim_id), &amount);

        // I1: Assert liquidity invariant holds after reservation
        check_liquidity_invariant(&env)?;

        env.events().publish(
            (Symbol::new(&env, "liquidity_reserved"), claim_id),
            (amount, new_reserved_total),
        );

        Ok(())
    }

    pub fn payout_reserved_claim(env: Env, caller_contract: Address, claim_id: u64, recipient: Address) -> Result<(), ContractError> {
        // Verify that the caller is a trusted contract (e.g., claims contract)
        caller_contract.require_auth();
        require_trusted_contract(&env, &caller_contract)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &recipient)?;

        let mut stats: (i128, i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&POOL_STATS)
            .ok_or(ContractError::NotFound)?;

        let mut reserved_total: i128 = env
            .storage()
            .persistent()
            .get(&RESERVED_TOTAL)
            .unwrap_or(0i128);

        let amount: i128 = env
            .storage()
            .persistent()
            .get(&(CLAIM_RESERVATION, claim_id))
            .ok_or(ContractError::NotFound)?;

        if amount <= 0 {
            return Err(ContractError::InvalidState);
        }

        if reserved_total < amount {
            return Err(ContractError::InvalidState);
        }

        if stats.0 < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Safe arithmetic for payout
        reserved_total = reserved_total.checked_sub(amount).ok_or(ContractError::Overflow)?;
        stats.0 = stats.0.checked_sub(amount).ok_or(ContractError::Overflow)?;
        stats.1 = stats.1.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage()
            .persistent()
            .set(&RESERVED_TOTAL, &reserved_total);
        env.storage()
            .persistent()
            .remove(&(CLAIM_RESERVATION, claim_id));
        env.storage()
            .persistent()
            .set(&POOL_STATS, &stats);

        // I1: Assert liquidity invariant holds after payout
        check_liquidity_invariant(&env)?;

        env.events().publish(
            (Symbol::new(&env, "reserved_claim_payout"), claim_id),
            (recipient, amount),
        );

        Ok(())
    }

    pub fn payout_claim(env: Env, manager: Address, recipient: Address, amount: i128) -> Result<(), ContractError> {
        // Verify identity and require risk pool management permission
        manager.require_auth();
        require_risk_pool_management(&env, &manager)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &recipient)?;
        
        // I4: Amount Non-Negativity - amount must be positive
        validate_amount(amount)?;

        let mut stats: (i128, i128, i128, u64) = env
            .storage()
            .persistent()
            .get(&POOL_STATS)
            .ok_or(ContractError::NotFound)?;
        let reserved_total: i128 = env
            .storage()
            .persistent()
            .get(&RESERVED_TOTAL)
            .unwrap_or(0i128);

        let available = stats.0.checked_sub(reserved_total).ok_or(ContractError::Overflow)?;
        if available < amount {
            return Err(ContractError::InsufficientFunds);
        }

        // Safe arithmetic for payout
        stats.0 = stats.0.checked_sub(amount).ok_or(ContractError::Overflow)?;
        stats.1 = stats.1.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage()
            .persistent()
            .set(&POOL_STATS, &stats);

        // I1: Assert liquidity invariant holds after payout
        check_liquidity_invariant(&env)?;

        // TODO: Actually transfer XLM tokens to recipient
        // This would require token contract integration

        env.events().publish(
            (Symbol::new(&env, "claim_payout"), recipient.clone()),
            (amount,),
        );

        Ok(())
    }

    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, true);
        
        env.events().publish(
            (Symbol::new(&env, "paused"), ()),
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
            (Symbol::new(&env, "unpaused"), ()),
            admin,
        );
        
        Ok(())
    }
    
    /// Grant risk pool manager role to an address (admin only)
    pub fn grant_manager_role(env: Env, admin: Address, manager: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::grant_role(&env, &admin, &manager, Role::RiskPoolManager)?;
        
        env.events().publish(
            (Symbol::new(&env, "role_granted"), manager.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Revoke risk pool manager role from an address (admin only)
    pub fn revoke_manager_role(env: Env, admin: Address, manager: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::revoke_role(&env, &admin, &manager)?;
        
        env.events().publish(
            (Symbol::new(&env, "role_revoked"), manager.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Get the role of an address
    pub fn get_user_role(env: Env, address: Address) -> Role {
        get_role(&env, &address)
    }
}
