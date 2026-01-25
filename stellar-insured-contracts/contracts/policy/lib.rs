#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror, contracttype, Address, Env, Symbol};

// Import authorization from the common library
use insurance_contracts::authorization::{
    initialize_admin, require_admin, require_policy_management,
    register_trusted_contract, Role, get_role
};

// Import invariant checks and error types
use insurance_invariants::{InvariantError, ProtocolInvariants};

// Policy validation constants
const MIN_COVERAGE_AMOUNT: i128 = 1_000_000; // 1 unit (assuming 6 decimals)
const MAX_COVERAGE_AMOUNT: i128 = 1_000_000_000_000_000; // 1M units
const MIN_PREMIUM_AMOUNT: i128 = 100_000; // 0.1 units
const MAX_PREMIUM_AMOUNT: i128 = 100_000_000_000_000; // 100k units
const MIN_POLICY_DURATION_DAYS: u32 = 1;
const MAX_POLICY_DURATION_DAYS: u32 = 365;

#[contract]
pub struct PolicyContract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Paused,
    Config,
    Policy(u64),
    PolicyCounter,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub risk_pool: Address,
}

// Step 1: Define the Policy State Enum
/// Represents the lifecycle states of a policy.
/// This is a closed enum with only valid states - no string states allowed.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyState {
    Active,
    Expired,
    Cancelled,
}

// Step 2: Define Allowed State Transitions
impl PolicyState {
    /// Validates whether a transition from the current state to the next state is allowed.
    ///
    /// Valid transitions:
    /// - Active → Expired
    /// - Active → Cancelled
    /// - Expired → (no transitions)
    /// - Cancelled → (no transitions)
    pub fn can_transition_to(self, next: PolicyState) -> bool {
        match (self, next) {
            // Active can transition to Expired or Cancelled
            (PolicyState::Active, PolicyState::Expired) => true,
            (PolicyState::Active, PolicyState::Cancelled) => true,
            // Expired and Cancelled are terminal states - no transitions allowed
            (PolicyState::Expired, _) => false,
            (PolicyState::Cancelled, _) => false,
            // Self-transitions are not allowed
            _ => false,
        }
    }
}

// Step 3: Define the Policy Struct
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub holder: Address,
    pub coverage_amount: i128,
    pub premium_amount: i128,
    pub start_time: u64,
    pub end_time: u64,
    state: PolicyState,  // Private - controlled through methods
    pub created_at: u64,
}

// Step 4: Implement Policy Methods
impl Policy {
    /// Creates a new policy in Active state
    pub fn new(
        holder: Address,
        coverage_amount: i128,
        premium_amount: i128,
        start_time: u64,
        end_time: u64,
        created_at: u64,
    ) -> Self {
        Policy {
            holder,
            coverage_amount,
            premium_amount,
            start_time,
            end_time,
            state: PolicyState::Active,
            created_at,
        }
    }

    /// Returns the current state (read-only)
    pub fn state(&self) -> PolicyState {
        self.state
    }

    /// Attempts to transition to a new state
    pub fn transition_to(&mut self, next: PolicyState) -> Result<(), ContractError> {
        if !self.state.can_transition_to(next) {
            return Err(ContractError::InvalidStateTransition);
        }
        self.state = next;
        Ok(())
    }

    /// Cancels the policy (only if Active)
    pub fn cancel(&mut self) -> Result<(), ContractError> {
        self.transition_to(PolicyState::Cancelled)
    }

    /// Expires the policy (only if Active)
    pub fn expire(&mut self) -> Result<(), ContractError> {
        self.transition_to(PolicyState::Expired)
    }

    /// Checks if the policy is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, PolicyState::Active)
    }

    /// Checks if the policy is expired
    pub fn is_expired(&self) -> bool {
        matches!(self.state, PolicyState::Expired)
    }

    /// Checks if the policy is cancelled
    pub fn is_cancelled(&self) -> bool {
        matches!(self.state, PolicyState::Cancelled)
    }
}

// Step 5: Define Domain Errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PolicyError {
    /// Invalid state transition attempted
    InvalidStateTransition = 1,
    /// Access denied for the requested operation
    AccessDenied = 2,
    /// Policy not found
    NotFound = 3,
    /// Invalid input parameters
    InvalidInput = 4,
    /// Policy is in an invalid state for the requested operation
    InvalidState = 5,
}

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
    InvalidRole = 11,
    RoleNotFound = 12,
    NotTrustedContract = 13,
    // Invariant violation errors (100-199)
    InvalidPolicyState = 101,
    InvalidAmount = 103,
    InvalidPremium = 106,
    Overflow2 = 107,
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
            InvariantError::InvalidPolicyState => ContractError::InvalidPolicyState,
            InvariantError::InvalidAmount => ContractError::InvalidAmount,
            InvariantError::InvalidPremium => ContractError::InvalidPremium,
            InvariantError::Overflow => ContractError::Overflow2,
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
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

fn set_paused(env: &Env, paused: bool) {
    env.storage()
        .persistent()
        .set(&DataKey::Paused, &paused);
}

fn next_policy_id(env: &Env) -> u64 {
    let current_id: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::PolicyCounter)
        .unwrap_or(0u64);
    let next_id = current_id + 1;
    env.storage()
        .persistent()
        .set(&DataKey::PolicyCounter, &next_id);
    next_id
}

/// I2: Validate policy state transition
/// Maps valid state transitions for policy lifecycle:
/// Active -> Expired (time-based), Cancelled, or Claimed
fn is_valid_policy_state_transition(current: PolicyStatus, next: PolicyStatus) -> bool {
    match (&current, &next) {
        // Valid forward transitions
        (PolicyStatus::Active, PolicyStatus::Expired) => true,
        (PolicyStatus::Active, PolicyStatus::Cancelled) => true,
        (PolicyStatus::Active, PolicyStatus::Claimed) => true,
        (PolicyStatus::Expired, PolicyStatus::Claimed) => true,
        // Invalid transitions
        _ => false,
    }
}

/// I4: Validate coverage amount within bounds
fn validate_coverage_amount(amount: i128) -> Result<(), ContractError> {
    if amount < MIN_COVERAGE_AMOUNT || amount > MAX_COVERAGE_AMOUNT {
        return Err(ContractError::InvalidAmount);
    }
    Ok(())
}

/// I7: Validate premium amount within bounds
fn validate_premium_amount(premium: i128) -> Result<(), ContractError> {
    if premium < MIN_PREMIUM_AMOUNT || premium > MAX_PREMIUM_AMOUNT {
        return Err(ContractError::InvalidPremium);
    }
    Ok(())
}

/// Validate policy duration
fn validate_duration(duration_days: u32) -> Result<(), ContractError> {
    if duration_days < MIN_POLICY_DURATION_DAYS || duration_days > MAX_POLICY_DURATION_DAYS {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}

#[contractimpl]
impl PolicyContract {
    pub fn initialize(env: Env, admin: Address, risk_pool: Address) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &risk_pool)?;

        // Initialize authorization system with admin
        admin.require_auth();
        initialize_admin(&env, admin.clone());
        
        // Register risk pool contract as trusted for cross-contract calls
        register_trusted_contract(&env, &admin, &risk_pool)?;
        
        let config = Config { risk_pool };
        env.storage().persistent().set(&DataKey::Config, &config);
        
        env.storage()
            .persistent()
            .set(&DataKey::PolicyCounter, &0u64);
        
        set_paused(&env, false);

        env.events().publish(
            (Symbol::new(&env, "initialized"), ()),
            admin,
        );

        Ok(())
    }

    pub fn issue_policy(
        env: Env,
        manager: Address,
        holder: Address,
        coverage_amount: i128,
        premium_amount: i128,
        duration_days: u32,
    ) -> Result<u64, ContractError> {
        // Verify identity and require policy management permission
        manager.require_auth();
        require_policy_management(&env, &manager)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        validate_address(&env, &holder)?;

        // Validate coverage amount within bounds
        validate_coverage_amount(coverage_amount)?;

        // Validate premium amount within bounds
        validate_premium_amount(premium_amount)?;

        // Validate duration within bounds
        validate_duration(duration_days)?;

        let policy_id = next_policy_id(&env);
        let current_time = env.ledger().timestamp();
        let end_time = current_time.checked_add(u64::from(duration_days).checked_mul(86400).ok_or(ContractError::Overflow2)?).ok_or(ContractError::Overflow2)?;

        // Use the new Policy constructor which initializes state to Active
        let policy = Policy::new(
            holder.clone(),
            coverage_amount,
            premium_amount,
            current_time,
            end_time,
            current_time,
        );

        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        env.events().publish(
            (Symbol::new(&env, "PolicyIssued"), policy_id),
            (holder, coverage_amount, premium_amount, duration_days, manager, current_time),
        );

        Ok(policy_id)
    }

    pub fn get_policy(env: Env, policy_id: u64) -> Result<Policy, ContractError> {
        env.storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)
    }

    pub fn get_policy_holder(env: Env, policy_id: u64) -> Result<Address, ContractError> {
        let policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
        Ok(policy.holder)
    }

    pub fn get_coverage_amount(env: Env, policy_id: u64) -> Result<i128, ContractError> {
        let policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
        Ok(policy.coverage_amount)
    }

    pub fn get_premium_amount(env: Env, policy_id: u64) -> Result<i128, ContractError> {
        let policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
        Ok(policy.premium_amount)
    }

    pub fn get_policy_state(env: Env, policy_id: u64) -> Result<PolicyState, ContractError> {
        let policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
        Ok(policy.state())
    }

    pub fn get_policy_dates(env: Env, policy_id: u64) -> Result<(u64, u64), ContractError> {
        let policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;
        Ok((policy.start_time, policy.end_time))
    }

    /// Cancels a policy. Only allowed when the policy is Active.
    pub fn cancel_policy(env: Env, policy_id: u64) -> Result<(), ContractError> {
        require_admin(&env)?;

        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;

        // Use the state machine to cancel the policy
        policy.cancel()?;

        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        env.events().publish(
            (Symbol::new(&env, "policy_cancelled"), policy_id),
            (),
        );

        Ok(())
    }

    /// Expires a policy. Only allowed when the policy is Active.
    pub fn expire_policy(env: Env, policy_id: u64) -> Result<(), ContractError> {
        require_admin(&env)?;

        let mut policy: Policy = env
            .storage()
            .persistent()
            .get(&DataKey::Policy(policy_id))
            .ok_or(ContractError::NotFound)?;

        // Use the state machine to expire the policy
        policy.expire()?;

        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id), &policy);

        env.events().publish(
            (Symbol::new(&env, "policy_expired"), policy_id),
            (),
        );

        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        insurance_contracts::authorization::get_admin(&env)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn get_config(env: Env) -> Result<Config, ContractError> {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn get_risk_pool(env: Env) -> Result<Address, ContractError> {
        let config: Config = env
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .ok_or(ContractError::NotInitialized)?;
        Ok(config.risk_pool)
    }

    pub fn get_policy_count(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::PolicyCounter)
            .unwrap_or(0u64)
    }

    pub fn is_paused(env: Env) -> bool {
        is_paused(&env)
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
    
    /// Grant policy manager role to an address (admin only)
    pub fn grant_manager_role(env: Env, admin: Address, manager: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::grant_role(&env, &admin, &manager, Role::PolicyManager)?;
        
        env.events().publish(
            (Symbol::new(&env, "role_granted"), manager.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Revoke policy manager role from an address (admin only)
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

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Env as _};

    #[test]
    fn test_valid_policy_issuance() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        // Initialize contract
        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();

        // Grant manager role
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        // Issue policy
        let coverage = MIN_COVERAGE_AMOUNT + 1000;
        let premium = MIN_PREMIUM_AMOUNT + 100;
        let duration = 30;

        let policy_id = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            coverage,
            premium,
            duration,
        ).unwrap();

        assert_eq!(policy_id, 1);

        // Verify policy
        let policy = PolicyContract::get_policy(env.clone(), policy_id).unwrap();
        assert_eq!(policy.holder, holder);
        assert_eq!(policy.coverage_amount, coverage);
        assert_eq!(policy.premium_amount, premium);
        assert_eq!(policy.state(), PolicyState::Active);
    }

    #[test]
    fn test_invalid_coverage_too_low() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let result = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            MIN_COVERAGE_AMOUNT - 1,
            MIN_PREMIUM_AMOUNT + 100,
            30,
        );

        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_invalid_coverage_too_high() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let result = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            MAX_COVERAGE_AMOUNT + 1,
            MIN_PREMIUM_AMOUNT + 100,
            30,
        );

        assert_eq!(result, Err(ContractError::InvalidAmount));
    }

    #[test]
    fn test_invalid_premium_too_low() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let result = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            MIN_COVERAGE_AMOUNT + 1000,
            MIN_PREMIUM_AMOUNT - 1,
            30,
        );

        assert_eq!(result, Err(ContractError::InvalidPremium));
    }

    #[test]
    fn test_invalid_premium_too_high() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let result = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            MIN_COVERAGE_AMOUNT + 1000,
            MAX_PREMIUM_AMOUNT + 1,
            30,
        );

        assert_eq!(result, Err(ContractError::InvalidPremium));
    }

    #[test]
    fn test_invalid_duration_too_short() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let result = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            MIN_COVERAGE_AMOUNT + 1000,
            MIN_PREMIUM_AMOUNT + 100,
            MIN_POLICY_DURATION_DAYS - 1,
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_invalid_duration_too_long() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let result = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            MIN_COVERAGE_AMOUNT + 1000,
            MIN_PREMIUM_AMOUNT + 100,
            MAX_POLICY_DURATION_DAYS + 1,
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_duplicate_policy_issuance_not_possible() {
        // Since policy IDs are unique via counter, duplicate issuance isn't possible
        // This test ensures the counter increments properly
        let env = Env::default();
        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let holder = Address::generate(&env);
        let risk_pool = Address::generate(&env);

        PolicyContract::initialize(env.clone(), admin.clone(), risk_pool.clone()).unwrap();
        PolicyContract::grant_manager_role(env.clone(), admin.clone(), manager.clone()).unwrap();

        let coverage = MIN_COVERAGE_AMOUNT + 1000;
        let premium = MIN_PREMIUM_AMOUNT + 100;
        let duration = 30;

        let policy_id1 = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            coverage,
            premium,
            duration,
        ).unwrap();

        let policy_id2 = PolicyContract::issue_policy(
            env.clone(),
            manager.clone(),
            holder.clone(),
            coverage,
            premium,
            duration,
        ).unwrap();

        assert_eq!(policy_id1, 1);
        assert_eq!(policy_id2, 2);
        assert_ne!(policy_id1, policy_id2);
    }
}
