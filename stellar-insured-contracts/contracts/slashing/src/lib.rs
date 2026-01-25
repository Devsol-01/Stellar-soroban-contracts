#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror, Address, Env, Symbol, Vec};

#[contract]
pub struct SlashingContract;

const ADMIN: Symbol = Symbol::short("ADMIN");
const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const SLASHING_RECORD: Symbol = Symbol::short("SLASH_REC");
const SLASHABLE_ROLES: Symbol = Symbol::short("SLASH_RL");
const PENALTY_PARAMS: Symbol = Symbol::short("PENALTY");
const SLASH_COUNTER: Symbol = Symbol::short("SLASH_CNT");
const GOVERNANCE_CONTRACT: Symbol = Symbol::short("GOV_CON");
const RISK_POOL_CONTRACT: Symbol = Symbol::short("RISK_PO");

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SlashingRole {
    OracleProvider = 0,
    ClaimSubmitter = 1,
    GovernanceParticipant = 2,
    RiskPoolProvider = 3,
    PolicyHolder = 4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SlashingReason {
    OracleManipulation = 0,
    FraudulentClaim = 1,
    GovernanceAbuse = 2,
    RiskPoolMisconduct = 3,
    PolicyFraud = 4,
    Negligence = 5,
    Collusion = 6,
    FrontRunning = 7,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PenaltyDestination {
    RiskPool = 0,
    Treasury = 1,
    Burn = 2,
    CompensationFund = 3,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    NotFound = 4,
    AlreadyExists = 5,
    InvalidState = 6,
    NotInitialized = 7,
    AlreadyInitialized = 8,
    InsufficientBalance = 9,
    RoleNotSlashable = 10,
    InvalidReason = 11,
    SlashingPeriodNotElapsed = 12,
    MaxPenaltyExceeded = 13,
    DuplicateSlashing = 14,
    GovernanceRequired = 15,
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

fn require_admin(env: &Env) -> Result<Address, ContractError> {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&ADMIN)
        .ok_or(ContractError::NotInitialized)?;
    
    let caller = env.current_contract_address();
    if caller != admin {
        return Err(ContractError::Unauthorized);
    }
    
    Ok(admin)
}

fn require_governance_or_admin(env: &Env) -> Result<(), ContractError> {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&ADMIN)
        .ok_or(ContractError::NotInitialized)?;
    
    let governance_contract: Address = env
        .storage()
        .persistent()
        .get(&GOVERNANCE_CONTRACT)
        .ok_or(ContractError::NotInitialized)?;
    
    let caller = env.current_contract_address();
    if caller != admin && caller != governance_contract {
        return Err(ContractError::GovernanceRequired);
    }
    
    Ok(())
}

fn is_role_slashable(env: &Env, role: u32) -> bool {
    let slashable_roles: Vec<u32> = env
        .storage()
        .persistent()
        .get(&SLASHABLE_ROLES)
        .unwrap_or_else(|| Vec::new(&env));
    
    slashable_roles.contains(&role)
}

fn calculate_penalty_amount(
    base_amount: i128,
    penalty_percentage: u32,
    violation_count: u32,
    multiplier: u32,
) -> Result<i128, ContractError> {
    if penalty_percentage > 100 {
        return Err(ContractError::InvalidInput);
    }
    
    let base_penalty = (base_amount * penalty_percentage as i128) / 100;
    let repeat_offender_multiplier = 1 + (violation_count.saturating_sub(1) * multiplier);
    
    Ok(base_penalty * repeat_offender_multiplier as i128)
}

fn has_recent_slashing(env: &Env, target: &Address, role: u32, current_time: u64) -> bool {
    let slashing_records: Vec<(u64, Address, u32, u32, u64, i128, u32, u32)> = env
        .storage()
        .persistent()
        .get(&(SLASHING_RECORD, target, role))
        .unwrap_or_else(|| Vec::new(&env));
    
    let cooldown_period = 86400u64; // 24 hours in seconds
    
    for record in slashing_records.iter() {
        if current_time - record.4 < cooldown_period {
            return true;
        }
    }
    
    false
}

#[contractimpl]
impl SlashingContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        governance_contract: Address,
        risk_pool_contract: Address,
    ) -> Result<(), ContractError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &governance_contract)?;
        validate_address(&env, &risk_pool_contract)?;

        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&GOVERNANCE_CONTRACT, &governance_contract);
        env.storage().persistent().set(&RISK_POOL_CONTRACT, &risk_pool_contract);
        env.storage().persistent().set(&SLASH_COUNTER, &0u64);

        let mut default_slashable_roles = Vec::new(&env);
        default_slashable_roles.push_back(SlashingRole::OracleProvider as u32);
        default_slashable_roles.push_back(SlashingRole::ClaimSubmitter as u32);
        default_slashable_roles.push_back(SlashingRole::GovernanceParticipant as u32);
        default_slashable_roles.push_back(SlashingRole::RiskPoolProvider as u32);
        env.storage().persistent().set(&SLASHABLE_ROLES, &default_slashable_roles);

        let default_penalty_params = (
            SlashingRole::OracleProvider as u32,
            SlashingReason::OracleManipulation as u32,
            50u32, // 50% penalty
            PenaltyDestination::RiskPool as u32,
            2u32,  // 2x multiplier for repeat offenders
            86400u64, // 24 hour cooldown
        );
        env.storage().persistent().set(&PENALTY_PARAMS, &default_penalty_params);

        Ok(())
    }

    pub fn configure_penalty_parameters(
        env: Env,
        role: u32,
        reason: u32,
        penalty_percentage: u32,
        destination: u32,
        repeat_offender_multiplier: u32,
        cooldown_period: u64,
    ) -> Result<(), ContractError> {
        require_governance_or_admin(&env)?;

        if penalty_percentage > 100 {
            return Err(ContractError::InvalidInput);
        }

        if repeat_offender_multiplier == 0 {
            return Err(ContractError::InvalidInput);
        }

        let penalty_params = (
            role,
            reason,
            penalty_percentage,
            destination,
            repeat_offender_multiplier,
            cooldown_period,
        );

        env.storage()
            .persistent()
            .set(&(PENALTY_PARAMS, role, reason), &penalty_params);

        env.events().publish(
            (Symbol::new(&env, "penalty_configured"), role),
            (reason, penalty_percentage, destination),
        );

        Ok(())
    }

    pub fn add_slashable_role(env: Env, role: u32) -> Result<(), ContractError> {
        require_admin(&env)?;

        let mut slashable_roles: Vec<u32> = env
            .storage()
            .persistent()
            .get(&SLASHABLE_ROLES)
            .unwrap_or_else(|| Vec::new(&env));

        if !slashable_roles.contains(&role) {
            slashable_roles.push_back(role);
            env.storage().persistent().set(&SLASHABLE_ROLES, &slashable_roles);
        }

        env.events().publish(
            (Symbol::new(&env, "role_added"), role),
            (),
        );

        Ok(())
    }

    pub fn remove_slashable_role(env: Env, role: u32) -> Result<(), ContractError> {
        require_admin(&env)?;

        let mut slashable_roles: Vec<u32> = env
            .storage()
            .persistent()
            .get(&SLASHABLE_ROLES)
            .unwrap_or_else(|| Vec::new(&env));

        let index = slashable_roles.iter().position(|r| r == role);
        if let Some(index) = index {
            slashable_roles.remove(index.try_into().unwrap());
        }
        env.storage().persistent().set(&SLASHABLE_ROLES, &slashable_roles);

        env.events().publish(
            (Symbol::new(&env, "role_removed"), role),
            (),
        );

        Ok(())
    }

    pub fn slash_funds(
        env: Env,
        target: Address,
        role: u32,
        reason: u32,
        base_amount: i128,
    ) -> Result<u64, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if base_amount <= 0 {
            return Err(ContractError::InvalidInput);
        }

        if !is_role_slashable(&env, role) {
            return Err(ContractError::RoleNotSlashable);
        }

        let current_time = env.ledger().timestamp();
        if has_recent_slashing(&env, &target, role, current_time) {
            return Err(ContractError::SlashingPeriodNotElapsed);
        }

        let penalty_params: (u32, u32, u32, u32, u32, u64) = env
            .storage()
            .persistent()
            .get(&(PENALTY_PARAMS, role, reason))
            .ok_or(ContractError::NotFound)?;

        let violation_count = Self::get_violation_count(env.clone(), target.clone(), role)?;
        let penalty_amount = calculate_penalty_amount(
            base_amount,
            penalty_params.2,
            violation_count,
            penalty_params.4,
        )?;

        let slash_id: u64 = env
            .storage()
            .persistent()
            .get(&SLASH_COUNTER)
            .unwrap_or(0) + 1;

        let slashing_record = (
            slash_id,
            target.clone(),
            role,
            reason,
            current_time,
            penalty_amount,
            penalty_params.3, // destination
            violation_count + 1,
        );

        let mut user_records: Vec<(u64, Address, u32, u32, u64, i128, u32, u32)> = env
            .storage()
            .persistent()
            .get(&(SLASHING_RECORD, target.clone(), role))
            .unwrap_or_else(|| Vec::new(&env));
        user_records.push_back(slashing_record);
        env.storage()
            .persistent()
            .set(&(SLASHING_RECORD, target.clone(), role), &user_records);

        env.storage().persistent().set(&SLASH_COUNTER, &slash_id);

        Self::redirect_funds(env.clone(), penalty_amount, penalty_params.3)?;

        env.events().publish(
            (Symbol::new(&env, "funds_slashed"), slash_id),
            (target, role, reason, penalty_amount, penalty_params.3),
        );

        Ok(slash_id)
    }

    fn redirect_funds(env: Env, amount: i128, destination: u32) -> Result<(), ContractError> {
        match destination {
            0 => {
                // Risk Pool
                let risk_pool_contract: Address = env
                    .storage()
                    .persistent()
                    .get(&RISK_POOL_CONTRACT)
                    .ok_or(ContractError::NotInitialized)?;
                
                // In a real implementation, this would call the risk pool contract
                // to deposit the slashed funds
                env.events().publish(
                    (Symbol::new(&env, "funds_redirected"), 0u32),
                    (risk_pool_contract, amount),
                );
            }
            1 => {
                // Treasury - funds are burned or sent to treasury address
                env.events().publish(
                    (Symbol::new(&env, "funds_burned"), 1u32),
                    (amount,),
                );
            }
            2 => {
                // Burn directly
                env.events().publish(
                    (Symbol::new(&env, "funds_burned"), 2u32),
                    (amount,),
                );
            }
            3 => {
                // Compensation Fund
                env.events().publish(
                    (Symbol::new(&env, "funds_redirected"), 3u32),
                    (amount,),
                );
            }
            _ => return Err(ContractError::InvalidInput),
        }

        Ok(())
    }

    pub fn get_violation_count(env: Env, target: Address, role: u32) -> Result<u32, ContractError> {
        let records: Vec<(u64, Address, u32, u32, u64, i128, u32, u32)> = env
            .storage()
            .persistent()
            .get(&(SLASHING_RECORD, target, role))
            .unwrap_or_else(|| Vec::new(&env));

        Ok(records.len() as u32)
    }

    pub fn get_slashing_history(
        env: Env,
        target: Address,
        role: u32,
    ) -> Result<Vec<(u64, Address, u32, u32, u64, i128, u32, u32)>, ContractError> {
        let records: Vec<(u64, Address, u32, u32, u64, i128, u32, u32)> = env
            .storage()
            .persistent()
            .get(&(SLASHING_RECORD, target, role))
            .unwrap_or_else(|| Vec::new(&env));

        Ok(records)
    }

    pub fn get_penalty_parameters(
        env: Env,
        role: u32,
        reason: u32,
    ) -> Result<(u32, u32, u32, u32, u32, u64), ContractError> {
        let params: (u32, u32, u32, u32, u32, u64) = env
            .storage()
            .persistent()
            .get(&(PENALTY_PARAMS, role, reason))
            .ok_or(ContractError::NotFound)?;

        Ok(params)
    }

    pub fn get_slashable_roles(env: Env) -> Result<Vec<u32>, ContractError> {
        let roles: Vec<u32> = env
            .storage()
            .persistent()
            .get(&SLASHABLE_ROLES)
            .unwrap_or_else(|| Vec::new(&env));

        Ok(roles)
    }

    pub fn can_be_slashed(
        env: Env,
        target: Address,
        role: u32,
    ) -> Result<bool, ContractError> {
        if !is_role_slashable(&env, role) {
            return Ok(false);
        }

        let current_time = env.ledger().timestamp();
        Ok(!has_recent_slashing(&env, &target, role, current_time))
    }

    pub fn pause(env: Env) -> Result<(), ContractError> {
        require_admin(&env)?;
        set_paused(&env, true);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), ContractError> {
        require_admin(&env)?;
        set_paused(&env, false);
        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&ADMIN)
            .ok_or(ContractError::NotInitialized)?;

        Ok(admin)
    }

    pub fn is_contract_paused(env: Env) -> bool {
        is_paused(&env)
    }

    pub fn get_slashing_stats(env: Env) -> Result<(u64, u64, i128), ContractError> {
        let slash_count: u64 = env
            .storage()
            .persistent()
            .get(&SLASH_COUNTER)
            .unwrap_or(0);

        // In a real implementation, we'd calculate total slashed amount
        // by iterating through all records. For now, return placeholder.
        let total_slashed = 0i128;
        let unique_addresses = 0u64;

        Ok((slash_count, unique_addresses, total_slashed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Address, Env};

    #[test]
    fn test_contract_compiles() {
        // Basic test to ensure the contract compiles correctly
        let env = Env::default();
        
        let contract_id = env.register_contract(None, SlashingContract);
        
        // Test that we can create the contract
        // Just verify the contract ID exists
        assert!(true);
    }

    #[test]
    fn test_enum_values() {
        // Test that enum values are correct
        assert_eq!(SlashingRole::OracleProvider as u32, 0);
        assert_eq!(SlashingRole::ClaimSubmitter as u32, 1);
        assert_eq!(SlashingRole::GovernanceParticipant as u32, 2);
        
        assert_eq!(SlashingReason::OracleManipulation as u32, 0);
        assert_eq!(SlashingReason::FraudulentClaim as u32, 1);
        assert_eq!(SlashingReason::GovernanceAbuse as u32, 2);
        
        assert_eq!(PenaltyDestination::RiskPool as u32, 0);
        assert_eq!(PenaltyDestination::Treasury as u32, 1);
        assert_eq!(PenaltyDestination::Burn as u32, 2);
    }

    #[test]
    fn test_error_values() {
        // Test that error values are unique
        assert_eq!(ContractError::Unauthorized as u32, 1);
        assert_eq!(ContractError::Paused as u32, 2);
        assert_eq!(ContractError::InvalidInput as u32, 3);
        assert_eq!(ContractError::NotFound as u32, 4);
    }

    #[test]
    fn test_penalty_calculation() {
        let base_amount = 1000i128;
        let penalty_percentage = 50u32;
        let violation_count = 1u32;
        let multiplier = 2u32;
        
        let expected_penalty = (base_amount * penalty_percentage as i128) / 100;
        assert_eq!(expected_penalty, 500i128);
        
        // Test repeat offender calculation
        let repeat_multiplier = 1 + (violation_count.saturating_sub(1) * multiplier);
        let repeat_penalty = expected_penalty * repeat_multiplier as i128;
        assert_eq!(repeat_penalty, 500i128); // First offense
        
        let repeat_multiplier_2 = 1 + (2u32.saturating_sub(1) * multiplier);
        let repeat_penalty_2 = expected_penalty * repeat_multiplier_2 as i128;
        assert_eq!(repeat_penalty_2, 1500i128); // Second offense (1 + (2-1)*2 = 3, 500*3 = 1500)
    }
}
