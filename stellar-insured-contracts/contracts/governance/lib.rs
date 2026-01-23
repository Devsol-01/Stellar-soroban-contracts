#![no_std]
use soroban_sdk::{contract, contractimpl, contracterror, Address, Env, Symbol, Vec};

// Import authorization from the common library
use insurance_contracts::authorization::{
    initialize_admin, require_admin, require_governance_permission, Role, get_role
};

#[contract]
pub struct GovernanceContract;

const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const PROPOSAL: Symbol = Symbol::short("PROPOSAL");
const PROPOSAL_COUNTER: Symbol = Symbol::short("PROP_CNT");
const VOTER: Symbol = Symbol::short("VOTER");
const PROPOSAL_LIST: Symbol = Symbol::short("PROP_LIST");

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ProposalStatus {
    Active = 0,
    Passed = 1,
    Rejected = 2,
    Executed = 3,
    Expired = 4,
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
    NotInitialized = 8,
    AlreadyInitialized = 9,
    VotingPeriodEnded = 10,
    AlreadyVoted = 11,
    ProposalNotActive = 12,
    QuorumNotMet = 13,
    ThresholdNotMet = 14,
    InvalidRole = 15,
    RoleNotFound = 16,
    NotTrustedContract = 17,
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

fn is_voting_period_active(proposal_status: u32, voting_ends_at: u64, current_time: u64) -> bool {
    current_time < voting_ends_at && proposal_status == ProposalStatus::Active as u32
}

fn has_voted(env: &Env, proposal_id: u64, voter: &Address) -> bool {
    env.storage()
        .persistent()
        .has(&(VOTER, proposal_id, voter))
}

fn calculate_quorum_met(yes_votes: i128, no_votes: i128, total_supply: i128, min_quorum_percentage: u32) -> bool {
    let total_votes = yes_votes + no_votes;
    if total_supply == 0 {
        return false;
    }
    let quorum_percentage = (total_votes * 100) / total_supply;
    quorum_percentage >= min_quorum_percentage as i128
}

fn calculate_threshold_met(yes_votes: i128, no_votes: i128, threshold_percentage: u32) -> bool {
    let total_votes = yes_votes + no_votes;
    if total_votes == 0 {
        return false;
    }
    let yes_percentage = (yes_votes * 100) / total_votes;
    yes_percentage >= threshold_percentage as i128
}

#[contractimpl]
impl GovernanceContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        token_contract: Address,
        voting_period_days: u32,
        min_voting_percentage: u32,
        min_quorum_percentage: u32,
    ) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &token_contract)?;

        if voting_period_days == 0 || voting_period_days > 365 {
            return Err(ContractError::InvalidInput);
        }

        if min_voting_percentage == 0 || min_voting_percentage > 100 {
            return Err(ContractError::InvalidInput);
        }

        if min_quorum_percentage == 0 || min_quorum_percentage > 100 {
            return Err(ContractError::InvalidInput);
        }

        // Initialize authorization system with admin
        admin.require_auth();
        initialize_admin(&env, admin.clone());

        env.storage().persistent().set(
            &CONFIG, 
            &(token_contract, voting_period_days, min_voting_percentage, min_quorum_percentage)
        );
        env.storage().persistent().set(&PROPOSAL_COUNTER, &0u64);
        
        env.events().publish(
            (Symbol::new(&env, "initialized"), ()),
            admin,
        );
        
        Ok(())
    }

    pub fn create_proposal(
        env: Env,
        proposer: Address,
        title: Symbol,
        description: Symbol,
        execution_data: Symbol,
        threshold_percentage: u32,
    ) -> Result<u64, ContractError> {
        // Verify identity - governance participants can create proposals
        proposer.require_auth();
        // Note: We could add governance role check here if we want to restrict proposal creation
        // require_governance_permission(&env, &proposer)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if threshold_percentage == 0 || threshold_percentage > 100 {
            return Err(ContractError::InvalidInput);
        }

        let config: (Address, u32, u32, u32) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;
        let proposal_id: u64 = env
            .storage()
            .persistent()
            .get(&PROPOSAL_COUNTER)
            .unwrap_or(0) + 1;
        
        let current_time = env.ledger().timestamp();
        let voting_end_time = current_time + (86400u64 * config.1 as u64);
        
        let proposal = (
            proposal_id,
            proposer.clone(),
            title.clone(),
            description.clone(),
            current_time,
            voting_end_time,
            threshold_percentage,
            ProposalStatus::Active as u32,
            0i128,
            0i128,
            0u32,
            execution_data.clone(),
        );

        env.storage()
            .persistent()
            .set(&(PROPOSAL, proposal_id), &proposal);
        
        env.storage()
            .persistent()
            .set(&PROPOSAL_COUNTER, &proposal_id);

        let mut proposal_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&PROPOSAL_LIST)
            .unwrap_or_else(|| Vec::new(&env));
        proposal_list.push_back(proposal_id);
        env.storage()
            .persistent()
            .set(&PROPOSAL_LIST, &proposal_list);

        env.events().publish(
            (Symbol::new(&env, "proposal_created"), proposal_id),
            (proposer, title, threshold_percentage),
        );

        Ok(proposal_id)
    }

    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<(u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol), ContractError> {
        let proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) = env
            .storage()
            .persistent()
            .get(&(PROPOSAL, proposal_id))
            .ok_or(ContractError::NotFound)?;
        
        Ok(proposal)
    }

    pub fn vote(
        env: Env,
        voter: Address,
        proposal_id: u64,
        vote_weight: i128,
        is_yes: bool,
    ) -> Result<(), ContractError> {
        // Verify identity - anyone can vote (could add governance role check)
        voter.require_auth();
        // Note: We could add governance role check here if we want to restrict voting
        // require_governance_permission(&env, &voter)?;

        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if vote_weight <= 0 {
            return Err(ContractError::InvalidInput);
        }

        let _config: (Address, u32, u32, u32) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        let mut proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) = env
            .storage()
            .persistent()
            .get(&(PROPOSAL, proposal_id))
            .ok_or(ContractError::NotFound)?;

        let current_time = env.ledger().timestamp();
        if !is_voting_period_active(proposal.7, proposal.5, current_time) {
            return Err(ContractError::VotingPeriodEnded);
        }

        if has_voted(&env, proposal_id, &voter) {
            return Err(ContractError::AlreadyVoted);
        }

        let vote_record = (voter.clone(), vote_weight, current_time, is_yes);

        env.storage()
            .persistent()
            .set(&(VOTER, proposal_id, voter.clone()), &vote_record);

        if is_yes {
            proposal.8 += vote_weight;
        } else {
            proposal.9 += vote_weight;
        }
        proposal.10 += 1;

        env.storage()
            .persistent()
            .set(&(PROPOSAL, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "vote_cast"), proposal_id),
            (voter, vote_weight, is_yes, proposal.8, proposal.9),
        );

        Ok(())
    }

    pub fn finalize_proposal(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        let mut proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) = env
            .storage()
            .persistent()
            .get(&(PROPOSAL, proposal_id))
            .ok_or(ContractError::NotFound)?;

        if proposal.7 != ProposalStatus::Active as u32 {
            return Err(ContractError::ProposalNotActive);
        }

        let current_time = env.ledger().timestamp();
        if current_time < proposal.5 {
            return Err(ContractError::InvalidState);
        }

        let config: (Address, u32, u32, u32) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        let min_quorum_percentage = config.3;

        let total_supply = 1000000i128;

        if !calculate_quorum_met(proposal.8, proposal.9, total_supply, min_quorum_percentage) {
            proposal.7 = ProposalStatus::Expired as u32;
        } else if calculate_threshold_met(proposal.8, proposal.9, proposal.6) {
            proposal.7 = ProposalStatus::Passed as u32;
        } else {
            proposal.7 = ProposalStatus::Rejected as u32;
        }

        env.storage()
            .persistent()
            .set(&(PROPOSAL, proposal_id), &proposal);

        let total_votes = proposal.8 + proposal.9;
        let yes_percentage = if total_votes > 0 {
            (proposal.8 * 100) / total_votes
        } else {
            0
        };

        env.events().publish(
            (Symbol::new(&env, "proposal_finalized"), proposal_id),
            (proposal.7, yes_percentage, proposal.8, proposal.9),
        );

        Ok(())
    }

    pub fn execute_proposal(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        let mut proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) = env
            .storage()
            .persistent()
            .get(&(PROPOSAL, proposal_id))
            .ok_or(ContractError::NotFound)?;

        if proposal.7 != ProposalStatus::Passed as u32 {
            return Err(ContractError::InvalidState);
        }

        proposal.7 = ProposalStatus::Executed as u32;

        env.storage()
            .persistent()
            .set(&(PROPOSAL, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "proposal_executed"), proposal_id),
            (proposal.11,),
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

    pub fn get_vote_record(env: Env, proposal_id: u64, voter: Address) -> Result<(Address, i128, u64, bool), ContractError> {
        let vote_record: (Address, i128, u64, bool) = env
            .storage()
            .persistent()
            .get(&(VOTER, proposal_id, voter))
            .ok_or(ContractError::NotFound)?;
        
        Ok(vote_record)
    }

    pub fn get_all_proposals(env: Env) -> Result<Vec<u64>, ContractError> {
        let proposal_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&PROPOSAL_LIST)
            .unwrap_or_else(|| Vec::new(&env));
        
        Ok(proposal_list)
    }

    pub fn get_active_proposals(env: Env) -> Result<Vec<u64>, ContractError> {
        let all_proposals = Self::get_all_proposals(env.clone())?;
        let current_time = env.ledger().timestamp();
        let mut active_proposals = Vec::new(&env);

        for proposal_id in all_proposals.iter() {
            if let Ok(proposal) = Self::get_proposal(env.clone(), proposal_id) {
                if is_voting_period_active(proposal.7, proposal.5, current_time) {
                    active_proposals.push_back(proposal_id);
                }
            }
        }

        Ok(active_proposals)
    }

    pub fn get_proposal_stats(env: Env, proposal_id: u64) -> Result<(i128, i128, u32, u64, u64), ContractError> {
        let proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) = Self::get_proposal(env.clone(), proposal_id)?;
        
        let total_votes = proposal.8 + proposal.9;
        let yes_percentage = if total_votes > 0 {
            (proposal.8 * 100) / total_votes
        } else {
            0
        };

        Ok((
            proposal.8,
            proposal.9,
            proposal.10,
            yes_percentage as u64,
            proposal.5,
        ))
    }

    pub fn get_config(env: Env) -> Result<(Address, u32, u32, u32), ContractError> {
        let config: (Address, u32, u32, u32) = env
            .storage()
            .persistent()
            .get(&CONFIG)
            .ok_or(ContractError::NotInitialized)?;
        
        Ok(config)
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        insurance_contracts::authorization::get_admin(&env)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn is_contract_paused(env: Env) -> bool {
        is_paused(&env)
    }

    pub fn get_proposal_count(env: Env) -> Result<u64, ContractError> {
        let count: u64 = env
            .storage()
            .persistent()
            .get(&PROPOSAL_COUNTER)
            .unwrap_or(0);
        
        Ok(count)
    }
    
    /// Grant governance role to an address (admin only)
    pub fn grant_governance_role(env: Env, admin: Address, participant: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::grant_role(&env, &admin, &participant, Role::Governance)?;
        
        env.events().publish(
            (Symbol::new(&env, "role_granted"), participant.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Revoke governance role from an address (admin only)
    pub fn revoke_governance_role(env: Env, admin: Address, participant: Address) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;
        
        insurance_contracts::authorization::revoke_role(&env, &admin, &participant)?;
        
        env.events().publish(
            (Symbol::new(&env, "role_revoked"), participant.clone()),
            admin,
        );
        
        Ok(())
    }
    
    /// Get the role of an address
    pub fn get_user_role(env: Env, address: Address) -> Role {
        get_role(&env, &address)
    }
}
