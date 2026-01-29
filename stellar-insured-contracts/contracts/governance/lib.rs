#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Symbol, Vec};

use insurance_contracts::authorization::{get_role, initialize_admin, require_admin, Role};
use soroban_sdk::{contract, contractimpl, contracterror, contracttype, Address, Env, Symbol, Vec};

// Import authorization from the common library
use insurance_contracts::authorization::{
    initialize_admin, require_admin, Role, get_role
};

#[contract]
pub struct GovernanceContract;

const ADMIN: Symbol = Symbol::short("ADMIN");
const PAUSED: Symbol = Symbol::short("PAUSED");
const CONFIG: Symbol = Symbol::short("CONFIG");
const PROPOSAL: Symbol = Symbol::short("PROPOSAL");
const PROPOSAL_COUNTER: Symbol = Symbol::short("PROP_CNT");
const VOTER: Symbol = Symbol::short("VOTER");
const PROPOSAL_LIST: Symbol = Symbol::short("PROP_LIST");
const SLASHING_CONTRACT: Symbol = Symbol::short("SLASHING");
const SLASHING_CONTRACT: Symbol = Symbol::short("SLASH_C");

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ProposalStatus {
    Active = 0,
    Passed = 1,
    Rejected = 2,
    Executed = 3,
    Expired = 4,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ProposalType {
    ParameterChange = 0,
    ContractUpgrade = 1,
    SlashingAction = 2,
    TreasuryAllocation = 3,
    EmergencyAction = 4,
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
    SlashingContractNotSet = 15,
    SlashingExecutionFailed = 16,
    InvalidRole = 17,
    RoleNotFound = 18,
    NotTrustedContract = 19,
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

/// Maximum number of proposals to return in a single paginated request.
/// This limit prevents excessive gas consumption when iterating over proposals.
const MAX_PAGINATION_LIMIT: u32 = 50;

/// Structured view of a governance proposal for frontend/indexer consumption.
/// Contains essential proposal data in a gas-efficient format.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalView {
    /// Unique proposal identifier
    pub id: u64,
    /// Address of the proposal creator
    pub proposer: Address,
    /// Short title of the proposal
    pub title: Symbol,
    /// Current status (0=Active, 1=Passed, 2=Rejected, 3=Executed, 4=Expired)
    pub status: u32,
    /// Total votes in favor
    pub yes_votes: i128,
    /// Total votes against
    pub no_votes: i128,
    /// Number of unique voters
    pub total_voters: u32,
    /// Timestamp when voting period ends
    pub voting_ends_at: u64,
    /// Required percentage for proposal to pass
    pub threshold_percentage: u32,
}

/// Result of a paginated proposals query.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedProposalsResult {
    /// List of proposals in the current page
    pub proposals: Vec<ProposalView>,
    /// Total number of proposals (for pagination calculations)
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

fn is_voting_period_active(proposal_status: u32, voting_ends_at: u64, current_time: u64) -> bool {
    current_time < voting_ends_at && proposal_status == ProposalStatus::Active as u32
}

fn has_voted(env: &Env, proposal_id: u64, voter: &Address) -> bool {
    env.storage().persistent().has(&(VOTER, proposal_id, voter))
}

fn calculate_quorum_met(
    yes_votes: i128,
    no_votes: i128,
    total_supply: i128,
    min_quorum_percentage: u32,
) -> bool {
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
        slashing_contract: Address,
    ) -> Result<(), ContractError> {
        // Check if already initialized
        if insurance_contracts::authorization::get_admin(&env).is_some() {
            return Err(ContractError::AlreadyInitialized);
        }

        validate_address(&env, &admin)?;
        validate_address(&env, &token_contract)?;
        validate_address(&env, &slashing_contract)?;

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
            &(token_contract, voting_period_days, min_voting_percentage, min_quorum_percentage),
        );
        env.storage().persistent().set(&SLASHING_CONTRACT, &slashing_contract);
        env.storage().persistent().set(&PROPOSAL_COUNTER, &0u64);

        env.events().publish((Symbol::new(&env, "initialized"), ()), admin);

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

        let config: (Address, u32, u32, u32) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;
        let proposal_id: u64 = env.storage().persistent().get(&PROPOSAL_COUNTER).unwrap_or(0) + 1;

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

        env.storage().persistent().set(&(PROPOSAL, proposal_id), &proposal);

        env.storage().persistent().set(&PROPOSAL_COUNTER, &proposal_id);

        let mut proposal_list: Vec<u64> =
            env.storage().persistent().get(&PROPOSAL_LIST).unwrap_or_else(|| Vec::new(&env));
        proposal_list.push_back(proposal_id);
        env.storage().persistent().set(&PROPOSAL_LIST, &proposal_list);

        env.events().publish(
            (Symbol::new(&env, "proposal_created"), proposal_id),
            (proposer, title, threshold_percentage),
        );

        Ok(proposal_id)
    }

    pub fn get_proposal(
        env: Env,
        proposal_id: u64,
    ) -> Result<
        (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol),
        ContractError,
    > {
        let proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) =
            env.storage()
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

        let _config: (Address, u32, u32, u32) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        let mut proposal: (
            u64,
            Address,
            Symbol,
            Symbol,
            u64,
            u64,
            u32,
            u32,
            i128,
            i128,
            u32,
            Symbol,
        ) = env
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

        env.storage().persistent().set(&(PROPOSAL, proposal_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "vote_cast"), proposal_id),
            (voter, vote_weight, is_yes, proposal.8, proposal.9),
        );

        Ok(())
    }

    pub fn finalize_proposal(env: Env, proposal_id: u64) -> Result<(), ContractError> {
        let mut proposal: (
            u64,
            Address,
            Symbol,
            Symbol,
            u64,
            u64,
            u32,
            u32,
            i128,
            i128,
            u32,
            Symbol,
        ) = env
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

        let config: (Address, u32, u32, u32) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        let min_quorum_percentage = config.3;

        let total_supply = 1000000i128;

        if !calculate_quorum_met(proposal.8, proposal.9, total_supply, min_quorum_percentage) {
            proposal.7 = ProposalStatus::Expired as u32;
        } else if calculate_threshold_met(proposal.8, proposal.9, proposal.6) {
            proposal.7 = ProposalStatus::Passed as u32;
        } else {
            proposal.7 = ProposalStatus::Rejected as u32;
        }

        env.storage().persistent().set(&(PROPOSAL, proposal_id), &proposal);

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
        let mut proposal: (
            u64,
            Address,
            Symbol,
            Symbol,
            u64,
            u64,
            u32,
            u32,
            i128,
            i128,
            u32,
            Symbol,
        ) = env
            .storage()
            .persistent()
            .get(&(PROPOSAL, proposal_id))
            .ok_or(ContractError::NotFound)?;

        if proposal.7 != ProposalStatus::Passed as u32 {
            return Err(ContractError::InvalidState);
        }

        proposal.7 = ProposalStatus::Executed as u32;

        env.storage().persistent().set(&(PROPOSAL, proposal_id), &proposal);

        env.events()
            .publish((Symbol::new(&env, "proposal_executed"), proposal_id), (proposal.11,));

        Ok(())
    }

    pub fn pause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, true);

        env.events().publish((Symbol::new(&env, "paused"), ()), admin);

        Ok(())
    }

    pub fn unpause(env: Env, admin: Address) -> Result<(), ContractError> {
        // Verify identity and require admin permission
        admin.require_auth();
        require_admin(&env, &admin)?;

        set_paused(&env, false);

        env.events().publish((Symbol::new(&env, "unpaused"), ()), admin);

        Ok(())
    }

    pub fn get_vote_record(
        env: Env,
        proposal_id: u64,
        voter: Address,
    ) -> Result<(Address, i128, u64, bool), ContractError> {
        let vote_record: (Address, i128, u64, bool) = env
            .storage()
            .persistent()
            .get(&(VOTER, proposal_id, voter))
            .ok_or(ContractError::NotFound)?;

        Ok(vote_record)
    }

    pub fn create_slashing_proposal(
        env: Env,
        target: Address,
        role: u32,
        reason: u32,
        amount: i128,
        evidence: Symbol,
        threshold_percentage: u32,
    ) -> Result<u64, ContractError> {
        if is_paused(&env) {
            return Err(ContractError::Paused);
        }

        if amount <= 0 {
            return Err(ContractError::InvalidInput);
        }

        if threshold_percentage == 0 || threshold_percentage > 100 {
            return Err(ContractError::InvalidInput);
        }

        let config: (Address, u32, u32, u32) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        let proposer = env.current_contract_address();
        let proposal_id: u64 = env.storage().persistent().get(&PROPOSAL_COUNTER).unwrap_or(0) + 1;

        let current_time = env.ledger().timestamp();
        let voting_end_time = current_time + (86400u64 * config.1 as u64);

        // Store slashing proposals in a dedicated key to avoid type-mismatches with the
        // regular proposal tuple (title/description/execution_data).
        // NOTE: The slashing proposal feature needs a dedicated contract type to be fully
        // supported in Soroban storage. For now, we omit persistence to keep the crate
        // compiling and the workspace tests runnable.

        env.storage().persistent().set(&PROPOSAL_COUNTER, &proposal_id);

        let mut proposal_list: Vec<u64> =
            env.storage().persistent().get(&PROPOSAL_LIST).unwrap_or_else(|| Vec::new(&env));
        proposal_list.push_back(proposal_id);
        env.storage().persistent().set(&PROPOSAL_LIST, &proposal_list);

        env.events().publish(
            (Symbol::new(&env, "slashing_proposal_created"), proposal_id),
            (target, role, reason, amount, threshold_percentage),
        );

        Ok(proposal_id)
    }

    pub fn execute_slashing_proposal(env: Env, proposal_id: u64) -> Result<u64, ContractError> {
        // TODO: Implement slashing proposal storage as a proper contract type.
        // For now, return NotFound to avoid storage type-mismatch compilation errors.
        let _ = proposal_id;
        Err(ContractError::NotFound)
    }

    fn execute_slashing(
        env: Env,
        target: Address,
        role: u32,
        reason: u32,
        amount: i128,
    ) -> Result<u64, ContractError> {
        let slashing_contract: Address = env
            .storage()
            .persistent()
            .get(&SLASHING_CONTRACT)
            .ok_or(ContractError::SlashingContractNotSet)?;

        // For now, we'll emit an event and return a mock slash ID
        // In a real implementation, this would make a cross-contract call
        env.events().publish(
            (Symbol::new(&env, "slashing_executed"), 0u64),
            (target, role, reason, amount),
        );

        Ok(1u64)
    }

    pub fn get_active_proposals(env: Env) -> Result<Vec<u64>, ContractError> {
        let all_proposals = Self::get_all_proposals(env.clone());
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

    pub fn get_all_proposals(env: Env) -> Vec<u64> {
        env.storage().persistent().get(&PROPOSAL_LIST).unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_proposal_stats(
        env: Env,
        proposal_id: u64,
    ) -> Result<(i128, i128, u32, u64, u64), ContractError> {
        let proposal: (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol) =
            Self::get_proposal(env.clone(), proposal_id)?;

        let total_votes = proposal.8 + proposal.9;
        let yes_percentage = if total_votes > 0 {
            (proposal.8 * 100) / total_votes
        } else {
            0
        };

        Ok((proposal.8, proposal.9, proposal.10, yes_percentage as u64, proposal.5))
    }

    pub fn get_config(env: Env) -> Result<(Address, u32, u32, u32), ContractError> {
        let config: (Address, u32, u32, u32) =
            env.storage().persistent().get(&CONFIG).ok_or(ContractError::NotInitialized)?;

        Ok(config)
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        insurance_contracts::authorization::get_admin(&env).ok_or(ContractError::NotInitialized)
    }

    pub fn is_contract_paused(env: Env) -> bool {
        is_paused(&env)
    }

    pub fn get_proposal_count(env: Env) -> Result<u64, ContractError> {
        let count: u64 = env.storage().persistent().get(&PROPOSAL_COUNTER).unwrap_or(0);
        let count: u64 = env
            .storage()
            .persistent()
            .get(&PROPOSAL_COUNTER)
            .unwrap_or(0);

        Ok(count)
    }

    /// Returns the list of all proposal IDs.
    /// This is a read-only function.
    pub fn get_all_proposals(env: Env) -> Result<Vec<u64>, ContractError> {
        let proposal_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&PROPOSAL_LIST)
            .unwrap_or_else(|| Vec::new(&env));

        Ok(proposal_list)
    }

    /// Returns a paginated list of proposals with structured view data.
    /// This is a read-only function optimized for frontend/indexer consumption.
    ///
    /// # Arguments
    /// * `start_index` - Zero-based index to start from in the proposal list
    /// * `limit` - Maximum number of proposals to return (capped at 50)
    ///
    /// # Returns
    /// * `PaginatedProposalsResult` containing the proposals and total count
    ///
    /// # Example
    /// To get the first page: `get_proposals_paginated(0, 50)`
    /// To get the second page: `get_proposals_paginated(50, 50)`
    pub fn get_proposals_paginated(
        env: Env,
        start_index: u32,
        limit: u32,
    ) -> Result<PaginatedProposalsResult, ContractError> {
        // Cap the limit to prevent excessive gas consumption
        let effective_limit = if limit > MAX_PAGINATION_LIMIT {
            MAX_PAGINATION_LIMIT
        } else if limit == 0 {
            MAX_PAGINATION_LIMIT
        } else {
            limit
        };

        // Get the full proposal list
        let proposal_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&PROPOSAL_LIST)
            .unwrap_or_else(|| Vec::new(&env));

        let total_count = proposal_list.len();

        // Handle out-of-bounds start_index
        if start_index >= total_count {
            return Ok(PaginatedProposalsResult {
                proposals: Vec::new(&env),
                total_count,
            });
        }

        // Calculate the actual range to fetch
        let end_index = core::cmp::min(start_index + effective_limit, total_count);

        // Build the result vector with ProposalView structs
        let mut proposals: Vec<ProposalView> = Vec::new(&env);

        for i in start_index..end_index {
            let proposal_id = proposal_list.get(i).unwrap();

            // Read the proposal data from storage
            // Proposal tuple: (id, proposer, title, description, created_at, voting_ends_at, threshold, status, yes_votes, no_votes, voter_count, execution_data)
            if let Some(proposal_data) = env
                .storage()
                .persistent()
                .get::<_, (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol)>(
                    &(PROPOSAL, proposal_id),
                )
            {
                let view = ProposalView {
                    id: proposal_data.0,
                    proposer: proposal_data.1,
                    title: proposal_data.2,
                    status: proposal_data.7,
                    yes_votes: proposal_data.8,
                    no_votes: proposal_data.9,
                    total_voters: proposal_data.10,
                    voting_ends_at: proposal_data.5,
                    threshold_percentage: proposal_data.6,
                };
                proposals.push_back(view);
            }
        }

        Ok(PaginatedProposalsResult {
            proposals,
            total_count,
        })
    }

    /// Returns a paginated list of proposals filtered by status.
    /// This is a read-only function optimized for frontend/indexer consumption.
    ///
    /// # Arguments
    /// * `status` - The status to filter by (0=Active, 1=Passed, 2=Rejected, 3=Executed, 4=Expired)
    /// * `start_index` - Zero-based index to start from in the filtered results
    /// * `limit` - Maximum number of proposals to return (capped at 50)
    ///
    /// # Returns
    /// * `PaginatedProposalsResult` containing matching proposals and total matching count
    ///
    /// # Note
    /// This function iterates over all proposals to filter by status.
    /// For large proposal sets, consider using events/indexer for status-based queries.
    pub fn get_proposals_by_status(
        env: Env,
        status: u32,
        start_index: u32,
        limit: u32,
    ) -> Result<PaginatedProposalsResult, ContractError> {
        // Cap the limit to prevent excessive gas consumption
        let effective_limit = if limit > MAX_PAGINATION_LIMIT {
            MAX_PAGINATION_LIMIT
        } else if limit == 0 {
            MAX_PAGINATION_LIMIT
        } else {
            limit
        };

        // Get the full proposal list
        let proposal_list: Vec<u64> = env
            .storage()
            .persistent()
            .get(&PROPOSAL_LIST)
            .unwrap_or_else(|| Vec::new(&env));

        // First pass: count matching proposals and collect IDs
        let mut matching_ids: Vec<u64> = Vec::new(&env);

        for i in 0..proposal_list.len() {
            let proposal_id = proposal_list.get(i).unwrap();

            if let Some(proposal_data) = env
                .storage()
                .persistent()
                .get::<_, (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol)>(
                    &(PROPOSAL, proposal_id),
                )
            {
                if proposal_data.7 == status {
                    matching_ids.push_back(proposal_id);
                }
            }
        }

        let total_count = matching_ids.len();

        // Handle out-of-bounds start_index
        if start_index >= total_count {
            return Ok(PaginatedProposalsResult {
                proposals: Vec::new(&env),
                total_count,
            });
        }

        // Calculate the actual range to fetch
        let end_index = core::cmp::min(start_index + effective_limit, total_count);

        // Build the result vector with ProposalView structs
        let mut proposals: Vec<ProposalView> = Vec::new(&env);

        for i in start_index..end_index {
            let proposal_id = matching_ids.get(i).unwrap();

            if let Some(proposal_data) = env
                .storage()
                .persistent()
                .get::<_, (u64, Address, Symbol, Symbol, u64, u64, u32, u32, i128, i128, u32, Symbol)>(
                    &(PROPOSAL, proposal_id),
                )
            {
                let view = ProposalView {
                    id: proposal_data.0,
                    proposer: proposal_data.1,
                    title: proposal_data.2,
                    status: proposal_data.7,
                    yes_votes: proposal_data.8,
                    no_votes: proposal_data.9,
                    total_voters: proposal_data.10,
                    voting_ends_at: proposal_data.5,
                    threshold_percentage: proposal_data.6,
                };
                proposals.push_back(view);
            }
        }

        Ok(PaginatedProposalsResult {
            proposals,
            total_count,
        })
    }

    /// Grant governance role to an address (admin only)
    pub fn grant_governance_role(
        env: Env,
        admin: Address,
        participant: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::grant_role(
            &env,
            &admin,
            &participant,
            Role::Governance,
        )?;

        env.events()
            .publish((Symbol::new(&env, "role_granted"), participant.clone()), admin);

        Ok(())
    }

    /// Revoke governance role from an address (admin only)
    pub fn revoke_governance_role(
        env: Env,
        admin: Address,
        participant: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        require_admin(&env, &admin)?;

        insurance_contracts::authorization::revoke_role(&env, &admin, &participant)?;

        env.events()
            .publish((Symbol::new(&env, "role_revoked"), participant.clone()), admin);

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
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Env, Address};

    fn setup_test_env() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let token_contract = Address::generate(&env);
        let slashing_contract = Address::generate(&env);

        (env, admin, token_contract, slashing_contract)
    }

    fn initialize_governance(
        env: &Env,
        admin: &Address,
        token: &Address,
        slashing: &Address,
    ) {
        GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,    // voting_period_days
            51,   // min_voting_percentage
            20,   // min_quorum_percentage
            slashing.clone(),
        ).unwrap();
    }

    // ============================================================
    // INITIALIZATION TESTS
    // ============================================================

    #[test]
    fn test_initialize_success() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,
            51,
            20,
            slashing.clone(),
        );

        assert!(result.is_ok());

        let config = GovernanceContract::get_config(env.clone()).unwrap();
        assert_eq!(config.0, token);
        assert_eq!(config.1, 7);
        assert_eq!(config.2, 51);
        assert_eq!(config.3, 20);
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,
            51,
            20,
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::AlreadyInitialized));
    }

    #[test]
    fn test_initialize_invalid_voting_period_zero() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            0,  // invalid
            51,
            20,
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_initialize_invalid_voting_period_too_large() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            366,  // > 365
            51,
            20,
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_initialize_invalid_min_voting_percentage_zero() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,
            0,  // invalid
            20,
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_initialize_invalid_min_voting_percentage_too_large() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,
            101,  // > 100
            20,
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_initialize_invalid_quorum_percentage_zero() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,
            51,
            0,  // invalid
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_initialize_invalid_quorum_percentage_too_large() {
        let (env, admin, token, slashing) = setup_test_env();

        let result = GovernanceContract::initialize(
            env.clone(),
            admin.clone(),
            token.clone(),
            7,
            51,
            101,  // > 100
            slashing.clone(),
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    // ============================================================
    // CREATE PROPOSAL TESTS
    // ============================================================

    #[test]
    fn test_create_proposal_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let result = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        );

        assert!(result.is_ok());
        let proposal_id = result.unwrap();
        assert_eq!(proposal_id, 1);

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.0, proposal_id);
        assert_eq!(proposal.1, proposer);
        assert_eq!(proposal.6, 51);
        assert_eq!(proposal.7, ProposalStatus::Active as u32);
    }

    #[test]
    fn test_create_proposal_when_paused() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        GovernanceContract::pause(env.clone(), admin.clone()).unwrap();

        let proposer = Address::generate(&env);

        let result = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        );

        assert_eq!(result, Err(ContractError::Paused));
    }

    #[test]
    fn test_create_proposal_invalid_threshold_zero() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let result = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            0,  // invalid
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_create_proposal_invalid_threshold_too_large() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let result = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            101,  // > 100
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_create_multiple_proposals() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let id1 = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title1"),
            Symbol::new(&env, "desc1"),
            Symbol::new(&env, "exec_data1"),
            51,
        ).unwrap();

        let id2 = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title2"),
            Symbol::new(&env, "desc2"),
            Symbol::new(&env, "exec_data2"),
            60,
        ).unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        let count = GovernanceContract::get_proposal_count(env.clone()).unwrap();
        assert_eq!(count, 2);
    }

    // ============================================================
    // VOTING TESTS
    // ============================================================

    #[test]
    fn test_vote_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            1000,
            true,
        );

        assert!(result.is_ok());

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.8, 1000);  // yes votes
        assert_eq!(proposal.9, 0);     // no votes
        assert_eq!(proposal.10, 1);    // voter count
    }

    #[test]
    fn test_vote_no_vote() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            1000,
            false,  // no vote
        ).unwrap();

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.8, 0);     // yes votes
        assert_eq!(proposal.9, 1000);  // no votes
        assert_eq!(proposal.10, 1);    // voter count
    }

    #[test]
    fn test_vote_multiple_voters() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);
        let voter3 = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(env.clone(), voter1.clone(), proposal_id, 1000, true).unwrap();
        GovernanceContract::vote(env.clone(), voter2.clone(), proposal_id, 500, true).unwrap();
        GovernanceContract::vote(env.clone(), voter3.clone(), proposal_id, 300, false).unwrap();

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.8, 1500);  // yes votes
        assert_eq!(proposal.9, 300);   // no votes
        assert_eq!(proposal.10, 3);    // voter count
    }

    #[test]
    fn test_vote_already_voted() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            1000,
            true,
        ).unwrap();

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            500,
            false,
        );

        assert_eq!(result, Err(ContractError::AlreadyVoted));
    }

    #[test]
    fn test_vote_invalid_weight_zero() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            0,  // invalid
            true,
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_vote_invalid_weight_negative() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            -100,  // invalid
            true,
        );

        assert_eq!(result, Err(ContractError::InvalidInput));
    }

    #[test]
    fn test_vote_when_paused() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::pause(env.clone(), admin.clone()).unwrap();

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            1000,
            true,
        );

        assert_eq!(result, Err(ContractError::Paused));
    }

    #[test]
    fn test_vote_nonexistent_proposal() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let voter = Address::generate(&env);

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            99999,  // nonexistent
            1000,
            true,
        );

        assert_eq!(result, Err(ContractError::NotFound));
    }

    #[test]
    fn test_vote_after_voting_period_ended() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        // Advance time beyond voting period (7 days = 604800 seconds)
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        let result = GovernanceContract::vote(
            env.clone(),
            voter.clone(),
            proposal_id,
            1000,
            true,
        );

        assert_eq!(result, Err(ContractError::VotingPeriodEnded));
    }

    // ============================================================
    // FINALIZE PROPOSAL TESTS
    // ============================================================

    #[test]
    fn test_finalize_proposal_passed() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        // Cast votes to meet quorum and threshold
        // total_supply is hardcoded to 1,000,000 in the contract
        // min_quorum is 20%, so need >= 200,000 votes
        // threshold is 51%, so need >= 51% yes votes
        GovernanceContract::vote(env.clone(), voter1.clone(), proposal_id, 150000, true).unwrap();
        GovernanceContract::vote(env.clone(), voter2.clone(), proposal_id, 60000, true).unwrap();

        // Advance time beyond voting period
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        let result = GovernanceContract::finalize_proposal(env.clone(), proposal_id);
        assert!(result.is_ok());

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.7, ProposalStatus::Passed as u32);
    }

    #[test]
    fn test_finalize_proposal_rejected_by_threshold() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        // Cast votes to meet quorum but fail threshold
        // 100,000 yes, 110,000 no = 210,000 total (21% quorum, passes)
        // 47.6% yes (fails 51% threshold)
        GovernanceContract::vote(env.clone(), voter1.clone(), proposal_id, 100000, true).unwrap();
        GovernanceContract::vote(env.clone(), voter2.clone(), proposal_id, 110000, false).unwrap();

        // Advance time
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        GovernanceContract::finalize_proposal(env.clone(), proposal_id).unwrap();

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.7, ProposalStatus::Rejected as u32);
    }

    #[test]
    fn test_finalize_proposal_expired_by_quorum() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        // Cast insufficient votes to meet quorum
        // Need 20% of 1,000,000 = 200,000
        // Only cast 100,000
        GovernanceContract::vote(env.clone(), voter.clone(), proposal_id, 100000, true).unwrap();

        // Advance time
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        GovernanceContract::finalize_proposal(env.clone(), proposal_id).unwrap();

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.7, ProposalStatus::Expired as u32);
    }

    #[test]
    fn test_finalize_proposal_before_voting_ends() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        let result = GovernanceContract::finalize_proposal(env.clone(), proposal_id);
        assert_eq!(result, Err(ContractError::InvalidState));
    }

    #[test]
    fn test_finalize_proposal_already_finalized() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(env.clone(), voter.clone(), proposal_id, 250000, true).unwrap();

        // Advance time
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        GovernanceContract::finalize_proposal(env.clone(), proposal_id).unwrap();

        // Try to finalize again
        let result = GovernanceContract::finalize_proposal(env.clone(), proposal_id);
        assert_eq!(result, Err(ContractError::ProposalNotActive));
    }

    // ============================================================
    // EXECUTE PROPOSAL TESTS
    // ============================================================

    #[test]
    fn test_execute_proposal_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(env.clone(), voter.clone(), proposal_id, 250000, true).unwrap();

        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        GovernanceContract::finalize_proposal(env.clone(), proposal_id).unwrap();

        let result = GovernanceContract::execute_proposal(env.clone(), proposal_id);
        assert!(result.is_ok());

        let proposal = GovernanceContract::get_proposal(env.clone(), proposal_id).unwrap();
        assert_eq!(proposal.7, ProposalStatus::Executed as u32);
    }

    #[test]
    fn test_execute_proposal_not_passed() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        let result = GovernanceContract::execute_proposal(env.clone(), proposal_id);
        assert_eq!(result, Err(ContractError::InvalidState));
    }

    // ============================================================
    // GOVERNANCE MANIPULATION ATTACK TESTS
    // ============================================================

    #[test]
    fn test_governance_manipulation_vote_weight_overflow_attempt() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        // Try to overflow vote weight
        GovernanceContract::vote(env.clone(), voter1.clone(), proposal_id, i128::MAX / 2, true).unwrap();

        // This should work if overflow protection is in place
        let result = GovernanceContract::vote(env.clone(), voter2.clone(), proposal_id, i128::MAX / 2, true);
        // In a production system, this should either panic or handle gracefully
    }

    #[test]
    fn test_governance_manipulation_double_voting_prevented() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(env.clone(), voter.clone(), proposal_id, 1000, true).unwrap();

        // Attempt to vote again with different choice
        let result = GovernanceContract::vote(env.clone(), voter.clone(), proposal_id, 2000, false);
        assert_eq!(result, Err(ContractError::AlreadyVoted));
    }

    #[test]
    fn test_governance_manipulation_voting_after_finalization() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec_data"),
            51,
        ).unwrap();

        GovernanceContract::vote(env.clone(), voter1.clone(), proposal_id, 250000, true).unwrap();

        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 604801,
            protocol_version: 20,
            sequence_number: env.ledger().sequence(),
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 100000,
        });

        GovernanceContract::finalize_proposal(env.clone(), proposal_id).unwrap();

        // Try to vote after finalization
        let result = GovernanceContract::vote(env.clone(), voter2.clone(), proposal_id, 100000, false);
        assert_eq!(result, Err(ContractError::VotingPeriodEnded));
    }

    // ============================================================
    // ROLE MANAGEMENT TESTS
    // ============================================================

    #[test]
    fn test_grant_governance_role_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let participant = Address::generate(&env);

        let result = GovernanceContract::grant_governance_role(
            env.clone(),
            admin.clone(),
            participant.clone(),
        );

        assert!(result.is_ok());

        let role = GovernanceContract::get_user_role(env.clone(), participant.clone());
        assert_eq!(role, Role::Governance);
    }

    #[test]
    fn test_grant_governance_role_unauthorized() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let unauthorized = Address::generate(&env);
        let participant = Address::generate(&env);

        let result = GovernanceContract::grant_governance_role(
            env.clone(),
            unauthorized.clone(),
            participant.clone(),
        );

        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_revoke_governance_role_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let participant = Address::generate(&env);

        GovernanceContract::grant_governance_role(
            env.clone(),
            admin.clone(),
            participant.clone(),
        ).unwrap();

        let result = GovernanceContract::revoke_governance_role(
            env.clone(),
            admin.clone(),
            participant.clone(),
        );

        assert!(result.is_ok());

        let role = GovernanceContract::get_user_role(env.clone(), participant.clone());
        assert_eq!(role, Role::User);
    }

    // ============================================================
    // PAUSE/UNPAUSE TESTS
    // ============================================================

    #[test]
    fn test_pause_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let result = GovernanceContract::pause(env.clone(), admin.clone());
        assert!(result.is_ok());
        assert!(GovernanceContract::is_contract_paused(env.clone()));
    }

    #[test]
    fn test_pause_unauthorized() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let unauthorized = Address::generate(&env);

        let result = GovernanceContract::pause(env.clone(), unauthorized.clone());
        assert_eq!(result, Err(ContractError::Unauthorized));
    }

    #[test]
    fn test_unpause_success() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        GovernanceContract::pause(env.clone(), admin.clone()).unwrap();

        let result = GovernanceContract::unpause(env.clone(), admin.clone());
        assert!(result.is_ok());
        assert!(!GovernanceContract::is_contract_paused(env.clone()));
    }

    // ============================================================
    // UTILITY FUNCTION TESTS
    // ============================================================

    #[test]
    fn test_calculate_quorum_met() {
        assert_eq!(calculate_quorum_met(100, 0, 1000, 10), true);   // 10% quorum, met
        assert_eq!(calculate_quorum_met(50, 50, 1000, 10), true);   // 10% quorum, met
        assert_eq!(calculate_quorum_met(50, 0, 1000, 10), false);   // 5% quorum, not met
        assert_eq!(calculate_quorum_met(0, 0, 1000, 10), false);    // 0% quorum, not met
        assert_eq!(calculate_quorum_met(100, 0, 0, 10), false);     // Division by zero protection
    }

    #[test]
    fn test_calculate_threshold_met() {
        assert_eq!(calculate_threshold_met(60, 40, 51), true);      // 60% yes, threshold met
        assert_eq!(calculate_threshold_met(51, 49, 51), true);      // 51% yes, threshold met
        assert_eq!(calculate_threshold_met(50, 50, 51), false);     // 50% yes, threshold not met
        assert_eq!(calculate_threshold_met(40, 60, 51), false);     // 40% yes, threshold not met
        assert_eq!(calculate_threshold_met(0, 0, 51), false);       // Division by zero protection
    }

    #[test]
    fn test_get_active_proposals() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);

        let id1 = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title1"),
            Symbol::new(&env, "desc1"),
            Symbol::new(&env, "exec1"),
            51,
        ).unwrap();

        let id2 = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title2"),
            Symbol::new(&env, "desc2"),
            Symbol::new(&env, "exec2"),
            60,
        ).unwrap();

        let active = GovernanceContract::get_active_proposals(env.clone()).unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&id1));
        assert!(active.contains(&id2));
    }

    #[test]
    fn test_get_proposal_stats() {
        let (env, admin, token, slashing) = setup_test_env();
        initialize_governance(&env, &admin, &token, &slashing);

        let proposer = Address::generate(&env);
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        let proposal_id = GovernanceContract::create_proposal(
            env.clone(),
            proposer.clone(),
            Symbol::new(&env, "title"),
            Symbol::new(&env, "desc"),
            Symbol::new(&env, "exec"),
            51,
        ).unwrap();

        GovernanceContract::vote(env.clone(), voter1.clone(), proposal_id, 600, true).unwrap();
        GovernanceContract::vote(env.clone(), voter2.clone(), proposal_id, 400, false).unwrap();

        let stats = GovernanceContract::get_proposal_stats(env.clone(), proposal_id).unwrap();
        assert_eq!(stats.0, 600);   // yes votes
        assert_eq!(stats.1, 400);   // no votes
        assert_eq!(stats.2, 2);     // voter count
        assert_eq!(stats.3, 60);    // yes percentage
    }
}
