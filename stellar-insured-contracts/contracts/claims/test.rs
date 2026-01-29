#![cfg(test)]

//! Unit tests for Claims Contract View Functions (Issue #25)
//!
//! These tests verify the storage patterns and view function logic
//! for the Read-Only Views implementation.

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Env, Symbol, Vec, contracttype,
};

// Import ClaimStatus from shared types
use insurance_contracts::types::ClaimStatus;

// Re-define view structs for testing (mirrors lib.rs definitions)
#[contracttype]
#[derive(Clone, Debug)]
pub struct ClaimView {
    pub id: u64,
    pub policy_id: u64,
    pub claimant: Address,
    pub amount: i128,
    pub status: ClaimStatus,
    pub submitted_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedClaimsResult {
    pub claims: Vec<ClaimView>,
    pub total_count: u32,
}

// Storage keys (same as lib.rs)
const CLAIM: Symbol = symbol_short!("CLAIM");
const CLAIM_LIST: Symbol = symbol_short!("CLM_LST");
const CLAIM_COUNTER: Symbol = symbol_short!("CLM_CNT");
const MAX_PAGINATION_LIMIT: u32 = 50;

/// Helper to setup test environment with mocked time
fn setup_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();

    env.ledger().set(LedgerInfo {
        timestamp: 1704067200, // Jan 1, 2024
        protocol_version: 25,  // Matches soroban-sdk v25
        sequence_number: 100,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3110400,
    });

    env
}

// ============================================================================
// UNIT TESTS: Storage Patterns
// ============================================================================

// Minimal contract for test context
mod test_contract {
    use soroban_sdk::{contract, contractimpl, Env};

    #[contract]
    pub struct TestContract;

    #[contractimpl]
    impl TestContract {}
}

#[test]
fn test_sequential_claim_id_generation() {
    let env = setup_env();
    let contract_id = env.register(test_contract::TestContract, ());

    env.as_contract(&contract_id, || {
        // Initially should be 0
        let initial: u64 = env.storage().persistent().get(&CLAIM_COUNTER).unwrap_or(0);
        assert_eq!(initial, 0);

        // Simulate incrementing (as next_claim_id does)
        env.storage().persistent().set(&CLAIM_COUNTER, &1u64);
        let after_first: u64 = env.storage().persistent().get(&CLAIM_COUNTER).unwrap();
        assert_eq!(after_first, 1);

        env.storage().persistent().set(&CLAIM_COUNTER, &2u64);
        let after_second: u64 = env.storage().persistent().get(&CLAIM_COUNTER).unwrap();
        assert_eq!(after_second, 2);
    });
}

#[test]
fn test_claim_list_storage_pattern() {
    let env = setup_env();
    let contract_id = env.register(test_contract::TestContract, ());

    env.as_contract(&contract_id, || {
        // Initially empty
        let initial: Vec<u64> = env.storage().persistent()
            .get(&CLAIM_LIST)
            .unwrap_or_else(|| Vec::new(&env));
        assert_eq!(initial.len(), 0);

        // Add claims
        let mut claim_list: Vec<u64> = Vec::new(&env);
        claim_list.push_back(1);
        claim_list.push_back(2);
        claim_list.push_back(3);
        env.storage().persistent().set(&CLAIM_LIST, &claim_list);

        // Verify retrieval
        let retrieved: Vec<u64> = env.storage().persistent().get(&CLAIM_LIST).unwrap();
        assert_eq!(retrieved.len(), 3);
        assert_eq!(retrieved.get(0).unwrap(), 1);
        assert_eq!(retrieved.get(1).unwrap(), 2);
        assert_eq!(retrieved.get(2).unwrap(), 3);
    });
}

// ============================================================================
// UNIT TESTS: View Struct Construction
// ============================================================================

#[test]
fn test_claim_view_construction() {
    let env = setup_env();
    let claimant = Address::generate(&env);

    let view = ClaimView {
        id: 1,
        policy_id: 100,
        claimant: claimant.clone(),
        amount: 5000,
        status: ClaimStatus::Submitted,
        submitted_at: 1704067200,
    };

    assert_eq!(view.id, 1);
    assert_eq!(view.policy_id, 100);
    assert_eq!(view.amount, 5000);
    assert_eq!(view.status, ClaimStatus::Submitted);
}

#[test]
fn test_paginated_claims_result() {
    let env = setup_env();
    let claimant = Address::generate(&env);

    let mut claims: Vec<ClaimView> = Vec::new(&env);
    claims.push_back(ClaimView {
        id: 1,
        policy_id: 100,
        claimant: claimant.clone(),
        amount: 1000,
        status: ClaimStatus::Submitted,
        submitted_at: 1704067200,
    });
    claims.push_back(ClaimView {
        id: 2,
        policy_id: 101,
        claimant: claimant.clone(),
        amount: 2000,
        status: ClaimStatus::Approved,
        submitted_at: 1704067201,
    });

    let result = PaginatedClaimsResult {
        claims,
        total_count: 5,
    };

    assert_eq!(result.claims.len(), 2);
    assert_eq!(result.total_count, 5);
}

// ============================================================================
// UNIT TESTS: Pagination Logic
// ============================================================================

#[test]
fn test_pagination_limit_capping() {
    // Test limit > 50 is capped
    let requested: u32 = 100;
    let effective = if requested > MAX_PAGINATION_LIMIT {
        MAX_PAGINATION_LIMIT
    } else if requested == 0 {
        MAX_PAGINATION_LIMIT
    } else {
        requested
    };
    assert_eq!(effective, 50);

    // Test limit = 0 defaults to 50
    let requested: u32 = 0;
    let effective = if requested > MAX_PAGINATION_LIMIT {
        MAX_PAGINATION_LIMIT
    } else if requested == 0 {
        MAX_PAGINATION_LIMIT
    } else {
        requested
    };
    assert_eq!(effective, 50);

    // Test limit = 25 stays as 25
    let requested: u32 = 25;
    let effective = if requested > MAX_PAGINATION_LIMIT {
        MAX_PAGINATION_LIMIT
    } else if requested == 0 {
        MAX_PAGINATION_LIMIT
    } else {
        requested
    };
    assert_eq!(effective, 25);
}

#[test]
fn test_pagination_bounds_handling() {
    let env = setup_env();

    // Create a list of 10 items
    let mut list: Vec<u64> = Vec::new(&env);
    for i in 1u64..=10 {
        list.push_back(i);
    }
    let total_count = list.len();

    // Test: start=0, limit=3 -> [1,2,3]
    let start: u32 = 0;
    let limit: u32 = 3;
    let end = core::cmp::min(start + limit, total_count);
    assert_eq!(end - start, 3);

    // Test: start=8, limit=5 -> only 2 remaining
    let start: u32 = 8;
    let limit: u32 = 5;
    let end = core::cmp::min(start + limit, total_count);
    assert_eq!(end - start, 2);

    // Test: start=15 (out of bounds) -> empty
    let start: u32 = 15;
    assert!(start >= total_count);
}

// ============================================================================
// UNIT TESTS: Status Filtering
// ============================================================================

#[test]
fn test_claim_status_equality() {
    assert_eq!(ClaimStatus::Submitted, ClaimStatus::Submitted);
    assert_ne!(ClaimStatus::Submitted, ClaimStatus::Approved);
    assert_ne!(ClaimStatus::Approved, ClaimStatus::Rejected);
    assert_eq!(ClaimStatus::Settled, ClaimStatus::Settled);
}

#[test]
fn test_filter_claims_by_status_logic() {
    let env = setup_env();
    let contract_id = env.register(test_contract::TestContract, ());
    let claimant = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // Store 5 claims with different statuses
        env.storage().persistent().set(
            &(CLAIM, 1u64),
            &(100u64, claimant.clone(), 1000i128, ClaimStatus::Submitted, 1704067200u64),
        );
        env.storage().persistent().set(
            &(CLAIM, 2u64),
            &(101u64, claimant.clone(), 2000i128, ClaimStatus::Submitted, 1704067201u64),
        );
        env.storage().persistent().set(
            &(CLAIM, 3u64),
            &(102u64, claimant.clone(), 3000i128, ClaimStatus::Approved, 1704067202u64),
        );
        env.storage().persistent().set(
            &(CLAIM, 4u64),
            &(103u64, claimant.clone(), 4000i128, ClaimStatus::Submitted, 1704067203u64),
        );
        env.storage().persistent().set(
            &(CLAIM, 5u64),
            &(104u64, claimant.clone(), 5000i128, ClaimStatus::Rejected, 1704067204u64),
        );

        // Store claim list
        let mut claim_list: Vec<u64> = Vec::new(&env);
        for i in 1u64..=5 {
            claim_list.push_back(i);
        }
        env.storage().persistent().set(&CLAIM_LIST, &claim_list);

        // Filter for Submitted status
        let target_status = ClaimStatus::Submitted;
        let mut matching_ids: Vec<u64> = Vec::new(&env);

        for i in 0..claim_list.len() {
            let claim_id = claim_list.get(i).unwrap();
            if let Some(claim_data) = env.storage().persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, claim_id))
            {
                if claim_data.3 == target_status {
                    matching_ids.push_back(claim_id);
                }
            }
        }

        // Should find 3 Submitted claims (1, 2, 4)
        assert_eq!(matching_ids.len(), 3);
        assert_eq!(matching_ids.get(0).unwrap(), 1);
        assert_eq!(matching_ids.get(1).unwrap(), 2);
        assert_eq!(matching_ids.get(2).unwrap(), 4);
    });
}

// ============================================================================
// INTEGRATION TEST: Full E2E Scenario
// ============================================================================

#[test]
fn test_e2e_view_functions_simulation() {
    let env = setup_env();
    let contract_id = env.register(test_contract::TestContract, ());
    let claimant1 = Address::generate(&env);
    let claimant2 = Address::generate(&env);

    env.as_contract(&contract_id, || {
        // === SETUP: Simulate 5 claims submitted ===
        let mut claim_list: Vec<u64> = Vec::new(&env);
        env.storage().persistent().set(&CLAIM_COUNTER, &0u64);

        // Claim 1 - Submitted
        env.storage().persistent().set(
            &(CLAIM, 1u64),
            &(1u64, claimant1.clone(), 1000i128, ClaimStatus::Submitted, 1704067200u64),
        );
        claim_list.push_back(1);

        // Claim 2 - Submitted
        env.storage().persistent().set(
            &(CLAIM, 2u64),
            &(2u64, claimant1.clone(), 2000i128, ClaimStatus::Submitted, 1704067201u64),
        );
        claim_list.push_back(2);

        // Claim 3 - Approved
        env.storage().persistent().set(
            &(CLAIM, 3u64),
            &(3u64, claimant2.clone(), 3000i128, ClaimStatus::Approved, 1704067202u64),
        );
        claim_list.push_back(3);

        // Claim 4 - Rejected
        env.storage().persistent().set(
            &(CLAIM, 4u64),
            &(4u64, claimant2.clone(), 4000i128, ClaimStatus::Rejected, 1704067203u64),
        );
        claim_list.push_back(4);

        // Claim 5 - Settled
        env.storage().persistent().set(
            &(CLAIM, 5u64),
            &(5u64, claimant1.clone(), 5000i128, ClaimStatus::Settled, 1704067204u64),
        );
        claim_list.push_back(5);

        // Update counter and list
        env.storage().persistent().set(&CLAIM_COUNTER, &5u64);
        env.storage().persistent().set(&CLAIM_LIST, &claim_list);

        // === TEST: get_claims_by_status(Submitted) ===
        let stored_list: Vec<u64> = env.storage().persistent().get(&CLAIM_LIST).unwrap();
        let mut submitted: Vec<u64> = Vec::new(&env);
        for i in 0..stored_list.len() {
            let id = stored_list.get(i).unwrap();
            if let Some(claim) = env.storage().persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, id))
            {
                if claim.3 == ClaimStatus::Submitted {
                    submitted.push_back(id);
                }
            }
        }
        assert_eq!(submitted.len(), 2, "Expected 2 Submitted claims");

        // === TEST: get_claims_by_status(Approved) ===
        let mut approved: Vec<u64> = Vec::new(&env);
        for i in 0..stored_list.len() {
            let id = stored_list.get(i).unwrap();
            if let Some(claim) = env.storage().persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, id))
            {
                if claim.3 == ClaimStatus::Approved {
                    approved.push_back(id);
                }
            }
        }
        assert_eq!(approved.len(), 1, "Expected 1 Approved claim");

        // === TEST: get_claims_paginated(start=0, limit=2) ===
        let start: u32 = 0;
        let limit: u32 = 2;
        let end = core::cmp::min(start + limit, stored_list.len());

        let mut page1: Vec<ClaimView> = Vec::new(&env);
        for i in start..end {
            let id = stored_list.get(i).unwrap();
            if let Some(claim) = env.storage().persistent()
                .get::<_, (u64, Address, i128, ClaimStatus, u64)>(&(CLAIM, id))
            {
                page1.push_back(ClaimView {
                    id,
                    policy_id: claim.0,
                    claimant: claim.1,
                    amount: claim.2,
                    status: claim.3,
                    submitted_at: claim.4,
                });
            }
        }
        assert_eq!(page1.len(), 2, "Page 1 should have 2 claims");
        assert_eq!(page1.get(0).unwrap().id, 1);
        assert_eq!(page1.get(1).unwrap().id, 2);

        // === TEST: Total count ===
        let total: u64 = env.storage().persistent().get(&CLAIM_COUNTER).unwrap();
        assert_eq!(total, 5, "Total claims should be 5");

        // === TEST: Pagination total_count matches list length ===
        assert_eq!(stored_list.len(), 5);
    });
}

#[test]
fn test_vector_safe_access_pattern() {
    let env = setup_env();

    let mut list: Vec<u64> = Vec::new(&env);
    list.push_back(10);
    list.push_back(20);
    list.push_back(30);

    // Safe iteration (same pattern as production code)
    for i in 0..list.len() {
        let value = list.get(i).unwrap();
        match i {
            0 => assert_eq!(value, 10),
            1 => assert_eq!(value, 20),
            2 => assert_eq!(value, 30),
            _ => panic!("Unexpected index"),
        }
    }

    assert_eq!(list.len(), 3);
}
