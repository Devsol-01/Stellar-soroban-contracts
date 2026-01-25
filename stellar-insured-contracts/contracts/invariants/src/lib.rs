//! Protocol Invariants and Safety Assertions
//!
//! This module defines critical safety invariants for the Stellar Insured protocol
//! and provides macros for runtime assertion checks that fail fast on violations.
//!
//! ## Core Invariants
//! - I1: Liquidity Preservation: `pool_liquidity >= outstanding_claims_reserved`
//! - I2: Policy State Validity: Policies must be in valid state transitions
//! - I3: Claim State Validity: Claims must be in valid state transitions
//! - I4: Amount Non-Negativity: All financial amounts must be non-negative
//! - I5: Authorization Consistency: Role assignments must be consistent across contracts
//! - I6: Coverage Constraint: `claim_amount <= policy_coverage_amount`
//! - I7: Premium Validity: `premium_amount > 0` for active policies

#![no_std]

use soroban_sdk::contracterror;

/// Invariant violation error codes
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum InvariantError {
    /// I1: Pool liquidity insufficient for outstanding claims
    LiquidityViolation = 100,
    /// I2: Invalid policy state transition
    InvalidPolicyState = 101,
    /// I3: Invalid claim state transition
    InvalidClaimState = 102,
    /// I4: Negative or zero amount where positive required
    InvalidAmount = 103,
    /// I5: Authorization role mismatch
    AuthorizationViolation = 104,
    /// I6: Claim amount exceeds policy coverage
    CoverageExceeded = 105,
    /// I7: Premium invalid for policy type
    InvalidPremium = 106,
    /// Amount overflow during calculation
    Overflow = 107,
    /// Insufficient available liquidity for operation
    InsufficientLiquidity = 108,
    /// Policy does not exist or is not accessible
    PolicyNotFound = 109,
    /// Claim does not exist or is not accessible
    ClaimNotFound = 110,
}

/// Protocol invariant definitions
pub struct ProtocolInvariants;

impl ProtocolInvariants {
    /// I1: Liquidity Preservation Invariant
    ///
    /// The pool must maintain sufficient liquidity to cover all outstanding claim reservations.
    /// At any point: `total_liquidity >= reserved_for_claims`
    ///
    /// This ensures the pool can always settle approved claims without running insolvent.
    pub const LIQUIDITY_PRESERVATION: &'static str = "I1:Liquidity≥Claims";

    /// I2: Policy State Validity Invariant
    ///
    /// Policies must follow valid state transitions:
    /// - Active → Expired (time-based)
    /// - Active → Cancelled (holder-initiated)
    /// - Active → Claimed (claim settlement)
    /// - Expired → Claimed (if claim pending)
    ///
    /// Invalid transitions are rejected immediately.
    pub const POLICY_STATE_VALIDITY: &'static str = "I2:ValidPolicyStates";

    /// I3: Claim State Validity Invariant
    ///
    /// Claims must follow valid state transitions:
    /// - Submitted → UnderReview (admin-initiated)
    /// - UnderReview → Approved/Rejected (admin-decided)
    /// - Approved → Settled (admin-executed)
    /// - Rejected → terminal (no settlement)
    ///
    /// Direct jumps are prevented; claims cannot move backward.
    pub const CLAIM_STATE_VALIDITY: &'static str = "I3:ValidClaimStates";

    /// I4: Amount Non-Negativity Invariant
    ///
    /// All financial amounts (deposits, withdrawals, claims, premiums) must be positive.
    /// Zero amounts are rejected unless explicitly permitted (e.g., zero-premium policies).
    ///
    /// Prevents underflow attacks and maintains accurate accounting.
    pub const AMOUNT_NON_NEGATIVITY: &'static str = "I4:Amounts≥0";

    /// I5: Authorization Consistency Invariant
    ///
    /// Role assignments must remain consistent across cross-contract interactions.
    /// Only authorized roles can perform privileged actions:
    /// - Admin: contract initialization, role assignment
    /// - ClaimProcessor: claim approval/rejection
    /// - RiskPoolManager: liquidity operations
    /// - PolicyManager: policy issuance
    ///
    /// Prevents privilege escalation through role inconsistency.
    pub const AUTHORIZATION_CONSISTENCY: &'static str = "I5:AuthConsistent";

    /// I6: Coverage Constraint Invariant
    ///
    /// Claim amounts must not exceed the policy's coverage limit.
    /// `claim_amount <= policy_coverage_amount`
    ///
    /// Prevents overpayment and maintains underwriting integrity.
    pub const COVERAGE_CONSTRAINT: &'static str = "I6:Claim≤Coverage";

    /// I7: Premium Validity Invariant
    ///
    /// Premium amounts must be positive for policy activation.
    /// `premium_amount > 0` for policies in Active status.
    ///
    /// Zero premiums are only valid in test/special scenarios.
    pub const PREMIUM_VALIDITY: &'static str = "I7:Premium>0";
}

/// Macro for asserting invariant conditions in critical paths
/// 
/// Usage: `assert_invariant!(condition, error_code, message)`
/// 
/// Fails immediately (fail-fast) on violation with error code
#[macro_export]
macro_rules! assert_invariant {
    ($condition:expr, $error:expr, $message:expr) => {{
        if !$condition {
            panic!("Invariant violation: {} - {}", $message, stringify!($error));
        }
    }};
}

/// Macro for asserting liquidity is sufficient for outstanding claims
/// 
/// Usage: `assert_liquidity_sufficient!(available_liquidity, reserved_claims)`
#[macro_export]
macro_rules! assert_liquidity_sufficient {
    ($available:expr, $reserved:expr) => {{
        if $available < $reserved {
            return Err($crate::InvariantError::LiquidityViolation);
        }
    }};
}

/// Macro for asserting valid state transitions
/// 
/// Usage: `assert_valid_state!(current_state, allowed_next_states, actual_next_state)`
#[macro_export]
macro_rules! assert_valid_state {
    ($current:expr, $allowed:expr, $actual:expr) => {{
        if !$allowed.contains(&$actual) {
            return Err($crate::InvariantError::InvalidClaimState);
        }
    }};
}

/// Macro for asserting amount constraints
/// 
/// Usage: `assert_valid_amount!(amount, min_value)`
#[macro_export]
macro_rules! assert_valid_amount {
    ($amount:expr, $min:expr) => {{
        if $amount < $min {
            return Err($crate::InvariantError::InvalidAmount);
        }
    }};
}

/// Macro for asserting coverage constraints
/// 
/// Usage: `assert_coverage_constraint!(claim_amount, policy_coverage)`
#[macro_export]
macro_rules! assert_coverage_constraint {
    ($claim:expr, $coverage:expr) => {{
        if $claim > $coverage {
            return Err($crate::InvariantError::CoverageExceeded);
        }
    }};
}

/// Macro for safe arithmetic with overflow checks
/// 
/// Usage: `safe_add!(a, b)` returns Result<i128, InvariantError>
#[macro_export]
macro_rules! safe_add {
    ($a:expr, $b:expr) => {{
        ($a).checked_add($b).ok_or($crate::InvariantError::Overflow)
    }};
}

/// Macro for safe subtraction with underflow checks
/// 
/// Usage: `safe_sub!(a, b)` returns Result<i128, InvariantError>
#[macro_export]
macro_rules! safe_sub {
    ($a:expr, $b:expr) => {{
        ($a).checked_sub($b).ok_or($crate::InvariantError::Overflow)
    }};
}

/// Macro for safe multiplication with overflow checks
/// 
/// Usage: `safe_mul!(a, b)` returns Result<i128, InvariantError>
#[macro_export]
macro_rules! safe_mul {
    ($a:expr, $b:expr) => {{
        ($a).checked_mul($b).ok_or($crate::InvariantError::Overflow)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_error_codes() {
        assert_eq!(InvariantError::LiquidityViolation as u32, 100);
        assert_eq!(InvariantError::InvalidPolicyState as u32, 101);
        assert_eq!(InvariantError::InvalidClaimState as u32, 102);
        assert_eq!(InvariantError::InvalidAmount as u32, 103);
        assert_eq!(InvariantError::AuthorizationViolation as u32, 104);
        assert_eq!(InvariantError::CoverageExceeded as u32, 105);
        assert_eq!(InvariantError::InvalidPremium as u32, 106);
    }

    #[test]
    fn test_invariant_constants() {
        assert_eq!(
            ProtocolInvariants::LIQUIDITY_PRESERVATION,
            "I1:Liquidity≥Claims"
        );
        assert_eq!(
            ProtocolInvariants::POLICY_STATE_VALIDITY,
            "I2:ValidPolicyStates"
        );
        assert_eq!(
            ProtocolInvariants::CLAIM_STATE_VALIDITY,
            "I3:ValidClaimStates"
        );
    }
}
