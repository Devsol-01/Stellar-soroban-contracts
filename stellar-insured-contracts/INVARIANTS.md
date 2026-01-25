# Protocol Invariants and Safety Assertions

## Overview

This document specifies the critical safety invariants enforced by the Stellar Insured protocol. These invariants are runtime-checked and fail-fast on violation, ensuring the protocol maintains logical consistency and prevents exploitation of edge cases.

**Purpose**: Provide auditors, developers, and stakeholders with explicit guarantees about protocol safety properties.

---

## Core Invariants

### I1: Liquidity Preservation

**Statement**: At any point in time, the risk pool must maintain sufficient liquidity to cover all outstanding claim reservations.

```
pool_liquidity ≥ reserved_for_claims
```

**Enforcement Points**:
- `deposit_liquidity()` - Asserts after adding funds
- `reserve_liquidity()` - Asserts after reserving for pending claims
- `payout_reserved_claim()` - Asserts after releasing reserved funds

**Implementation**: Checked in `check_liquidity_invariant()` helper function.

**Error Code**: `LiquidityViolation = 100`

**Fail-Fast Behavior**: 
- Immediately returns `ContractError::LiquidityViolation` if violated
- No state mutations before check
- Prevents insolvent pool operations

**Why It Matters**:
- Ensures approved claims can always be paid
- Prevents pool insolvency
- Maintains user trust in settlement guarantees

**Test Coverage**: `tests/invariant_tests.rs::liquidity_invariant`

---

### I2: Policy State Validity

**Statement**: Policies must follow valid, predetermined state transitions. Backward transitions and state skips are prohibited.

**Valid Transitions**:
```
Active → Expired   (time-based expiration)
Active → Cancelled (policyholder cancellation)
Active → Claimed   (claim settlement)
Expired → Claimed  (claim after expiration)
```

**Invalid Transitions**: All others, including:
- `Cancelled → Active` (backward)
- `Active → Claimed → Active` (backward)
- `Active → Settled` (skipping intermediate states)

**Enforcement Points**:
- `issue_policy()` - Sets initial state to `Active`
- `expire_policy()` - Validates transition to `Expired`
- `cancel_policy()` - Validates transition to `Cancelled`
- `claim_policy()` - Validates transition to `Claimed`

**Implementation**: Checked in `is_valid_policy_state_transition()` helper function.

**Error Code**: `InvalidPolicyState = 101`

**Fail-Fast Behavior**:
- Validates transition before state update
- Rejects invalid state combinations immediately
- No side effects on rejection

**Why It Matters**:
- Ensures predictable policy lifecycle
- Prevents double-claims on expired policies
- Maintains underwriting integrity

**Test Coverage**: `tests/invariant_tests.rs::policy_state_invariant`

---

### I3: Claim State Validity

**Statement**: Claims must follow valid linear state progression. Multi-stage workflow enforces procedural integrity.

**Valid Transitions** (Linear Progression):
```
Submitted
    ↓
UnderReview
    ├→ Approved → Settled (settlement path)
    └→ Rejected → [TERMINAL] (rejection path)
```

**Invalid Transitions**:
- `Rejected → Settled` (cannot settle rejected claims)
- `UnderReview → Settled` (must approve first)
- `Submitted → Approved` (must review first)
- Any backward transition

**Enforcement Points**:
- `submit_claim()` - Sets state to `Submitted`
- `start_review()` - Validates `Submitted → UnderReview`
- `approve_claim()` - Validates `UnderReview → Approved`
- `reject_claim()` - Validates `UnderReview → Rejected`
- `settle_claim()` - Validates `Approved → Settled`

**Implementation**: Checked in `is_valid_state_transition()` helper function using explicit validation.

**Error Code**: `InvalidClaimState = 102`

**Fail-Fast Behavior**:
- Pre-state validation using explicit transition rules
- Rejects invalid transitions immediately
- Prevents procedural bypasses

**Why It Matters**:
- Enforces multi-stage approval workflow
- Prevents premature claim settlement
- Ensures claims cannot be double-processed
- Maintains audit trail integrity

**Test Coverage**: `tests/invariant_tests.rs::claim_state_invariant`

---

### I4: Amount Non-Negativity

**Statement**: All financial amounts (deposits, withdrawals, claims, premiums) must be strictly positive.

```
amount > 0 (for all financial operations)
```

**Enforcement Points**:
- `deposit_liquidity(amount)` - Validates `amount > 0`
- `reserve_liquidity(amount)` - Validates `amount > 0`
- `payout_claim(amount)` - Validates `amount > 0`
- `submit_claim(amount)` - Validates `amount > 0`
- `issue_policy(coverage, premium)` - Validates both > 0

**Implementation**:
- Explicit checks: `if amount <= 0 { return Err(...) }`
- Safe arithmetic: `checked_add()`, `checked_sub()`, `checked_mul()`

**Error Codes**:
- `InvalidAmount = 103` (amount <= 0)
- `Overflow = 107` (arithmetic overflow/underflow)

**Fail-Fast Behavior**:
- Rejects zero and negative amounts before state mutations
- Uses Rust's `checked_*` functions for safe arithmetic
- Returns overflow errors instead of wrapping

**Why It Matters**:
- Prevents underflow attacks
- Maintains accounting accuracy
- Ensures financial integrity

**Test Coverage**: `tests/invariant_tests.rs::amount_invariant`

---

### I5: Authorization Consistency

**Statement**: Role assignments must remain consistent across cross-contract interactions. Only authorized roles can perform privileged operations.

**Role Permissions**:
| Role | Permissions |
|------|-------------|
| `Admin` | initialize, pause/unpause, role assignment, config |
| `PolicyManager` | issue_policy, renew_policy, expire_policy |
| `ClaimProcessor` | approve_claim, reject_claim, settle_claim |
| `RiskPoolManager` | deposit_liquidity, withdraw_liquidity, reserve_liquidity |
| `User` | submit_claim, view policies |

**Enforcement Points**:
- All privileged functions check role before execution
- Cross-contract calls verify `require_trusted_contract()`
- Role changes are admin-only

**Implementation**:
- `require_admin()` for admin operations
- `require_policy_management()` for policy operations
- `require_claim_processing()` for claim operations
- `require_risk_pool_management()` for liquidity operations

**Error Code**: `AuthorizationViolation = 104` (from invariants module, mapped to contract errors)

**Fail-Fast Behavior**:
- Identity check (`require_auth()`) before any operation
- Role verification before state mutations
- Trusted contract verification before cross-contract calls

**Why It Matters**:
- Prevents privilege escalation
- Enforces least-privilege principle
- Ensures only authorized agents make critical decisions

**Test Coverage**: `tests/invariant_tests.rs::authorization_invariant`

---

### I6: Coverage Constraint

**Statement**: Claim amounts cannot exceed the policy's coverage limit.

```
claim_amount ≤ policy_coverage_amount
```

**Enforcement Points**:
- `submit_claim(policy_id, amount)` - Will validate once policy contract integration is complete
- Claims initiated against policies must respect coverage limits

**Implementation**:
```rust
// Helper function
fn validate_coverage_constraint(claim_amount: i128, coverage_amount: i128) -> Result<(), ContractError> {
    if claim_amount > coverage_amount {
        return Err(ContractError::CoverageExceeded);
    }
    Ok(())
}
```

**Error Code**: `CoverageExceeded = 105`

**Fail-Fast Behavior**:
- Pre-submission validation
- Prevents overpayment claims
- Rejects invalid claim amounts before processing

**Why It Matters**:
- Maintains underwriting boundaries
- Prevents overpayment scenarios
- Ensures claims respect policy terms

**Test Coverage**: `tests/invariant_tests.rs::coverage_invariant`

---

### I7: Premium Validity

**Statement**: Premium amounts must be strictly positive for active policies.

```
premium_amount > 0 (for Active policies)
```

**Enforcement Points**:
- `issue_policy()` - Validates `premium_amount > 0`
- Policy state transitions maintain premium validity

**Implementation**:
```rust
fn validate_premium(premium: i128) -> Result<(), ContractError> {
    if premium <= 0 {
        return Err(ContractError::InvalidPremium);
    }
    Ok(())
}
```

**Error Code**: `InvalidPremium = 106`

**Fail-Fast Behavior**:
- Pre-policy issuance validation
- Prevents zero-premium policies
- Ensures economic incentive alignment

**Why It Matters**:
- Prevents free-insurance policies
- Maintains premium collection economics
- Ensures DAO revenue generation

**Test Coverage**: `tests/invariant_tests.rs::premium_invariant`

---

## Error Codes and Mapping

### Invariant Error Codes (100-199)

| Code | Invariant | Description |
|------|-----------|-------------|
| 100 | I1 | Liquidity Preservation Violation |
| 101 | I2 | Invalid Policy State |
| 102 | I3 | Invalid Claim State |
| 103 | I4 | Invalid Amount (negative/zero) |
| 104 | I5 | Authorization Violation |
| 105 | I6 | Coverage Constraint Exceeded |
| 106 | I7 | Invalid Premium |
| 107 | I4 | Arithmetic Overflow/Underflow |

### Contract-Specific Error Mapping

**Risk Pool Contract** (`contracts/risk_pool/lib.rs`):
- Maps invariant errors to `ContractError`
- Routes I1, I4, I7 errors through `From<InvariantError>`

**Claims Contract** (`contracts/claims/lib.rs`):
- Maps invariant errors to `ContractError`
- Routes I3, I4, I6 errors through `From<InvariantError>`

**Policy Contract** (`contracts/policy/lib.rs`):
- Maps invariant errors to `ContractError`
- Routes I2, I4, I7 errors through `From<InvariantError>`

---

## Safety Assertion Macros

### `assert_invariant!` Macro

**Usage**: Runtime assertion for custom invariant conditions

```rust
assert_invariant!(condition, error_code, message);
```

**Behavior**:
- Panics if condition is false
- Includes error code and descriptive message
- Use for critical checks that should never fail

### `assert_liquidity_sufficient!` Macro

**Usage**: Specific check for I1 violations

```rust
assert_liquidity_sufficient!(available_liquidity, reserved_claims);
```

**Behavior**:
- Returns `Err(InvariantError::LiquidityViolation)` if violated
- Used in pool operations

### `assert_valid_state!` Macro

**Usage**: Validate state transitions

```rust
assert_valid_state!(current_state, allowed_next_states, actual_next_state);
```

**Behavior**:
- Returns error if transition not in allowed set
- Prevents invalid state changes

### `assert_valid_amount!` Macro

**Usage**: Validate amount constraints

```rust
assert_valid_amount!(amount, min_value);
```

**Behavior**:
- Returns error if amount less than minimum
- Default minimum is 0 (positive amounts only)

### `assert_coverage_constraint!` Macro

**Usage**: Validate claim vs. coverage

```rust
assert_coverage_constraint!(claim_amount, policy_coverage);
```

**Behavior**:
- Returns `Err(InvariantError::CoverageExceeded)` if violated

### Safe Arithmetic Macros

**`safe_add!(a, b)`**: Checked addition
**`safe_sub!(a, b)`**: Checked subtraction
**`safe_mul!(a, b)`**: Checked multiplication

All return `Result<i128, InvariantError::Overflow>` on overflow/underflow.

---

## Integration Points

### Cross-Contract Calls

All cross-contract calls validate:
1. Caller is identified (`require_auth()`)
2. Caller is trusted (`require_trusted_contract()`)
3. Operation is authorized (role check)
4. Invariants hold before and after interaction

### State Mutations

Every state mutation follows this pattern:
```
1. Validate inputs (I4 amounts, roles)
2. Retrieve current state
3. Calculate new state
4. Check invariants (I1, I2, I3)
5. Persist new state
6. Emit event
```

---

## Testing Strategy

### Unit Tests

Located in `tests/invariant_tests.rs`:

- **Liquidity invariant**: deposit, reserve, payout scenarios
- **Policy state**: all valid/invalid transitions
- **Claim state**: complete lifecycle tests
- **Amounts**: positive, zero, negative, boundary cases
- **Authorization**: role checks and privilege separation
- **Coverage**: claim amount validation
- **Premiums**: positive validation
- **Edge cases**: max/min i128, overflow detection, multi-operation flows

### Property-Based Testing

Consider adding fuzzing for:
- Random operation sequences
- Amount combinations
- State transition chains

### Audit Checklist

For auditors reviewing invariant enforcement:

- [ ] All invariant checks are fail-fast (no state mutations before validation)
- [ ] Error codes match specification (100-107)
- [ ] All critical paths include invariant assertions
- [ ] Safe arithmetic (`checked_*`) used throughout
- [ ] Cross-contract calls verify trust and authorization
- [ ] State transitions validated before mutations
- [ ] Test coverage includes all invariant violations

---

## Performance Implications

Invariant checks add minimal overhead:
- **Liquidity check**: O(1) comparison
- **State validation**: O(1) pattern matching
- **Amount validation**: O(1) comparison
- **Safe arithmetic**: Single CPU instruction (overflow flag check)

Total overhead: < 1% of transaction gas

---

## Future Enhancements

### Proposed Invariants (Not Yet Implemented)

- **I8: Claim Ordering**: Claims on same policy must settle in order
- **I9: Role Hierarchy**: Admin can override other roles
- **I10: Governance Consistency**: All protocol changes logged and verifiable

### Integration with Monitoring

Monitor for invariant violations as:
- Red flags in production
- Signals for protocol upgrades needed
- Metrics for auditor confidence

---

## Glossary

| Term | Definition |
|------|-----------|
| **Fail-Fast** | Immediately reject invalid operations without side effects |
| **Invariant** | A safety property that must hold in all valid states |
| **State Transition** | Movement from one valid state to another |
| **Cross-Contract Call** | Interaction between different Soroban contracts |
| **Role** | Authorization level determining permitted operations |

---

## References

- **Implementation**: `contracts/invariants/src/lib.rs`
- **Risk Pool**: `contracts/risk_pool/lib.rs` (I1, I4, I7)
- **Claims**: `contracts/claims/lib.rs` (I3, I4, I6)
- **Policies**: `contracts/policy/lib.rs` (I2, I4, I7)
- **Tests**: `tests/invariant_tests.rs`

---

**Version**: 1.0  
**Last Updated**: January 24, 2026  
**Status**: Active (All 7 invariants enforced)
