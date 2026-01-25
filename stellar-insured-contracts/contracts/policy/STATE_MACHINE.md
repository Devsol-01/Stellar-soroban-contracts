# Policy State Machine Documentation

## Overview

This document describes the explicit state machine implementation for the Policy lifecycle in the Stellar insurance contracts. The state machine enforces compile-time safety and prevents invalid state transitions through strong typing.

## Architecture

### 1. Policy State Enum

The [`PolicyState`](lib.rs:20) enum represents the only valid lifecycle states:

```rust
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyState {
    Active,
    Expired,
    Cancelled,
}
```

**Key Features:**
- Closed enum (no string states)
- Derives: `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`
- Soroban-compatible with `#[contracttype]`

### 2. State Transition Rules

The state machine enforces the following transition rules via [`PolicyState::can_transition_to()`](lib.rs:35):

```
Active → Expired     ✓ Valid
Active → Cancelled   ✓ Valid
Expired → *          ✗ Invalid (terminal state)
Cancelled → *        ✗ Invalid (terminal state)
Self-transitions     ✗ Invalid
```

**Implementation:**
```rust
pub fn can_transition_to(self, next: PolicyState) -> bool {
    match (self, next) {
        (PolicyState::Active, PolicyState::Expired) => true,
        (PolicyState::Active, PolicyState::Cancelled) => true,
        (PolicyState::Expired, _) => false,
        (PolicyState::Cancelled, _) => false,
        _ => false,
    }
}
```

### 3. Policy Struct

The [`Policy`](lib.rs:88) struct encapsulates the policy data with a **private** state field:

```rust
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub holder: Address,
    pub coverage_amount: i128,
    pub premium_amount: i128,
    pub start_time: u64,
    pub end_time: u64,
    state: PolicyState,  // Private - no direct mutation
    pub created_at: u64,
}
```

**Key Design Decisions:**
- `state` field is **private** to prevent external mutation
- All state changes must go through controlled methods
- No public setters for state

### 4. Safe State Transitions

The [`Policy::transition_to()`](lib.rs:130) method validates all state transitions:

```rust
fn transition_to(&mut self, next: PolicyState) -> Result<(), ContractError> {
    if !self.state.can_transition_to(next) {
        return Err(ContractError::InvalidStateTransition);
    }
    self.state = next;
    Ok(())
}
```

**Guarantees:**
- All transitions are validated
- Invalid transitions return `Result::Err`
- No silent failures
- No panics

### 5. Domain Errors

The implementation defines two error enums:

#### PolicyError (Domain-Specific)
```rust
#[contracterror]
pub enum PolicyError {
    InvalidStateTransition = 1,
    AccessDenied = 2,
    NotFound = 3,
    InvalidInput = 4,
    InvalidState = 5,
}
```

#### ContractError (Contract-Wide)
```rust
#[contracterror]
pub enum ContractError {
    // ... other errors
    InvalidStateTransition = 11,
    InvalidState = 7,
}
```

### 6. State-Based Access Control

The implementation provides state-guarded actions:

#### [`Policy::cancel()`](lib.rs:138)
```rust
pub fn cancel(&mut self) -> Result<(), ContractError> {
    if self.state != PolicyState::Active {
        return Err(ContractError::InvalidState);
    }
    self.transition_to(PolicyState::Cancelled)
}
```

#### [`Policy::expire()`](lib.rs:145)
```rust
pub fn expire(&mut self) -> Result<(), ContractError> {
    if self.state != PolicyState::Active {
        return Err(ContractError::InvalidState);
    }
    self.transition_to(PolicyState::Expired)
}
```

**Rules:**
- Each action validates the current state
- Actions internally call `transition_to()`
- No action bypasses state validation

### 7. State Query Methods

Read-only access to state information:

```rust
pub fn state(&self) -> PolicyState
pub fn is_active(&self) -> bool
pub fn is_expired(&self) -> bool
pub fn is_cancelled(&self) -> bool
```

## Contract Integration

### Public Contract Methods

#### [`PolicyContract::cancel_policy()`](lib.rs:357)
```rust
pub fn cancel_policy(env: Env, policy_id: u64) -> Result<(), ContractError>
```
- Requires admin authorization
- Uses state machine to validate transition
- Emits `policy_cancelled` event

#### [`PolicyContract::expire_policy()`](lib.rs:376)
```rust
pub fn expire_policy(env: Env, policy_id: u64) -> Result<(), ContractError>
```
- Requires admin authorization
- Uses state machine to validate transition
- Emits `policy_expired` event

#### [`PolicyContract::get_policy_state()`](lib.rs:343)
```rust
pub fn get_policy_state(env: Env, policy_id: u64) -> Result<PolicyState, ContractError>
```
- Returns the current state of a policy
- Read-only access

## Testing

The implementation includes comprehensive unit tests covering:

### Valid Transitions
- ✓ Active → Expired
- ✓ Active → Cancelled

### Invalid Transitions
- ✗ Expired → Active
- ✗ Expired → Cancelled
- ✗ Cancelled → Active
- ✗ Cancelled → Expired
- ✗ All self-transitions

### State-Based Actions
- ✓ Cancel from Active succeeds
- ✓ Expire from Active succeeds
- ✗ Cancel from Expired fails
- ✗ Expire from Cancelled fails
- ✗ Double cancel fails
- ✗ Double expire fails

### Safety Guarantees
- ✓ No panics, only Result-based errors
- ✓ All state checks work correctly
- ✓ Proper derives (Debug, Clone, Copy, PartialEq, Eq)

## Usage Examples

### Creating a Policy
```rust
let policy = Policy::new(
    holder_address,
    coverage_amount,
    premium_amount,
    start_time,
    end_time,
    created_at,
);
// Policy starts in Active state
assert!(policy.is_active());
```

### Cancelling a Policy
```rust
let mut policy = get_policy(policy_id);
match policy.cancel() {
    Ok(()) => {
        // Successfully cancelled
        assert!(policy.is_cancelled());
    }
    Err(ContractError::InvalidState) => {
        // Policy was not in Active state
    }
    Err(e) => {
        // Other error
    }
}
```

### Expiring a Policy
```rust
let mut policy = get_policy(policy_id);
match policy.expire() {
    Ok(()) => {
        // Successfully expired
        assert!(policy.is_expired());
    }
    Err(ContractError::InvalidState) => {
        // Policy was not in Active state
    }
    Err(e) => {
        // Other error
    }
}
```

## Design Principles

### 1. Compile-Time Safety
- Strong typing prevents invalid states
- Closed enum ensures only valid states exist
- Private state field prevents direct mutation

### 2. No Runtime Hacks
- All validation is explicit
- No string-based states
- No reflection or dynamic dispatch

### 3. Explicit Transitions
- All transitions are validated
- Invalid transitions return errors
- No silent failures

### 4. Idiomatic Rust
- Result-based error handling
- No panics in production code
- Proper use of ownership and borrowing

### 5. Production-Ready
- Comprehensive test coverage
- Clear error messages
- Debuggable state transitions

## Benefits

1. **Type Safety**: Impossible to create invalid states at compile time
2. **Explicit Control**: All state changes are visible and controlled
3. **Testability**: Easy to test all transitions and edge cases
4. **Maintainability**: Clear state machine logic in one place
5. **Debuggability**: Descriptive errors for invalid transitions
6. **Performance**: Zero-cost abstractions with Copy types

## Future Enhancements

Potential improvements to consider:

1. **State History**: Track state transition history
2. **Transition Hooks**: Add callbacks for state changes
3. **Conditional Transitions**: Add time-based or condition-based transitions
4. **State Metrics**: Track time spent in each state
5. **Audit Trail**: Log all state transitions with timestamps

## Conclusion

This state machine implementation provides a robust, type-safe foundation for managing policy lifecycles. It enforces business rules at the type level, prevents invalid transitions, and provides clear error handling—all while maintaining idiomatic Rust code and production-ready quality.
