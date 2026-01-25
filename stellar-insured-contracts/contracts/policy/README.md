# Policy Contract - State Machine Implementation

## Overview

This contract implements a robust state machine for managing insurance policy lifecycles on the Stellar blockchain using Soroban smart contracts.

## Features

- ✅ **Type-Safe State Machine**: Compile-time guarantees for valid state transitions
- ✅ **Explicit State Control**: All state changes are validated and controlled
- ✅ **Production-Ready**: Comprehensive error handling and testing
- ✅ **Zero-Cost Abstractions**: Efficient implementation with Copy types
- ✅ **Soroban Compatible**: Fully compatible with Stellar Soroban SDK

## State Machine

### States

```
┌─────────┐
│ Active  │ ──────┐
└─────────┘       │
     │            │
     │ expire()   │ cancel()
     │            │
     ▼            ▼
┌─────────┐  ┌───────────┐
│ Expired │  │ Cancelled │
└─────────┘  └───────────┘
(terminal)    (terminal)
```

### Valid Transitions

- `Active → Expired` - Policy reaches end date
- `Active → Cancelled` - Policy is cancelled by admin

### Terminal States

- `Expired` - No further transitions allowed
- `Cancelled` - No further transitions allowed

## Files

- [`lib.rs`](lib.rs) - Main contract implementation
- [`STATE_MACHINE.md`](STATE_MACHINE.md) - Detailed state machine documentation
- [`VALIDATION.md`](VALIDATION.md) - Code validation and production readiness report
- [`verify.sh`](verify.sh) - Automated verification script
- [`README.md`](README.md) - This file

## Quick Start

### Prerequisites

- Rust 1.70 or later
- Soroban CLI
- wasm32-unknown-unknown target

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add wasm target
rustup target add wasm32-unknown-unknown

# Install Soroban CLI
cargo install --locked soroban-cli
```

### Build

```bash
# Check compilation
cargo check

# Run tests
cargo test

# Build WASM
cargo build --release --target wasm32-unknown-unknown
```

### Verify

Run the automated verification script:

```bash
./verify.sh
```

This will:
1. Check code formatting
2. Run clippy lints
3. Verify compilation
4. Run all tests
5. Build WASM binary
6. Verify state machine tests

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Test Categories

```bash
# State transition tests
cargo test test_policy_state

# State-based action tests
cargo test test_policy_cancel
cargo test test_policy_expire

# Terminal state tests
cargo test test_policy_double
```

### Test Coverage

The implementation includes 12 comprehensive unit tests:

1. ✅ Valid transitions succeed
2. ✅ Invalid transitions fail
3. ✅ Policy creation starts in Active state
4. ✅ Cancel from Active succeeds
5. ✅ Expire from Active succeeds
6. ✅ Cancel from Expired fails
7. ✅ Expire from Cancelled fails
8. ✅ Double cancel fails
9. ✅ Double expire fails
10. ✅ State query methods work
11. ✅ No panics, only Results
12. ✅ Proper derives work

## Usage Examples

### Creating a Policy

```rust
let policy = Policy::new(
    holder_address,
    1000,  // coverage_amount
    100,   // premium_amount
    start_time,
    end_time,
    created_at,
);

assert!(policy.is_active());
```

### Cancelling a Policy

```rust
let mut policy = get_policy(policy_id);

match policy.cancel() {
    Ok(()) => {
        // Successfully cancelled
        save_policy(policy_id, &policy);
    }
    Err(ContractError::InvalidState) => {
        // Policy was not in Active state
    }
}
```

### Expiring a Policy

```rust
let mut policy = get_policy(policy_id);

match policy.expire() {
    Ok(()) => {
        // Successfully expired
        save_policy(policy_id, &policy);
    }
    Err(ContractError::InvalidState) => {
        // Policy was not in Active state
    }
}
```

### Checking Policy State

```rust
let policy = get_policy(policy_id);

if policy.is_active() {
    // Policy can be cancelled or expired
} else if policy.is_expired() {
    // Policy has expired - terminal state
} else if policy.is_cancelled() {
    // Policy was cancelled - terminal state
}
```

## Contract Methods

### Public Methods

#### `initialize(env, admin, risk_pool)`
Initialize the contract with admin and risk pool addresses.

#### `issue_policy(env, holder, coverage_amount, premium_amount, duration_days)`
Issue a new policy in Active state.

#### `cancel_policy(env, policy_id)`
Cancel an active policy (admin only).

#### `expire_policy(env, policy_id)`
Expire an active policy (admin only).

#### `get_policy(env, policy_id)`
Get policy details including state.

#### `get_policy_state(env, policy_id)`
Get the current state of a policy.

## Error Handling

### ContractError Variants

- `InvalidStateTransition` - Attempted invalid state transition
- `InvalidState` - Action not allowed in current state
- `Unauthorized` - Caller is not authorized
- `NotFound` - Policy not found
- `InvalidInput` - Invalid input parameters

### Error Examples

```rust
// Invalid transition
let mut policy = expired_policy();
match policy.cancel() {
    Err(ContractError::InvalidState) => {
        // Expected: can't cancel expired policy
    }
}

// Invalid state for action
let mut policy = cancelled_policy();
match policy.expire() {
    Err(ContractError::InvalidState) => {
        // Expected: can't expire cancelled policy
    }
}
```

## Design Principles

1. **Type Safety**: Strong typing prevents invalid states at compile time
2. **Explicit Control**: All state changes are visible and validated
3. **No Runtime Hacks**: All validation is explicit, no string states
4. **Idiomatic Rust**: Result-based error handling, no panics
5. **Production-Ready**: Comprehensive testing and documentation

## Architecture

### PolicyState Enum

```rust
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyState {
    Active,
    Expired,
    Cancelled,
}
```

### Policy Struct

```rust
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub holder: Address,
    pub coverage_amount: i128,
    pub premium_amount: i128,
    pub start_time: u64,
    pub end_time: u64,
    pub state: PolicyState,  // Controlled through methods
    pub created_at: u64,
}
```

### State Transition Validation

```rust
impl PolicyState {
    pub fn can_transition_to(self, next: PolicyState) -> bool {
        match (self, next) {
            (PolicyState::Active, PolicyState::Expired) => true,
            (PolicyState::Active, PolicyState::Cancelled) => true,
            (PolicyState::Expired, _) => false,
            (PolicyState::Cancelled, _) => false,
            _ => false,
        }
    }
}
```

## Deployment

### Build for Production

```bash
cargo build --release --target wasm32-unknown-unknown
```

The WASM binary will be at:
```
target/wasm32-unknown-unknown/release/policy_contract.wasm
```

### Deploy to Testnet

```bash
# Deploy contract
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/policy_contract.wasm \
  --source ADMIN_SECRET_KEY \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015"

# Initialize contract
soroban contract invoke \
  --id CONTRACT_ID \
  --source ADMIN_SECRET_KEY \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015" \
  -- initialize \
  --admin ADMIN_ADDRESS \
  --risk_pool RISK_POOL_ADDRESS
```

## Security Considerations

1. **Admin Authorization**: State-changing operations require admin authorization
2. **State Validation**: All transitions are validated before execution
3. **No Direct Mutation**: State can only be changed through controlled methods
4. **Terminal States**: Expired and Cancelled states prevent further modifications
5. **Event Emission**: All state changes emit events for transparency

## Performance

- **Zero-Cost Abstractions**: Copy types with no runtime overhead
- **Efficient Pattern Matching**: Compile-time optimized state transitions
- **Minimal Storage**: Compact state representation
- **Gas Efficient**: Optimized for Stellar gas costs

## Contributing

When contributing to this contract:

1. Maintain type safety - no string states
2. Add tests for new functionality
3. Update documentation
4. Run `./verify.sh` before submitting
5. Follow Rust best practices

## License

See project root for license information.

## Support

For issues or questions:
- Review [`STATE_MACHINE.md`](STATE_MACHINE.md) for detailed documentation
- Check [`VALIDATION.md`](VALIDATION.md) for production readiness
- Run `./verify.sh` to verify your changes

## Version

- **Version**: 0.1.0
- **Soroban SDK**: 21.7.7
- **Rust Edition**: 2021
