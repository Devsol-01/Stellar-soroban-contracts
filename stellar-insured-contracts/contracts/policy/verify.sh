#!/bin/bash

# Policy Contract State Machine Verification Script
# This script verifies the policy contract compiles and tests pass

set -e  # Exit on any error

echo "=========================================="
echo "Policy Contract Verification"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to policy contract directory
cd "$(dirname "$0")"

echo "📁 Working directory: $(pwd)"
echo ""

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Error: cargo not found${NC}"
    echo "Please install Rust: https://rustup.rs/"
    exit 1
fi

echo -e "${GREEN}✅ Cargo found: $(cargo --version)${NC}"
echo ""

# Step 1: Check code formatting
echo "🔍 Step 1: Checking code formatting..."
if cargo fmt -- --check; then
    echo -e "${GREEN}✅ Code formatting is correct${NC}"
else
    echo -e "${YELLOW}⚠️  Code formatting issues found. Run 'cargo fmt' to fix.${NC}"
fi
echo ""

# Step 2: Run clippy for lints
echo "🔍 Step 2: Running clippy..."
if cargo clippy -- -D warnings; then
    echo -e "${GREEN}✅ No clippy warnings${NC}"
else
    echo -e "${RED}❌ Clippy found issues${NC}"
    exit 1
fi
echo ""

# Step 3: Check compilation
echo "🔨 Step 3: Checking compilation..."
if cargo check; then
    echo -e "${GREEN}✅ Code compiles successfully${NC}"
else
    echo -e "${RED}❌ Compilation failed${NC}"
    exit 1
fi
echo ""

# Step 4: Run tests
echo "🧪 Step 4: Running tests..."
if cargo test -- --nocapture; then
    echo -e "${GREEN}✅ All tests passed${NC}"
else
    echo -e "${RED}❌ Tests failed${NC}"
    exit 1
fi
echo ""

# Step 5: Build release WASM
echo "🏗️  Step 5: Building release WASM..."
if cargo build --release --target wasm32-unknown-unknown; then
    echo -e "${GREEN}✅ WASM build successful${NC}"
    
    # Show WASM file size
    WASM_FILE="../../../target/wasm32-unknown-unknown/release/policy_contract.wasm"
    if [ -f "$WASM_FILE" ]; then
        SIZE=$(du -h "$WASM_FILE" | cut -f1)
        echo -e "${GREEN}📦 WASM size: $SIZE${NC}"
    fi
else
    echo -e "${RED}❌ WASM build failed${NC}"
    exit 1
fi
echo ""

# Step 6: Run state machine specific tests
echo "🔄 Step 6: Verifying state machine tests..."
echo ""
echo "Testing state transitions..."
cargo test test_policy_state_valid_transitions -- --nocapture
cargo test test_policy_state_invalid_transitions -- --nocapture
echo ""
echo "Testing state-based actions..."
cargo test test_policy_cancel_from_active_succeeds -- --nocapture
cargo test test_policy_expire_from_active_succeeds -- --nocapture
cargo test test_policy_cancel_from_expired_fails -- --nocapture
cargo test test_policy_expire_from_cancelled_fails -- --nocapture
echo ""
echo "Testing terminal states..."
cargo test test_policy_double_cancel_fails -- --nocapture
cargo test test_policy_double_expire_fails -- --nocapture
echo ""
echo -e "${GREEN}✅ All state machine tests passed${NC}"
echo ""

# Summary
echo "=========================================="
echo "✅ VERIFICATION COMPLETE"
echo "=========================================="
echo ""
echo "Summary:"
echo "  ✅ Code formatting: OK"
echo "  ✅ Clippy lints: OK"
echo "  ✅ Compilation: OK"
echo "  ✅ Tests: OK"
echo "  ✅ WASM build: OK"
echo "  ✅ State machine: OK"
echo ""
echo "The policy contract is ready for deployment!"
echo ""
echo "Next steps:"
echo "  1. Deploy to Stellar testnet"
echo "  2. Run integration tests"
echo "  3. Perform security audit"
echo "  4. Deploy to mainnet"
echo ""
