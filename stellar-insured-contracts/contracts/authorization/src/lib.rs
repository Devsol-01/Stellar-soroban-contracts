//! Authorization Module for Stellar Insured Protocol
//!
//! This module provides a unified, role-based access control (RBAC) system
//! for all contracts in the Stellar Insured ecosystem.
//!
//! ## Features
//! - Standardized role definitions across all contracts
//! - Explicit permission checking for privileged operations
//! - Cross-contract call validation
//! - Least-privilege enforcement
//! - Audit trail support

#![no_std]

use soroban_sdk::{contracttype, Address, Env};

/// Protocol-wide role definitions
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Role {
    /// Root administrator with full protocol access
    Admin,
    /// Governance contract or approved governance participant
    Governance,
    /// Risk pool manager authorized to handle liquidity operations
    RiskPoolManager,
    /// Policy manager authorized to create and manage policies
    PolicyManager,
    /// Claim processor authorized to approve/reject claims
    ClaimProcessor,
    /// Regular user (policyholder, liquidity provider, etc.)
    User,
}

/// Storage keys for role assignments
#[contracttype]
#[derive(Clone)]
pub enum RoleKey {
    /// Maps Address -> Role
    UserRole(Address),
    /// Contract-level admin address
    ContractAdmin,
    /// Trusted contract addresses for cross-contract calls
    TrustedContract(Address),
}

/// Authorization errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    Unauthorized,
    InvalidRole,
    RoleNotFound,
    NotTrustedContract,
}

/// Permission matrix: defines what each role can do
impl Role {
    /// Check if this role has permission for administrative actions
    pub fn can_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Check if this role can manage policies
    pub fn can_manage_policies(&self) -> bool {
        matches!(self, Role::Admin | Role::PolicyManager)
    }

    /// Check if this role can process claims
    pub fn can_process_claims(&self) -> bool {
        matches!(self, Role::Admin | Role::ClaimProcessor)
    }

    /// Check if this role can manage risk pool
    pub fn can_manage_risk_pool(&self) -> bool {
        matches!(self, Role::Admin | Role::RiskPoolManager)
    }

    /// Check if this role can participate in governance
    pub fn can_govern(&self) -> bool {
        matches!(self, Role::Admin | Role::Governance)
    }

    /// Check if this role can submit claims
    pub fn can_submit_claim(&self) -> bool {
        !matches!(self, Role::ClaimProcessor) // Claim processors cannot submit their own claims
    }
}

/// Core authorization functions

/// Initialize contract admin (call once during contract initialization)
pub fn initialize_admin(env: &Env, admin: Address) {
    env.storage()
        .persistent()
        .set(&RoleKey::ContractAdmin, &admin);
    env.storage()
        .persistent()
        .set(&RoleKey::UserRole(admin.clone()), &Role::Admin);
}

/// Get the contract admin address
pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&RoleKey::ContractAdmin)
}

/// Grant a role to an address (admin only)
pub fn grant_role(env: &Env, caller: &Address, target: &Address, role: Role) -> Result<(), AuthError> {
    // Verify caller is admin
    require_role(env, caller, Role::Admin)?;
    
    // Grant the role
    env.storage()
        .persistent()
        .set(&RoleKey::UserRole(target.clone()), &role);
    
    Ok(())
}

/// Revoke a role from an address (admin only)
pub fn revoke_role(env: &Env, caller: &Address, target: &Address) -> Result<(), AuthError> {
    // Verify caller is admin
    require_role(env, caller, Role::Admin)?;
    
    // Prevent admin from revoking their own role (safeguard)
    if caller == target {
        return Err(AuthError::Unauthorized);
    }
    
    // Revoke by setting to User role (lowest privilege)
    env.storage()
        .persistent()
        .set(&RoleKey::UserRole(target.clone()), &Role::User);
    
    Ok(())
}

/// Get the role of an address
pub fn get_role(env: &Env, address: &Address) -> Role {
    env.storage()
        .persistent()
        .get(&RoleKey::UserRole(address.clone()))
        .unwrap_or(Role::User) // Default to User if no role assigned
}

/// Check if an address has a specific role
pub fn has_role(env: &Env, address: &Address, required_role: Role) -> bool {
    let user_role = get_role(env, address);
    user_role == required_role
}

/// Require that the caller has a specific role (throws error if not)
pub fn require_role(env: &Env, address: &Address, required_role: Role) -> Result<(), AuthError> {
    let user_role = get_role(env, address);
    
    if user_role == required_role {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Require admin privileges
pub fn require_admin(env: &Env, address: &Address) -> Result<(), AuthError> {
    require_role(env, address, Role::Admin)
}

/// Check if an address has any of the specified roles
pub fn has_any_role(env: &Env, address: &Address, roles: &[Role]) -> bool {
    let user_role = get_role(env, address);
    roles.contains(&user_role)
}

/// Require that the caller has one of the specified roles
pub fn require_any_role(env: &Env, address: &Address, roles: &[Role]) -> Result<(), AuthError> {
    if has_any_role(env, address, roles) {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Permission-based authorization (more granular than role-based)

/// Require permission to manage policies
pub fn require_policy_management(env: &Env, address: &Address) -> Result<(), AuthError> {
    let role = get_role(env, address);
    if role.can_manage_policies() {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Require permission to process claims
pub fn require_claim_processing(env: &Env, address: &Address) -> Result<(), AuthError> {
    let role = get_role(env, address);
    if role.can_process_claims() {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Require permission to manage risk pool
pub fn require_risk_pool_management(env: &Env, address: &Address) -> Result<(), AuthError> {
    let role = get_role(env, address);
    if role.can_manage_risk_pool() {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Require permission to participate in governance
pub fn require_governance_permission(env: &Env, address: &Address) -> Result<(), AuthError> {
    let role = get_role(env, address);
    if role.can_govern() {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Cross-contract call validation

/// Register a trusted contract address (admin only)
pub fn register_trusted_contract(env: &Env, caller: &Address, contract_address: &Address) -> Result<(), AuthError> {
    require_admin(env, caller)?;
    
    env.storage()
        .persistent()
        .set(&RoleKey::TrustedContract(contract_address.clone()), &true);
    
    Ok(())
}

/// Unregister a trusted contract address (admin only)
pub fn unregister_trusted_contract(env: &Env, caller: &Address, contract_address: &Address) -> Result<(), AuthError> {
    require_admin(env, caller)?;
    
    env.storage()
        .persistent()
        .remove(&RoleKey::TrustedContract(contract_address.clone()));
    
    Ok(())
}

/// Check if a contract address is trusted
pub fn is_trusted_contract(env: &Env, contract_address: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&RoleKey::TrustedContract(contract_address.clone()))
        .unwrap_or(false)
}

/// Require that the contract making the call is trusted
pub fn require_trusted_contract(env: &Env, contract_address: &Address) -> Result<(), AuthError> {
    if is_trusted_contract(env, contract_address) {
        Ok(())
    } else {
        Err(AuthError::NotTrustedContract)
    }
}

/// Utility: Combine identity verification with role check
/// This is the recommended pattern for most privileged operations
pub fn verify_and_require_role(env: &Env, caller: &Address, required_role: Role) -> Result<(), AuthError> {
    // First, verify the caller's identity (Soroban's built-in auth)
    caller.require_auth();
    
    // Then, check if they have the required role
    require_role(env, caller, required_role)
}

/// Utility: Verify identity and check permission
pub fn verify_and_check_permission<F>(env: &Env, caller: &Address, permission_check: F) -> Result<(), AuthError>
where
    F: Fn(&Role) -> bool,
{
    caller.require_auth();
    
    let role = get_role(env, caller);
    if permission_check(&role) {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}
