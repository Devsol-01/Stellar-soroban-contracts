// Centralized error definitions
use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SecurityError {
    Reentrancy = 100,
    InvalidStateTransition = 101,
    Unauthorized = 102,  
}