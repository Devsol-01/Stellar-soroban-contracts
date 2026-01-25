#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracterror, contracttype, symbol_short, Address, Env, Symbol, Vec, Map,
};

// ============================================================================
// Constants
// ============================================================================

const ADMIN: Symbol = symbol_short!("ADMIN");
const PAUSED: Symbol = symbol_short!("PAUSED");
const CONFIG: Symbol = symbol_short!("CONFIG");
const ORACLE_DATA: Symbol = symbol_short!("ORA_DATA");
const ORACLE_HISTORY: Symbol = symbol_short!("ORA_HIST");
const SUBMISSIONS: Symbol = symbol_short!("SUBS");
const THRESHOLDS: Symbol = symbol_short!("THRESH");

// Default thresholds for oracle validation
const DEFAULT_MIN_SUBMISSIONS: u32 = 3;
const DEFAULT_MAJORITY_THRESHOLD: u32 = 66; // 66% (2 out of 3)
const DEFAULT_OUTLIER_DEVIATION: i128 = 15; // 15% deviation threshold
const DEFAULT_STALENESS_THRESHOLD_SECONDS: u64 = 3600; // 1 hour

// ============================================================================
// Error Handling
// ============================================================================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum OracleError {
    Unauthorized = 1,
    Paused = 2,
    InvalidInput = 3,
    InsufficientSubmissions = 4,
    NotFound = 5,
    AlreadyInitialized = 6,
    NotInitialized = 7,
    StaleData = 8,
    OutlierDetected = 9,
    ConsensusNotReached = 10,
    InvalidThreshold = 11,
    DuplicateSubmission = 12,
}

// ============================================================================
// Type Definitions
// ============================================================================

/// Validation thresholds for oracle consensus
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationThreshold {
    /// Minimum number of oracle submissions required
    pub min_submissions: u32,
    /// Percentage threshold for consensus (0-100)
    pub majority_threshold_percent: u32,
    /// Maximum allowed deviation for outlier detection (in basis points: 1000 = 10%)
    pub outlier_deviation_percent: i128,
    /// Maximum age of oracle data in seconds
    pub staleness_threshold_seconds: u64,
}

impl ValidationThreshold {
    pub fn default() -> Self {
        ValidationThreshold {
            min_submissions: DEFAULT_MIN_SUBMISSIONS,
            majority_threshold_percent: DEFAULT_MAJORITY_THRESHOLD,
            outlier_deviation_percent: DEFAULT_OUTLIER_DEVIATION,
            staleness_threshold_seconds: DEFAULT_STALENESS_THRESHOLD_SECONDS,
        }
    }
}

/// Individual oracle submission
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleSubmission {
    /// Address of the oracle provider
    pub oracle: Address,
    /// Data value submitted
    pub value: i128,
    /// Timestamp of submission
    pub timestamp: u64,
    /// Optional metadata/signature from oracle
    pub source_id: u32,
}

/// Finalized oracle data with consensus proof
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleData {
    /// Unique identifier for this oracle data point
    pub data_id: u64,
    /// The consensus value determined by validators
    pub consensus_value: i128,
    /// Number of submissions supporting this value
    pub submission_count: u32,
    /// Percentage agreement from oracle submissions
    pub consensus_percentage: u32,
    /// Timestamp when consensus was reached
    pub finalized_at: u64,
    /// Submissions that were included in final value
    pub included_submissions: u32,
    /// Submissions that were rejected as outliers
    pub rejected_submissions: u32,
}

/// Configuration for the oracle contract
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub admin: Address,
}

/// Statistics about oracle operations
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleStats {
    pub total_submissions: u64,
    pub total_consensus_reached: u64,
    pub consensus_failures: u64,
    pub average_submissions_per_data: u32,
}

// ============================================================================
// Oracle Contract
// ============================================================================

#[contract]
pub struct OracleContract;

// ============================================================================
// Helper Functions
// ============================================================================

fn require_admin(env: &Env) -> Result<Address, OracleError> {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&ADMIN)
        .ok_or(OracleError::NotInitialized)?;

    env.invoker().require_auth();
    if env.invoker() != admin {
        return Err(OracleError::Unauthorized);
    }

    Ok(admin)
}

fn is_paused(env: &Env) -> bool {
    env.storage()
        .persistent()
        .get(&PAUSED)
        .unwrap_or(false)
}

fn get_thresholds(env: &Env) -> ValidationThreshold {
    env.storage()
        .persistent()
        .get(&THRESHOLDS)
        .unwrap_or_else(ValidationThreshold::default)
}

fn set_thresholds(env: &Env, thresholds: &ValidationThreshold) {
    env.storage()
        .persistent()
        .set(&THRESHOLDS, thresholds);
}

/// Calculate median of values
fn calculate_median(values: &Vec<i128>) -> i128 {
    if values.is_empty() {
        return 0;
    }

    let len = values.len();

    // Simple bubble sort for small datasets (safe in blockchain context)
    let mut sorted = values.clone();
    for i in 0..len {
        for j in 0..(len - i - 1) {
            if sorted.get(j).unwrap() > sorted.get(j + 1).unwrap() {
                let temp = sorted.get(j).unwrap();
                sorted.set(j, sorted.get(j + 1).unwrap());
                sorted.set(j + 1, temp);
            }
        }
    }

    if len % 2 == 1 {
        sorted.get(len / 2).unwrap()
    } else {
        (sorted.get(len / 2 - 1).unwrap() + sorted.get(len / 2).unwrap()) / 2
    }
}

/// Calculate weighted average (simple equal weighting for all submissions)
fn calculate_weighted_average(values: &Vec<i128>) -> i128 {
    if values.is_empty() {
        return 0;
    }

    let mut sum: i128 = 0;
    for i in 0..values.len() {
        sum = sum.saturating_add(values.get(i).unwrap());
    }

    sum / (values.len() as i128)
}

/// Detect outliers using interquartile range (IQR) method
fn detect_outliers(
    values: &Vec<i128>,
    deviation_percent: i128,
) -> Vec<bool> {
    let len = values.len();
    let mut outlier_flags: Vec<bool> = Vec::new();

    if len < 3 {
        // With fewer than 3 values, no outlier detection
        for _ in 0..len {
            outlier_flags.push_back(false);
        }
        return outlier_flags;
    }

    // Calculate median (central value)
    let median = calculate_median(values);

    // Calculate acceptable deviation range
    let deviation_basis = if median > 0 { median } else { 1 };
    let max_deviation =
        (deviation_basis.abs() * deviation_percent) / 100;

    // Mark values outside deviation range as outliers
    for i in 0..len {
        let value = values.get(i).unwrap();
        let diff = if value > median {
            value - median
        } else {
            median - value
        };

        let is_outlier = diff > max_deviation;
        outlier_flags.push_back(is_outlier);
    }

    outlier_flags
}

/// Check if oracle data is stale
fn is_data_stale(timestamp: u64, current_time: u64, staleness_threshold: u64) -> bool {
    if current_time < timestamp {
        return true; // Future timestamp is invalid
    }
    (current_time - timestamp) > staleness_threshold
}

// ============================================================================
// Oracle Contract Implementation
// ============================================================================

#[contractimpl]
impl OracleContract {
    /// Initialize the oracle contract
    pub fn initialize(env: Env, admin: Address) -> Result<(), OracleError> {
        if env.storage().persistent().has(&ADMIN) {
            return Err(OracleError::AlreadyInitialized);
        }

        admin.require_auth();

        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&PAUSED, &false);

        let default_thresholds = ValidationThreshold::default();
        set_thresholds(&env, &default_thresholds);

        Ok(())
    }

    /// Pause or unpause the contract
    pub fn set_paused(env: Env, paused: bool) -> Result<(), OracleError> {
        let _admin = require_admin(&env)?;
        env.storage().persistent().set(&PAUSED, &paused);
        Ok(())
    }

    /// Update validation thresholds
    pub fn set_thresholds(
        env: Env,
        min_submissions: u32,
        majority_threshold_percent: u32,
        outlier_deviation_percent: i128,
        staleness_threshold_seconds: u64,
    ) -> Result<(), OracleError> {
        let _admin = require_admin(&env)?;

        if majority_threshold_percent > 100 || outlier_deviation_percent < 0 {
            return Err(OracleError::InvalidThreshold);
        }

        let thresholds = ValidationThreshold {
            min_submissions,
            majority_threshold_percent,
            outlier_deviation_percent,
            staleness_threshold_seconds,
        };

        set_thresholds(&env, &thresholds);
        Ok(())
    }

    /// Get current validation thresholds
    pub fn get_thresholds(env: Env) -> Result<ValidationThreshold, OracleError> {
        Ok(get_thresholds(&env))
    }

    /// Submit oracle data for a specific data point
    /// Returns true if consensus is reached immediately
    pub fn submit_oracle_data(
        env: Env,
        data_id: u64,
        value: i128,
    ) -> Result<bool, OracleError> {
        if is_paused(&env) {
            return Err(OracleError::Paused);
        }

        env.invoker().require_auth();
        let oracle = env.invoker();
        let current_time = env.ledger().timestamp();

        // Get existing submissions or create new storage
        let mut submissions_key = soroban_sdk::Symbol::new(&env, "SUBS");
        submissions_key = soroban_sdk::Symbol::new(&env, &format!("SUBS_{}", data_id));

        let mut submissions: Vec<OracleSubmission> = env
            .storage()
            .persistent()
            .get(&submissions_key)
            .unwrap_or_else(|| Vec::new(&env));

        // Check for duplicate submission from same oracle
        for i in 0..submissions.len() {
            let sub = submissions.get(i).unwrap();
            if sub.oracle == oracle {
                return Err(OracleError::DuplicateSubmission);
            }
        }

        // Add new submission
        let submission = OracleSubmission {
            oracle: oracle.clone(),
            value,
            timestamp: current_time,
            source_id: 0,
        };

        submissions.push_back(submission);
        env.storage()
            .persistent()
            .set(&submissions_key, &submissions);

        // Try to reach consensus
        self.try_resolve_oracle_data(&env, data_id)
    }

    /// Attempt to resolve oracle data with consensus validation
    pub fn resolve_oracle_data(
        env: Env,
        data_id: u64,
    ) -> Result<OracleData, OracleError> {
        self.try_resolve_oracle_data(&env, data_id)
    }

    /// Internal oracle resolution with validation
    fn try_resolve_oracle_data(
        &self,
        env: &Env,
        data_id: u64,
    ) -> Result<OracleData, OracleError> {
        let thresholds = get_thresholds(env);
        let current_time = env.ledger().timestamp();

        let submissions_key = soroban_sdk::Symbol::new(env, &format!("SUBS_{}", data_id));
        let submissions: Vec<OracleSubmission> = env
            .storage()
            .persistent()
            .get(&submissions_key)
            .ok_or(OracleError::NotFound)?;

        let submission_count = submissions.len() as u32;

        // Check minimum submissions
        if submission_count < thresholds.min_submissions {
            return Err(OracleError::InsufficientSubmissions);
        }

        // Extract values and check for staleness
        let mut values: Vec<i128> = Vec::new(&env);
        for i in 0..submissions.len() {
            let sub = submissions.get(i).unwrap();

            // Check staleness
            if is_data_stale(
                sub.timestamp,
                current_time,
                thresholds.staleness_threshold_seconds,
            ) {
                return Err(OracleError::StaleData);
            }

            values.push_back(sub.value);
        }

        // Detect outliers
        let outlier_flags = detect_outliers(&values, thresholds.outlier_deviation_percent);

        // Filter out outliers and calculate consensus
        let mut valid_values: Vec<i128> = Vec::new(&env);
        let mut rejected_count = 0u32;

        for i in 0..values.len() {
            if !outlier_flags.get(i).unwrap() {
                valid_values.push_back(values.get(i).unwrap());
            } else {
                rejected_count += 1;
            }
        }

        let valid_count = valid_values.len() as u32;

        // Verify consensus threshold is met
        let consensus_percentage =
            (valid_count * 100) / submission_count;

        if consensus_percentage < thresholds.majority_threshold_percent {
            return Err(OracleError::ConsensusNotReached);
        }

        // Calculate final consensus value (using median for robustness)
        let consensus_value = calculate_median(&valid_values);

        // Store the resolved oracle data
        let oracle_data = OracleData {
            data_id,
            consensus_value,
            submission_count,
            consensus_percentage,
            finalized_at: current_time,
            included_submissions: valid_count,
            rejected_submissions: rejected_count,
        };

        // Store the finalized data
        let data_key = soroban_sdk::Symbol::new(env, &format!("DATA_{}", data_id));
        env.storage().persistent().set(&data_key, &oracle_data);

        // Clear submissions after resolution
        env.storage().persistent().remove(&submissions_key);

        Ok(oracle_data)
    }

    /// Get resolved oracle data
    pub fn get_oracle_data(env: Env, data_id: u64) -> Result<OracleData, OracleError> {
        let data_key = soroban_sdk::Symbol::new(&env, &format!("DATA_{}", data_id));
        env.storage()
            .persistent()
            .get(&data_key)
            .ok_or(OracleError::NotFound)
    }

    /// Get pending submissions for a data point
    pub fn get_pending_submissions(
        env: Env,
        data_id: u64,
    ) -> Result<Vec<OracleSubmission>, OracleError> {
        let submissions_key = soroban_sdk::Symbol::new(&env, &format!("SUBS_{}", data_id));
        env.storage()
            .persistent()
            .get(&submissions_key)
            .ok_or(OracleError::NotFound)
    }

    /// Get submission count for a data point
    pub fn get_submission_count(env: Env, data_id: u64) -> Result<u32, OracleError> {
        let submissions_key = soroban_sdk::Symbol::new(&env, &format!("SUBS_{}", data_id));
        let submissions: Vec<OracleSubmission> = env
            .storage()
            .persistent()
            .get(&submissions_key)
            .ok_or(OracleError::NotFound)?;
        Ok(submissions.len() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};

    #[test]
    fn test_oracle_initialization() {
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        let result = contract.initialize(env.clone(), admin.clone());

        assert!(result.is_ok());

        // Test idempotency - second init should fail
        let result2 = contract.initialize(env.clone(), admin);
        assert_eq!(result2, Err(OracleError::AlreadyInitialized));
    }

    #[test]
    fn test_validation_thresholds() {
        let env = Env::default();
        let admin = Address::random(&env);

        OracleContract {}
            .initialize(env.clone(), admin.clone())
            .unwrap();

        // Get default thresholds
        let thresholds = OracleContract {}
            .get_thresholds(env.clone())
            .unwrap();

        assert_eq!(thresholds.min_submissions, DEFAULT_MIN_SUBMISSIONS);
        assert_eq!(
            thresholds.majority_threshold_percent,
            DEFAULT_MAJORITY_THRESHOLD
        );
    }

    #[test]
    fn test_detect_outliers() {
        let env = Env::default();

        let mut values = Vec::new(&env);
        values.push_back(100i128);
        values.push_back(102i128);
        values.push_back(101i128);
        values.push_back(500i128); // Outlier

        let outliers = detect_outliers(&values, 15); // 15% deviation

        assert_eq!(outliers.get(0), false); // 100
        assert_eq!(outliers.get(1), false); // 102
        assert_eq!(outliers.get(2), false); // 101
        assert_eq!(outliers.get(3), true);  // 500 is outlier
    }

    #[test]
    fn test_calculate_median() {
        let env = Env::default();

        let mut values = Vec::new(&env);
        values.push_back(10i128);
        values.push_back(20i128);
        values.push_back(30i128);

        let median = calculate_median(&values);
        assert_eq!(median, 20i128);
    }

    #[test]
    fn test_calculate_weighted_average() {
        let env = Env::default();

        let mut values = Vec::new(&env);
        values.push_back(10i128);
        values.push_back(20i128);
        values.push_back(30i128);

        let avg = calculate_weighted_average(&values);
        assert_eq!(avg, 20i128);
    }

    #[test]
    fn test_is_data_stale() {
        let current = 1000u64;
        let threshold = 3600u64;

        // Fresh data
        assert!(!is_data_stale(900, current, threshold));

        // Stale data
        assert!(is_data_stale(100, current, threshold));

        // Future data (invalid)
        assert!(is_data_stale(1100, current, threshold));
    }
}

// ============================================================================
// Extended Test Suite for Comprehensive Oracle Validation
// ============================================================================

#[cfg(test)]
mod oracle_consensus_tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};

    #[test]
    fn test_oracle_disagreement_scenario() {
        // Scenario: Multiple oracles submit different values for same data point
        let env = Env::default();
        let admin = Address::random(&env);
        let oracle1 = Address::random(&env);
        let oracle2 = Address::random(&env);
        let oracle3 = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        // Simulate three oracles with slightly different values
        let data_id = 1u64;
        
        // Oracle 1 submits value 100
        let result1 = contract.submit_oracle_data(env.clone(), data_id, 100i128);
        assert!(result1.is_ok());

        // Oracle 2 submits value 102 (within 15% deviation)
        let result2 = contract.submit_oracle_data(env.clone(), data_id, 102i128);
        assert!(result2.is_ok());

        // Oracle 3 submits value 101 (within 15% deviation)
        let result3 = contract.submit_oracle_data(env.clone(), data_id, 101i128);
        assert!(result3.is_ok());

        // Consensus should be reached with median of 101
        let resolved = contract.resolve_oracle_data(env.clone(), data_id);
        assert!(resolved.is_ok());
        let oracle_data = resolved.unwrap();
        
        // Median of [100, 102, 101] = 101
        assert_eq!(oracle_data.consensus_value, 101i128);
        assert_eq!(oracle_data.submission_count, 3u32);
        assert_eq!(oracle_data.consensus_percentage, 100u32);
        assert_eq!(oracle_data.included_submissions, 3u32);
    }

    #[test]
    fn test_oracle_outlier_rejection() {
        // Scenario: One oracle submits an outlier, should be detected and rejected
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        let data_id = 2u64;
        
        // Valid submissions
        let _result1 = contract.submit_oracle_data(env.clone(), data_id, 100i128);
        let _result2 = contract.submit_oracle_data(env.clone(), data_id, 101i128);
        let _result3 = contract.submit_oracle_data(env.clone(), data_id, 102i128);
        
        // Outlier submission (far outside 15% deviation range)
        let _result4 = contract.submit_oracle_data(env.clone(), data_id, 500i128);

        let resolved = contract.resolve_oracle_data(env.clone(), data_id);
        assert!(resolved.is_ok());
        let oracle_data = resolved.unwrap();
        
        // Should have 3 valid submissions, 1 rejected
        assert_eq!(oracle_data.submission_count, 4u32);
        assert_eq!(oracle_data.included_submissions, 3u32);
        assert_eq!(oracle_data.rejected_submissions, 1u32);
        assert!(oracle_data.consensus_percentage >= 75u32); // 3 out of 4
    }

    #[test]
    fn test_insufficient_submissions() {
        // Scenario: Fewer submissions than minimum required
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        let data_id = 3u64;
        
        // Submit only one oracle value
        let _result = contract.submit_oracle_data(env.clone(), data_id, 100i128);

        // Try to resolve - should fail with insufficient submissions
        let resolved = contract.resolve_oracle_data(env.clone(), data_id);
        assert_eq!(resolved, Err(OracleError::InsufficientSubmissions));
    }

    #[test]
    fn test_stale_data_rejection() {
        // Scenario: Oracle data is too old and should be rejected
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        // Set a very short staleness threshold
        let _result = contract.set_thresholds(
            env.clone(),
            3u32,
            66u32,
            15i128,
            100u64, // Only 100 seconds before stale
        );

        let data_id = 4u64;

        // Simulate oracle data submission at time 100
        env.ledger().with_timestamp(100);
        let _result = contract.submit_oracle_data(env.clone(), data_id, 100i128);
        let _result = contract.submit_oracle_data(env.clone(), data_id, 101i128);
        let _result = contract.submit_oracle_data(env.clone(), data_id, 102i128);

        // Try to resolve - should succeed at current time
        let resolved1 = contract.resolve_oracle_data(env.clone(), data_id);
        assert!(resolved1.is_ok());

        // Simulate time passing beyond staleness threshold
        env.ledger().with_timestamp(250); // 150 seconds later, exceeds 100 second threshold

        // Create new data point at future timestamp
        let data_id2 = 5u64;
        let _result = contract.submit_oracle_data(env.clone(), data_id2, 100i128);
        let _result = contract.submit_oracle_data(env.clone(), data_id2, 101i128);
        let _result = contract.submit_oracle_data(env.clone(), data_id2, 102i128);

        // This should fail because all submissions are stale
        let resolved2 = contract.resolve_oracle_data(env.clone(), data_id2);
        assert_eq!(resolved2, Err(OracleError::StaleData));
    }

    #[test]
    fn test_duplicate_oracle_submission() {
        // Scenario: Same oracle tries to submit twice for same data point
        let env = Env::default();
        let admin = Address::random(&env);
        let oracle = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        let data_id = 6u64;

        // First submission should succeed
        let result1 = contract.submit_oracle_data(env.clone(), data_id, 100i128);
        assert!(result1.is_ok());

        // Second submission from same oracle should fail
        let result2 = contract.submit_oracle_data(env.clone(), data_id, 102i128);
        assert_eq!(result2, Err(OracleError::DuplicateSubmission));
    }

    #[test]
    fn test_consensus_threshold_enforcement() {
        // Scenario: Test that consensus threshold is properly enforced
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        // Set high majority threshold (80%)
        let _result = contract.set_thresholds(
            env.clone(),
            3u32,
            80u32, // 80% required
            15i128,
            3600u64,
        );

        let data_id = 7u64;

        // Submit 3 values where 2 match and 1 is outlier
        let _result1 = contract.submit_oracle_data(env.clone(), data_id, 100i128);
        let _result2 = contract.submit_oracle_data(env.clone(), data_id, 101i128);
        let _result3 = contract.submit_oracle_data(env.clone(), data_id, 500i128); // Outlier

        // With only 2 valid submissions out of 3 (66%), below 80% threshold
        let resolved = contract.resolve_oracle_data(env.clone(), data_id);
        assert_eq!(resolved, Err(OracleError::ConsensusNotReached));
    }

    #[test]
    fn test_median_calculation() {
        let env = Env::default();

        // Odd number of values
        let mut values_odd = Vec::new(&env);
        values_odd.push_back(10i128);
        values_odd.push_back(30i128);
        values_odd.push_back(20i128);

        let median_odd = calculate_median(&values_odd);
        assert_eq!(median_odd, 20i128);

        // Even number of values
        let mut values_even = Vec::new(&env);
        values_even.push_back(10i128);
        values_even.push_back(20i128);
        values_even.push_back(30i128);
        values_even.push_back(40i128);

        let median_even = calculate_median(&values_even);
        assert_eq!(median_even, 25i128); // (20 + 30) / 2
    }

    #[test]
    fn test_weighted_average_calculation() {
        let env = Env::default();

        let mut values = Vec::new(&env);
        values.push_back(100i128);
        values.push_back(200i128);
        values.push_back(300i128);

        let avg = calculate_weighted_average(&values);
        assert_eq!(avg, 200i128);
    }

    #[test]
    fn test_outlier_detection_edge_cases() {
        let env = Env::default();

        // Single value - no outliers
        let mut values = Vec::new(&env);
        values.push_back(100i128);

        let outliers = detect_outliers(&values, 15);
        assert_eq!(outliers.len(), 1);
        assert_eq!(outliers.get(0), false);

        // Two values - no outliers with current implementation
        let mut values2 = Vec::new(&env);
        values2.push_back(100i128);
        values2.push_back(200i128);

        let outliers2 = detect_outliers(&values2, 15);
        assert_eq!(outliers2.len(), 2);
        assert_eq!(outliers2.get(0), false);
        assert_eq!(outliers2.get(1), false);
    }

    #[test]
    fn test_threshold_validation() {
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        // Try to set invalid threshold (>100%)
        let result = contract.set_thresholds(
            env.clone(),
            3u32,
            150u32, // Invalid: > 100%
            15i128,
            3600u64,
        );
        assert_eq!(result, Err(OracleError::InvalidThreshold));
    }

    #[test]
    fn test_oracle_data_retrieval() {
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        let data_id = 10u64;

        // Submit and resolve
        let _result1 = contract.submit_oracle_data(env.clone(), data_id, 100i128);
        let _result2 = contract.submit_oracle_data(env.clone(), data_id, 101i128);
        let _result3 = contract.submit_oracle_data(env.clone(), data_id, 102i128);

        let resolved = contract.resolve_oracle_data(env.clone(), data_id).unwrap();

        // Retrieve stored oracle data
        let stored = contract.get_oracle_data(env.clone(), data_id).unwrap();
        
        assert_eq!(stored.data_id, data_id);
        assert_eq!(stored.consensus_value, resolved.consensus_value);
        assert_eq!(stored.submission_count, resolved.submission_count);
    }

    #[test]
    fn test_multiple_independent_data_points() {
        // Scenario: Multiple oracle data points with independent consensus
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        // Data point 1
        let _r1_1 = contract.submit_oracle_data(env.clone(), 1u64, 100i128);
        let _r1_2 = contract.submit_oracle_data(env.clone(), 1u64, 101i128);
        let _r1_3 = contract.submit_oracle_data(env.clone(), 1u64, 102i128);

        // Data point 2
        let _r2_1 = contract.submit_oracle_data(env.clone(), 2u64, 200i128);
        let _r2_2 = contract.submit_oracle_data(env.clone(), 2u64, 201i128);
        let _r2_3 = contract.submit_oracle_data(env.clone(), 2u64, 202i128);

        // Resolve both independently
        let resolved1 = contract.resolve_oracle_data(env.clone(), 1u64).unwrap();
        let resolved2 = contract.resolve_oracle_data(env.clone(), 2u64).unwrap();

        assert_eq!(resolved1.consensus_value, 101i128);
        assert_eq!(resolved2.consensus_value, 201i128);
        assert_eq!(resolved1.submission_count, 3u32);
        assert_eq!(resolved2.submission_count, 3u32);
    }

    #[test]
    fn test_pause_functionality() {
        let env = Env::default();
        let admin = Address::random(&env);

        let contract = OracleContract {};
        contract.initialize(env.clone(), admin.clone()).unwrap();

        // Pause the contract
        let _result = contract.set_paused(env.clone(), true);

        // Attempts to submit should fail
        let submit_result = contract.submit_oracle_data(env.clone(), 1u64, 100i128);
        assert_eq!(submit_result, Err(OracleError::Paused));

        // Unpause
        let _result = contract.set_paused(env.clone(), false);

        // Should work again
        let submit_result2 = contract.submit_oracle_data(env.clone(), 1u64, 100i128);
        assert!(submit_result2.is_ok());
    }
}
