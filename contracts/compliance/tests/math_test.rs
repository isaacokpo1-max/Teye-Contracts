#![cfg(test)]

use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, Address, Env, Symbol, Vec, Map, String
};
use compliance::rules_engine::{RulesEngine, OperationContext, Jurisdiction, Severity};
use compliance::breach_detector::{BreachDetector, AccessEvent, BreachDetectorConfig};

#[contract]
pub struct ComplianceMockContract;

#[contractimpl]
impl ComplianceMockContract {
    /// Wrapper to test RulesEngine::evaluate with boundary values
    pub fn test_rules_eval(
        _env: Env,
        timestamp: u64,
        record_count: u32,
        sensitivity: u32,
        has_consent: bool,
    ) -> bool {
        let mut engine = RulesEngine::new();
        
        // Register a rule that uses the parameters to check for bounds-related issues
        engine.register_rule(compliance::rules_engine::ComplianceRule {
            id: "MATH-001".into(),
            name: "Boundary Test".into(),
            jurisdictions: vec![Jurisdiction::Both],
            severity: Severity::Critical,
            remediation: "N/A".into(),
            evaluate: Box::new(move |ctx| {
                // Perform some math that might overflow if not handled
                // (ctx.timestamp / 3600) % 24 is already tested in HIPAA rules
                let _hour = (ctx.timestamp / 3600) % 24;
                ctx.record_count <= 1_000_000 // Just a dummy check
            }),
        });

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("encrypted".into(), "true".into());

        let ctx = OperationContext {
            actor: "test_actor".into(),
            actor_role: "clinician".into(),
            action: "record.read".into(),
            target: "patient:1".into(),
            timestamp,
            has_consent,
            sensitivity,
            jurisdiction: Jurisdiction::Both,
            record_count,
            purpose: "treatment".into(),
            metadata,
        };

        engine.evaluate(&ctx).allowed
    }

    /// Wrapper to test BreachDetector with boundary values
    pub fn test_breach_detector(
        _env: Env,
        timestamp: u64,
        record_count: u32,
    ) -> u32 {
        let config = BreachDetectorConfig::default();
        let mut detector = BreachDetector::with_config(config);
        
        let event = AccessEvent {
            actor: "test_actor".into(),
            actor_role: "clinician".into(),
            action: "data.export".into(),
            target: "patient:1".into(),
            timestamp,
            record_count,
            sensitivity: 3,
            success: true,
        };

        let alerts = detector.record_event(event);
        alerts.len() as u32
    }
}

#[test]
fn test_timestamp_math_boundaries() {
    let env = Env::default();
    let contract_id = env.register(ComplianceMockContract, ());
    let client = ComplianceMockContractClient::new(&env, &contract_id);

    // Test with u64::MAX timestamp
    let max_ts = u64::MAX;
    let allowed = client.test_rules_eval(&max_ts, &1, &3, &true);
    assert!(allowed);

    // Test with very large record count
    let max_rc = u32::MAX;
    let allowed_large_rc = client.test_rules_eval(&1000, &max_rc, &3, &true);
    // Our dummy rule allows up to 1M, so this should be false but NOT panic
    assert!(!allowed_large_rc);
}

#[test]
fn test_breach_detector_boundaries() {
    let env = Env::default();
    let contract_id = env.register(ComplianceMockContract, ());
    let client = ComplianceMockContractClient::new(&env, &contract_id);

    // Test breach detector with u32::MAX records
    // Should trigger BulkExport alert but not panic
    let alerts_count = client.test_breach_detector(&1000, &u32::MAX);
    assert!(alerts_count > 0);

    // Test with 0 timestamp
    let alerts_zero_ts = client.test_breach_detector(&0, &1);
    assert_eq!(alerts_zero_ts, 0);
}

#[test]
fn test_floating_point_precision_boundaries() {
    let env = Env::default();
    let _contract_id = env.register(ComplianceMockContract, ());
    
    // Test RulesEngine report generation with many operations to check f64 accumulation
    let mut engine = RulesEngine::new();
    let ctx = OperationContext {
        actor: "actor".into(),
        actor_role: "role".into(),
        action: "action".into(),
        target: "target".into(),
        timestamp: 1000,
        has_consent: true,
        sensitivity: 1,
        jurisdiction: Jurisdiction::US,
        record_count: 1,
        purpose: "p".into(),
        metadata: std::collections::HashMap::new(),
    };

    // Evaluate many times
    for _ in 0..1000 {
        engine.evaluate(&ctx);
    }

    let report = engine.generate_report(0, 2000, 2000, Jurisdiction::US);
    assert_eq!(report.total_operations, 1000);
    assert!((report.aggregate_score - 100.0).abs() < 0.0001);
}
