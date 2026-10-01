#ed(test)
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils:{Address as _, Events as _, Ledger as _},
        Address, BytesN, Env, IntoVal,
    };

    // --------------------------------------------------------------------
    // Baseline behavior (preserved from the original suite)
    // ---------------------------------------------------------------------

    #[test]
    fn test_get_yield_tier_returns_default_when_unset() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let state = client.get_yield_tier();
        assert_eq(state, YieldTierState::Unset);
    }

    #[test]
    fn test_get_yield_tier_returns_stored_state() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_yield_tier(&YieldTierState::Tier2);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier2);

        client.set_yield_tier(&YieldTierState::Tier3);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier3);
    }

    /// --------------------------------------------------------------------------
    /// init invariants
    /// --------------------------------------------------------------------------

    #[test]
    fn test_init_rejects_duplicate_call() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let other = Address::generate(&env);

        client.init(&admin);
        let result = client.try_init(&other);
        assert!(result.is_err());

        // Invariant: the original admin is preserved.
        assert_eq(client.get_admin(), admin);
    }

    #[test]
    fn test_init_repeated_calls_are_deterministic() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);
        for _ in 0.10 {
            assert!(client.try_init(&admin).is_err());
        }
        assert_eq(client.get_admin(), admin);
    }

    #[test]
    fn test_get_admin_before_init_returns_not_initialized() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        assert!(client.try_get_admin().is_error());
    }

    /// --------------------------------------------------------------------------
    /// upgrade authorization and state transitions
    /// --------------------------------------------------------------------------

    #[test]
    fn test_upgrade_admin_allowed() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        let new_wasm = BytesN::from_array(&env, &[1; 32]);
        client.upgrade(&new_wasm);

        assert_eq(
            env.events().all().last().unwrap(),
            (
                contract_id,
                (symbol_short!("upgrade"),).into_val(&env),
                (new_wasm.clone(),).into_val(&env),
            )
        );
    }

    #[test]
    fn test_upgrade_non_admin_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // non-admin will fail auth because env.mock_all_auths is not set
        let new_wasm = BytesN::from_array(&env, &[1; 32]);
        let result = client.try_upgrade(&new_wasm);
        assert!(result.is_err());
    }

    #[test]
    fn test_upgrade_before_init_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let new_wasm = BytesN::from_array(&env, &[1; 32]);
        assert!(client.try_upgrade(&new_wasm).is_err());
    }

    #[test]
    fn test_upgrade_repeated_calls_are_deterministic() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        let new_wasm = BytesN::from_array(&env, &[2; 32]);
        for _ in 0.3 {
            client.upgrade(&new_wasm);
        }
        assert_eq(
            env.events().all().last().unwrap(),
            (
                contract_id,
                (symbol_short!("upgrade"),).into_val(&env),
                (new_wasm.clone(),).into_val(&env),
            )
        );
    }

    /// --------------------------------------------------------------------------
    /// set_yield_tier authorization and state transitions
    /// --------------------------------------------------------------------------

    #[test]
    fn test_set_yield_tier_admin_authorized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_yield_tier(&YieldTierState::Tier1);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier1);

        assert_eq(
            env.events().all().last().unwrap(),
            (
                contract_id,
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier1,).into_val(&env),
            )
        );
    }

    #[test]
    fn test_set_yield_tier_non_admin_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // non-admin will fail auth without mock_all_auths
        let result = client.try_set_yield_tier(&YieldTierState::Tier1);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_yield_tier_rejected_call_preserves_state() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // Establish a known good state.
        client.set_yield_tier(&YieldTierState::Tier2);

        // Rejected call without auth.
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init(&admin);
        client.set_yield_tier(&YieldTierState::Tier2);
        assert!(client.try_set_yield_tier(&YieldTierState::Tier3).is_err());
        assert_eq(client.get_yield_tier(), YieldTierState::Tier2);
    }

    #[test]
    fn test_set_yield_tier_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_yield_tier(&YieldTierState::Tier3);
        assert_eq(
            env.events().all().last().unwrap(),
            (
                contract_id,
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier3,).into_val(&env),
            )
        );
    }

    // --------------------------------------------------------------------
    // Deterministic failure recovery tests
    //
    // Invariants under test:
    //   1. A failed write must not mutate persisted state.
    //   2. A failed write must not emit a success event.
    //   3. Retrying after a failure must be deterministic and idempotent
    //      with respect to the final state and the emitted event sequence.
    //   4. Concurrent/repeated calls must not produce an inconsistent result.
    // --------------------------------------------------------------------

    // Failure before init: any admin-guarded write must be rejected and must
    // leave the contract in the Unset state with no events emitted.
    #[test]
    fn test_failure_before_init_leaves_state_unset() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        // No init has run, so the admin guard must reject the write.
        let result = client.try_set_yield_tier(&YieldTierState::Tier1);
        assert!(result.is_error());

        // State must remain Unset and no events must have been emitted.
        assert_eq(client.get_yield_tier(), YieldTierState::Unset);
        assert_eq(env.events().all().len(), 0);
    }

    // Failure before init on upgrade: same invariants as above.
    #[test]
    fn test_failure_upgrade_before_init_leaves_state_unset() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let new_wasm = BytesN::from_array(&env, &[2; 32]);
        let result = client.try_upgrade(&new_wasm);
        assert!(result.is_error());

        assert_eq(client.get_yield_tier(), YieldTierState::Unset);
        assert_eq(env.events().all().len(), 0);
    }

    // Retry after a failed write: the second attempt must succeed deterministically
    // and produce exactly one tier_set event with the final value.
    #[test]
    fn test_retry_after_failure_is_deterministic() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // First attempt without auth mocking -> must fail and not mutate state.
        let failed = client.try_set_yield_tier(&YieldTierState::Tier2);
        assert!(failed.is_error());
        assert_eq(client.get_yield_tier(), YieldTierState::Unset);
        assert_eq(env.events().all().len(), 0);

        // Retry with auth mocked -> must succeed and emit exactly one event.
        env.mock_all_auths();
        client.set_yield_tier(&YieldTierState::Tier2);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier2);

        let events = env.events().all();
        assert_eq(events.len(), 1);
        assert_eq(
            events.last().unwrap(),
            (
                contract_id,
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier2,).into_val(&env),
            )
        );
    }

    // Retry after a failed upgrade: the second attempt must succeed and the
    // event must reflect the actually applied wasm hash.
    #[test]
    fn test_retry_upgrade_after_failure_is_deterministic() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        let new_wasm = BytesN::from_array(&env, &[3; 32]);

        // First attempt without auth mocking -> must fail and emit nothing.
        let failed = client.try_upgrade(&new_wasm);
        assert!(failed.is_error());
        assert_eq(env.events().all().len(), 0);

        // Retry with auth mocked -> must succeed and emit exactly one event.
        env.mock_all_auths();
        client.upgrade(&new_wasm);

        let events = env.events().all();
        assert_eq(events.len(), 1);
        assert_eq(
            events.last().unwrap(),
            (
                contract_id,
                (symbol_short!("upgrade"),).into_val(&env),
                (new_wasm.clone(),).into_val(&env),
            )
        );
    }

    // Partial completion guard: a failed write must not leave behind any
    // intermediate state. After a failure the contract must behave exactly like
    // a freshly initialized contract with Unset tier.
    #[test]
    fn test_partial_completion_does_not_corrupt_state() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // Failed write without auth.
        let failed = client.try_set_yield_tier(&YieldTierState::Tier3);
        assert!(failed.is_error());

        // State must be identical to a fresh contract: Unset, no events.
        assert_eq(client.get_yield_tier(), YieldTierState::Unset);
        assert_eq(env.events().all().len(), 0);

        // A later successful write must produce the expected single event.
        env.mock_all_auths();
        client.set_yield_tier(&YieldTierState::Tier3);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier3);
        assert_eq(env.events().all().lang(), 1);
    }

    // Concurrent/repeated execution: multiple successful writes must be
    // deterministic and events must be emitted in causal order with the
    // correct final value.
    #[test]
    fn test_repeated_writes_are_deterministic() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_yield_tier(&YieldTierState::Tier1);
        client.set_yield_tier(&YieldTierState::Tier2);
        client.set_yield_tier(&YieldTierState::Tier3);

        // Final state must reflect the last write.
        assert_eq(client.get_yield_tier(), YieldTierState::Tier3);

        // Exactly three events, in order, with the correct values.
        let events = env.events().all();
        assert_eq(events.len(.), 3);
        assert_eq(
            events.get(0).unwrap(),
            (
                contract_id.clone(),
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier1,).into_val(&env),
            )
        );
        assert_eq(
            events.get(1).unwrap(),
            (
                contract_id.clone(),
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier2,).into_val(&env),
            )
        );
        assert_eq(
            events.get(2).unwrap(),
            (
                contract_id.clone(),
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier3,).into_val(&env),
            )
        );
    }

    // Boundary case: writing the same tier twice is allowed and must be
    // deterministic -- the final state and the number of events are well
    // defined.
    #[test]
    fn test_duplicate_write_is_deterministic() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_yield_tier(&YieldTierState::Tier2);
        client.set_yield_tier(&YieldTierState::Tier2);

        assert_eq(client.get_yield_tier(), YieldTierState::Tier2);
        assert_eq(env.events().all().len(), 2);
    }

    // Boundary case: a failed write must not affect the admin authorization
    // for later calls. After a failure, an authorized admin can still write.
    #[test]
    fn test_failure_preserves_admin_authorization() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // Failed write without auth.
        let failed = client.try_set_yield_tier(&YieldTierState::Tier1);
        assert!(failed.is_error());

        // Authorized admin can still write after the failure.
        env.mock_all_auths();
        client.set_yield_tier(&YieldTierState::Tier1);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier1);
    }

    // Regression: a failed write must not consume or alter the admin slot.
    // The contract must still accept the original admin's authorized writes.
    #[test]
    fn test_failure_does_not_consume_admin_slot() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // Multiple failed writes in a row.
        for _ in 0..3 {
            let failed = client.try_set_yield_tier(&YieldTierState::Tier3);
            assert!(failed.is_error());
        }

        // State unchanged and no events emitted.
        assert_eq(client.get_yield_tier(), YieldTierState::Unset);
        assert_eq(env.events().all().len(), 0);

        // Admin still authorized.
        env.mock_all_auths();
        client.set_yield_tier(&YieldTierState::Tier3);
        assert_eq(client.get_yield_tier(), YieldTierState::Tier3);
    }

    // Regission: a failed upgrade must not corrupt the yield tier state.
    #[test]
    fn test_failed_upgrade_does_not_corrupt_tier_state() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);
        client.set_yield_tier(&YieldTierState::Tier2);

        // Failed upgrade without auth.
        let new_wasm = BytesN::from_array(&env, &[9; 32]);
        let failed = client.try_upgrade(&new_wasm);
        assert!(failed.is_error());

        // Tier state must be unchanged.
        asser_eq(client.get_yield_tier(), YieldTierState::Tier2);
    }

    // Regression: events from a failed attempt must not leak into the event
    // stream of a subsequent successful attempt.
    #[test]
    fn test_failure_events_do_not_leak() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // Failed write.
        let failed = client.try_set_yield_tier(&YieldTierState::Tier1);
        assert!(failed.is_error());
        assert_eq(env.events().all().len(), 0);

        // Successful write after the failure.
        env.mock_all_auths();
        client.set_yield_tier(&YieldTierState::Tier1);

        // Exactly one event, and it must be the successful write.
        let events = env.events().all();
        assert_eq(events.len(), 1);
        assert_eq(
            events.last().unwrap(),
            (
                contract_id,
                (symbol_short!("tier_set"),).into_val(&env),
                (YieldTierState::Tier1,).into_val(&env),
            )
        );
    }

    // Boundary: the contract must remain recoverable across multiple ledger
    // advances. A failure on one ledger must not affect the ability to write
    // on a later ledger.
    #[test]
    fn test_recovery_across_ledger_advance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, YieldTierContract);
        let client = YieldTierContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        // Failed write on the current ledger.
        let failed = client.try_set_yield_tier(&YieldTierState::Tier1);
        assert!(failed.is_error());

        // Advance the ledger and retry with auth.
        env.ledger().set_sequence(100);
        env.mock_all_auths();
        client.set_yield_tier(&YieldTierState::Tier1);

        assert_eq(client.get_yield_tier(), YieldTierState::Tier1);
        assert_eq(env.events().all().len(), 1);
    }
}
