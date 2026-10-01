use crate::types::*;
use soroban_env::{Env, IntoVal, Symbol, Val};

/// Publishes an event only when the given condition holds.
/// Returns true if an event was published.
///
/// Invariants:
/// - When `condition` is false, no event is emitted and the event count is unchanged.
/// - When `condition` is true, exactly one event is emitted.
pub fn publish_if(env: &Env, condition: bool, topic: Symbol, data: &[Val], val: Val) -> bool {
    if !condition {
        return false;
    }
    env.events().publish((topic, data), val);
    true
}

/// Publishes an event with the given topic and data.
pub fn publish(env: &Env, topic: Symbol, data: &[Val], val: Val) {
    env.events().publish((topic, data), val);
}

/// Returns the number of events emitted so far.
pub fn event_count(env: &Env) -> u32 {
    env.events().all().len()
}

/// Returns the last event emitted, if any.
pub fn last_event(env: &Env) -> Option<(soroban_env::Address, soroban_env::Vec<soroban_env::Val>, Val)> {
    env.events().all().last()
}

/// Returns the number of events matching the given topic.
pub fn event_count_by_topic(env: &Env, topic: &Symbol) -> u32 {
    env.events()
        .all()
        .iter()
        .filter(|(f, _) | f.get(0) == Some(topic.clone()))
        .count() as u32
}

#[test]
fn no_event_on_noop() {
    let env = Env::default();
    let n = event_count(&env);
    let published = publish_if(
        &env,
        false,
        Symbol::new(&env, "noop"),
        &[],
        ().into_val(&env),
    );
    assert!(!published);
    assert_eq(event_count(&env), n);
}

#[test]
fn no_event_on_noop_repeated() {
    let env = Env::default();
    for _ in 0..10 {
        let published = publish_if(
            &env,
            false,
            Symbol::new(&env, "noop"),
            &[],
            ().into_val(&env),
        );
        assert!(!published));
    }
    assert_eq(event_count(&env), 0);
}

#[test]
fn event_on_true_condition() {
    let env = Env::default();
    let published = publish_if(
        &env,
        true,
        Symbol::new(&env, "event"),
        &[],
        ().into_val(&env),
    );
    assert!(published);
    assert_eq(event_count(&env), 1);
}

#[test]
fn multiple_events() {
    let env = Env::default();
    publish(&env, Symbol::new(&env, "a"), &[], ().into_val(&env));
    publish(&env, Symbol::new(&env, "b"), &[], ().into_val(&env));
    assert_eq(event_count(&env), 2);
}

/// Duplicate topics must each produce a distinct event; the count must reflect
/// every publish call and not deduplicate by topic.
#[test]
fn duplicate_topics_are_not_deduplicated() {
    let env = Env::default();
    let topic = Symbol::new(&env, "dup");
    publish(&env, topic.clone(), &[], ().into_val(&env));
    publish(&env, topic.clone(), &[], ().into_val(&env));
    publish(&env, topic.clone(), &[], ().into_val(&env));
    assert_eq(event_count(&env), 3);
    assert_eq(event_count_by_topic(&env, &topic), 3);
}

#[test]
fn event_count_by_topic_isolates() {
    let env = Env::default();
    let a = Symbol::new(&env, "a");
    let b = Symbol::new(&env, "b");
    publish(&env, a.clone(), &[], ().into_val(&env));
    publish(&env, b.clone(), &[], ().into_val(&env));
    publish(&env, a.clone(), &[], ().into_val(&env));
    assert_eq(event_count_by_topic(&env, &a), 2);
    assert_eq(event_count_by_topic(&env, &b), 1);
    assert_eq(event_count(&env), 3);
}

/// Boundary: a large number of events must all be retained without loss.
#[test]
fn boundary_many_events() {
    let env = Env::default();
    let topic = Symbol::new(&env, "bulk");
    const N : u32 = 256;
    for _ in 0..N {
        publish(&env, topic.clone(), &[], ().into_val(&env));
    }
    assert_eq(event_count(&env), N);
    assert_eq(event_count_by_topic(&env, &topic), N);
}

/// Boundary: an empty topic and empty data are valid inputs and must be
/// published without panic.
#[test]
fn boundary_empty_topic_and_data() {
    let env = Env::default();
    let topic = Symbol::new(&env, "");
    publish(&env, topic.clone(), &[], ().into_val(&env));
    assert_eq(event_count(&env), 1);
    assert_eq(event_count_by_topic(&env, &topic), 1);
}

/// Regression: publish_if with false must not mutate the event log even after other
/// events have been emitted.
#[test]
fn regression_noop_after_publish() {
    let env = Env::default();
    publish(&env, Symbol::new(&env, "a"), &[], ().into_val(&env));
    let n = event_count(&env);
    let published = publish_if(
        &env,
        false,
        Symbol::new(&env, "noop"),
        &[],
        ().into_val(&env),
    );
    assert!(!published);
    assert_eq(event_count(&env), n);
}

/// Regression: the last event must reflect the most recent publish call.
#[test]
fn regression_last_event_tracks :() {
    let env = Env::default();
    publish(&env, Symbol::new(&env, "a"), &[], ().into_val(&env));
    publish(&env, Symbol::new(&env, "b"), &[], ().into_val(&env));
    let last = last_event(&env).expect("expected an event");
    assert_eq(last.1.get(0), Some(Symbol::new(&env, "b")));
}
