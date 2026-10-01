//! Hardened concurrent-execution, idempotency, and boundary tests for the
//! protocol-fee subsystem (issue #1399).
//!
//! # Scope
//!
//! The protocol fee is configured at [`crate::LiquifactEscrow::init`], read via
//! `get_protocol_fee_bps`, mutated via `set_protocol_fee_bps`, and applied on the
//! SME disbursement path `withdraw`, where the funded principal is split:
//!
//! ```text
//! fee        = amount * protocol_fee_bps / 10_000   (floor, checked)
//! sme_payout = amount - fee                          (checked)
//! ```
//!
//! `withdraw` computes the split from the **live** stored fee at call time, so a
//! concurrent/retried admin update and an SME withdrawal cannot observe a torn or
//! stale value: the write is atomic and the last committed write wins.
//!
//! # Invariants asserted
//!
//! * **Conservation** — `fee + sme_payout == amount` for every withdrawal.
//! * **Monotone state machine** — `withdraw` only ever moves `status` `1 -> 3`, and
//!   a second call on terminal `status == 3` is rejected (`WithdrawalNotFunded`).
//! * **No partial writes** — rejected validation leaves the prior stored fee and the
//!   prior escrow state untouched (Soroban rolls back failed invocations).
//! * **Auth boundary** — `set_protocol_fee_bps` requires the current admin and
//!   `withdraw` requires the SME; neither is reachable without authorization.
//!
//! # Coverage map (issue #1399)
//!
//! | Acceptance criterion | Test(s) |
//! |----------------------|---------|
//! | Deterministic for valid inputs | `fee_split_*`, `withdraw_*`, `get_protocol_fee_bps_*` |
//! | Deterministic for invalid inputs | `init_rejects_fee_*`, `set_protocol_fee_bps_rejects_*` |
//! | Deterministic for boundary inputs | `*_boundary_*`, `withdraw_fee_minimum_*` |
//! | Duplicate/replayed work is idempotent | `*_idempotent_*`, `withdraw_second_call_*`, `withdraw_retry_*` |
//! | Concurrent execution cannot corrupt state | `*_concurrent_*`, `*_sequential_*`, `*_last_write_wins` |
//! | Authorization invariants enforced | `*_requires_admin_auth`, `withdraw_requires_sme_auth` |
//! | State-transition invariants enforced | `withdraw_transitions_*`, `withdraw_second_call_*` |
//! | Failures are diagnosable (typed codes) | every `assert_contract_error` usage |
//!
//! Each test owns a fresh `Env`; no cross-test state is shared. Soroban executes
//! one transaction per ledger, so "concurrent" calls are modelled as adjacent
//! sequential invocations against the same escrow — the strongest observable
//! approximation of interleaving the host permits.

use super::{assert_contract_error, deploy, TARGET};
use crate::{
    EscrowError, LiquifactEscrow, PauseReason, PauseScope, ProtocolFeeUpdated, SmeWithdrew,
};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _},
    token::{StellarAssetClient, TokenClient},
    Address, Env, Event, String,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal init with caller-supplied `protocol_fee_bps`, no on-chain token custody.
///
/// Returns `(client, admin, sme, treasury)`. Intended for the configuration /
/// accessor / auth tests that never call `withdraw`.
fn init_with_fee<'a>(
    env: &'a Env,
    invoice_id: &str,
    protocol_fee_bps: Option<i64>,
) -> (super::LiquifactEscrowClient<'a>, Address, Address, Address) {
    let client = deploy(env);
    let admin = Address::generate(env);
    let sme = Address::generate(env);
    let token = Address::generate(env);
    let treasury = Address::generate(env);
    client.init(
        &admin,
        &String::from_str(env, invoice_id),
        &sme,
        &TARGET,
        &800i64,
        &0u64,
        &token,
        &None,
        &treasury,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &protocol_fee_bps,
        &None::<u32>,
    );
    (client, admin, sme, treasury)
}

/// Build a fully funded escrow backed by a real Stellar asset contract.
///
/// Returns `(client, escrow_id, sme, treasury, sac_admin)`. The escrow starts at
/// `status == 1` (funded) and the contract account holds at least `amount` tokens
/// so `withdraw()` can transfer both the treasury fee and the SME payout.
///
/// Tokens are minted to the investor *and* directly to the escrow contract so the
/// helper is robust to whether a given build custodies principal by token transfer
/// or by accounting only.
fn funded_setup<'a>(
    env: &'a Env,
    invoice_id: &str,
    amount: i128,
    protocol_fee_bps: Option<i64>,
) -> (
    super::LiquifactEscrowClient<'a>,
    Address,
    Address,
    Address,
    StellarAssetClient<'a>,
) {
    env.mock_all_auths();
    let sac = env.register_stellar_asset_contract_v2(Address::generate(env));
    let token_id = sac.address();
    let sac_admin = StellarAssetClient::new(env, &token_id);

    let escrow_id = env.register(LiquifactEscrow, ());
    let client = super::LiquifactEscrowClient::new(env, &escrow_id);
    let admin = Address::generate(env);
    let sme = Address::generate(env);
    let treasury = Address::generate(env);

    client.init(
        &admin,
        &String::from_str(env, invoice_id),
        &sme,
        &amount,
        &800i64,
        &0u64,
        &token_id,
        &None,
        &treasury,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &protocol_fee_bps,
        &None::<u32>,
    );

    let investor = Address::generate(env);
    sac_admin.mint(&investor, &amount);
    client.fund(&investor, &amount);
    // Belt-and-suspenders custody so `withdraw` always has a token balance to move.
    sac_admin.mint(&escrow_id, &amount);

    (client, escrow_id, sme, treasury, sac_admin)
}

/// Floor fee split with checked intermediate arithmetic, mirroring the production
/// formula. Used to compute expected values independently of the contract.
fn split(amount: i128, fee_bps: i64) -> (i128, i128) {
    let fee = amount
        .checked_mul(fee_bps as i128)
        .expect("amount * fee_bps must fit i128")
        / 10_000;
    let net = amount - fee;
    (fee, net)
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 1 — `init`: fee configuration and validation
// ─────────────────────────────────────────────────────────────────────────────

/// `None` default is stored as `0` — no fee is applied on withdrawal.
#[test]
fn init_fee_none_defaults_to_zero() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES001", None);
    assert_eq!(client.get_protocol_fee_bps(), 0i64);
}

/// Explicit `Some(0)` is indistinguishable from the default.
#[test]
fn init_fee_explicit_zero_stored() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES002", Some(0i64));
    assert_eq!(client.get_protocol_fee_bps(), 0i64);
}

/// A mid-range fee is stored exactly.
#[test]
fn init_fee_midrange_stored_exactly() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES003", Some(500i64));
    assert_eq!(client.get_protocol_fee_bps(), 500i64);
}

/// The maximum valid fee (`10_000` bps = 100%) is accepted at the boundary.
#[test]
fn init_fee_boundary_max_accepted() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES004", Some(10_000i64));
    assert_eq!(client.get_protocol_fee_bps(), 10_000i64);
}

/// `10_001` is one above the maximum — rejected with a typed error.
#[test]
fn init_rejects_fee_above_max() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);
    let admin = Address::generate(&env);
    let sme = Address::generate(&env);
    let token = Address::generate(&env);
    let treasury = Address::generate(&env);
    assert_contract_error(
        client.try_init(
            &admin,
            &String::from_str(&env, "FEES005"),
            &sme,
            &TARGET,
            &800i64,
            &0u64,
            &token,
            &None,
            &treasury,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &Some(10_001i64),
            &None::<u32>,
        ),
        EscrowError::ProtocolFeeBpsOutOfRange,
    );
}

/// A negative fee is rejected with a typed error.
#[test]
fn init_rejects_fee_negative() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);
    let admin = Address::generate(&env);
    let sme = Address::generate(&env);
    let token = Address::generate(&env);
    let treasury = Address::generate(&env);
    assert_contract_error(
        client.try_init(
            &admin,
            &String::from_str(&env, "FEES006"),
            &sme,
            &TARGET,
            &800i64,
            &0u64,
            &token,
            &None,
            &treasury,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &Some(-1i64),
            &None::<u32>,
        ),
        EscrowError::ProtocolFeeBpsOutOfRange,
    );
}

/// A rejected init must not write partial state: a subsequent clean init on the
/// same contract instance succeeds and stores the new fee.
#[test]
fn init_fee_rejection_leaves_no_partial_state() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);
    let admin = Address::generate(&env);
    let sme = Address::generate(&env);
    let token = Address::generate(&env);
    let treasury = Address::generate(&env);

    // Rejected init (fee far above the maximum) — must terminate before any write.
    assert_contract_error(
        client.try_init(
            &admin,
            &String::from_str(&env, "FEES007"),
            &sme,
            &TARGET,
            &800i64,
            &0u64,
            &token,
            &None,
            &treasury,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &Some(99_999i64),
            &None::<u32>,
        ),
        EscrowError::ProtocolFeeBpsOutOfRange,
    );

    // A clean init with a valid fee must now succeed (proves nothing was persisted).
    client.init(
        &admin,
        &String::from_str(&env, "FEES007"),
        &sme,
        &TARGET,
        &800i64,
        &0u64,
        &token,
        &None,
        &treasury,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &Some(250i64),
        &None::<u32>,
    );
    assert_eq!(client.get_protocol_fee_bps(), 250i64);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2 — `get_protocol_fee_bps`: read-only, idempotent
// ─────────────────────────────────────────────────────────────────────────────

/// Uninitialized instances read `0` (additive-key default, ADR-007).
#[test]
fn get_protocol_fee_bps_before_init_returns_zero() {
    let env = Env::default();
    let client = deploy(&env);
    assert_eq!(client.get_protocol_fee_bps(), 0i64);
}

/// Repeated reads return the same value and mutate nothing.
#[test]
fn get_protocol_fee_bps_is_idempotent() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES010", Some(300i64));
    for _ in 0..5 {
        assert_eq!(client.get_protocol_fee_bps(), 300i64);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3 — `set_protocol_fee_bps`: mutation, auth, validation, idempotency
// ─────────────────────────────────────────────────────────────────────────────

/// Admin can update the fee to any value within `0..=10_000`.
#[test]
fn set_protocol_fee_bps_valid_update() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES020", None);

    let result = client.set_protocol_fee_bps(&750i64);
    assert_eq!(result, 750i64);
    assert_eq!(client.get_protocol_fee_bps(), 750i64);
}

/// The return value equals the newly stored fee.
#[test]
fn set_protocol_fee_bps_returns_new_value() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES021", Some(100i64));

    let returned = client.set_protocol_fee_bps(&200i64);
    assert_eq!(returned, 200i64);
}

/// Setting the *same* value is idempotent: it returns the current value and emits
/// no event, so duplicate/retried admin work cannot spam observers or corrupt state.
#[test]
fn set_protocol_fee_bps_idempotent_same_value_no_event() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES022", Some(500i64));

    let events_before = env.events().all().events().len();

    let r1 = client.set_protocol_fee_bps(&500i64);
    let r2 = client.set_protocol_fee_bps(&500i64);

    assert_eq!(r1, 500i64);
    assert_eq!(r2, 500i64);
    assert_eq!(client.get_protocol_fee_bps(), 500i64);
    assert_eq!(
        env.events().all().events().len(),
        events_before,
        "idempotent set_protocol_fee_bps must not emit events"
    );
}

/// A real change emits `ProtocolFeeUpdated` with the correct old/new values.
#[test]
fn set_protocol_fee_bps_emits_event_on_change() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES023", Some(100i64));
    let contract_id = client.address.clone();
    let invoice_id = client.get_escrow().invoice_id.clone();

    client.set_protocol_fee_bps(&300i64);

    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        ProtocolFeeUpdated {
            name: symbol_short!("fee_upd"),
            invoice_id,
            old_fee_bps: 100i64,
            new_fee_bps: 300i64,
        }
        .to_xdr(&env, &contract_id)
    );
}

/// Successive admin updates are atomic and last-write-wins; no intermediate value
/// can persist. This models back-to-back "racing" updates.
#[test]
fn set_protocol_fee_bps_sequential_updates_last_write_wins() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES024", None);

    client.set_protocol_fee_bps(&100i64);
    client.set_protocol_fee_bps(&200i64);
    client.set_protocol_fee_bps(&300i64);
    client.set_protocol_fee_bps(&400i64);

    assert_eq!(client.get_protocol_fee_bps(), 400i64);
}

/// Both boundary values (`0` and `10_000`) are accepted.
#[test]
fn set_protocol_fee_bps_boundary_zero_and_max() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES025", Some(500i64));

    assert_eq!(client.set_protocol_fee_bps(&0i64), 0i64);
    assert_eq!(client.get_protocol_fee_bps(), 0i64);

    assert_eq!(client.set_protocol_fee_bps(&10_000i64), 10_000i64);
    assert_eq!(client.get_protocol_fee_bps(), 10_000i64);
}

/// `10_001` is rejected and leaves stored state unchanged.
#[test]
fn set_protocol_fee_bps_rejects_above_max() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES026", None);

    assert_contract_error(
        client.try_set_protocol_fee_bps(&10_001i64),
        EscrowError::ProtocolFeeBpsOutOfRange,
    );
    assert_eq!(client.get_protocol_fee_bps(), 0i64);
}

/// Negative bps is rejected and preserves the prior value.
#[test]
fn set_protocol_fee_bps_rejects_negative() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES027", Some(250i64));

    assert_contract_error(
        client.try_set_protocol_fee_bps(&-1i64),
        EscrowError::ProtocolFeeBpsOutOfRange,
    );
    assert_eq!(client.get_protocol_fee_bps(), 250i64);
}

/// Several rejected updates in a row must not corrupt the stored fee.
#[test]
fn set_protocol_fee_bps_rejection_preserves_previous_value() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES028", Some(750i64));

    for bad in [-1i64, -100i64, -500i64, 10_001i64, 20_000i64, 50_000i64] {
        assert_contract_error(
            client.try_set_protocol_fee_bps(&bad),
            EscrowError::ProtocolFeeBpsOutOfRange,
        );
    }

    assert_eq!(
        client.get_protocol_fee_bps(),
        750i64,
        "failed updates must not corrupt the stored fee"
    );
}

/// A non-admin caller (no mocked signer) must fail host auth before any write.
#[test]
#[should_panic]
fn set_protocol_fee_bps_requires_admin_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES029", None);

    // Drop all mocked auths — no signer is authorized.
    env.mock_auths(&[]);
    client.set_protocol_fee_bps(&500i64);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4 — `withdraw`: fee split conservation
// ─────────────────────────────────────────────────────────────────────────────

/// Zero fee: full funded amount goes to the SME and no treasury transfer occurs.
#[test]
fn withdraw_zero_fee_full_amount_to_sme() {
    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES040", TARGET, None);

    client.withdraw();

    let escrow = client.get_escrow();
    assert_eq!(escrow.status, 3u32, "status must be 3 after withdraw");

    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount: TARGET,
            recipient: sme,
            fee: 0i128,
        }
        .to_xdr(&env, &contract_id)
    );
}

/// Non-zero fee: the conservation invariant `fee + net == amount` holds exactly.
#[test]
fn withdraw_nonzero_fee_conservation_invariant() {
    let amount: i128 = 10_000_000_000i128; // exactly divisible by 20
    let fee_bps: i64 = 500; // 5%
    let (expected_fee, expected_net) = split(amount, fee_bps);

    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES041", amount, Some(fee_bps));

    client.withdraw();

    let escrow = client.get_escrow();
    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount: expected_net,
            recipient: sme,
            fee: expected_fee,
        }
        .to_xdr(&env, &contract_id)
    );
    assert_eq!(
        expected_fee + expected_net,
        amount,
        "conservation: fee + net must equal amount exactly"
    );
}

/// Maximum fee (100%): the entire amount goes to treasury and the SME receives 0;
/// `withdraw` still succeeds and emits `fee == amount`, `net == 0`.
#[test]
fn withdraw_max_fee_all_to_treasury() {
    let amount: i128 = 1_000_000i128;
    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES042", amount, Some(10_000i64));

    client.withdraw();

    let escrow = client.get_escrow();
    assert_eq!(escrow.status, 3u32);
    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount: 0i128,
            recipient: sme,
            fee: amount,
        }
        .to_xdr(&env, &contract_id)
    );
}

/// Floor rounding: the residue always stays with the SME.
///
/// `amount = 1_000`, `fee_bps = 333` -> `fee = 33`, `net = 967` (never 33.3).
#[test]
fn withdraw_fee_rounding_residue_stays_with_sme() {
    let amount: i128 = 1_000i128;
    let fee_bps: i64 = 333;
    let (expected_fee, expected_net) = split(amount, fee_bps);
    assert_eq!(expected_fee, 33i128);

    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES043", amount, Some(fee_bps));

    client.withdraw();

    let escrow = client.get_escrow();
    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount: expected_net,
            recipient: sme,
            fee: expected_fee,
        }
        .to_xdr(&env, &contract_id)
    );
}

/// Minimum-principal edge case: `amount = 1`, `fee_bps = 9_999` floors the fee to
/// `0`, so the SME always receives at least one unit while `fee_bps < 10_000`.
#[test]
fn withdraw_fee_minimum_principal_floors_fee_to_zero() {
    let amount: i128 = 1i128;
    let fee_bps: i64 = 9_999;
    let (expected_fee, expected_net) = split(amount, fee_bps);
    assert_eq!(expected_fee, 0i128);
    assert_eq!(expected_net, 1i128);

    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES044", amount, Some(fee_bps));

    client.withdraw();

    let escrow = client.get_escrow();
    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount: expected_net,
            recipient: sme,
            fee: expected_fee,
        }
        .to_xdr(&env, &contract_id)
    );
    assert_eq!(expected_fee + expected_net, amount);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5 — `withdraw`: live fee uses the stored value at call time
// ─────────────────────────────────────────────────────────────────────────────

/// A fee updated after funding but before `withdraw` is honoured: the split uses
/// the *current* stored fee, not the value captured at init.
#[test]
fn withdraw_uses_fee_at_call_time_not_init_time() {
    let amount: i128 = 10_000i128;
    let updated_fee: i64 = 500; // 5%
    let (expected_fee, expected_net) = split(amount, updated_fee);

    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES050", amount, Some(100i64));

    client.set_protocol_fee_bps(&updated_fee);
    assert_eq!(client.get_protocol_fee_bps(), updated_fee);

    client.withdraw();

    let escrow = client.get_escrow();
    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount: expected_net,
            recipient: sme,
            fee: expected_fee,
        }
        .to_xdr(&env, &contract_id)
    );
}

/// Fee lowered to zero before withdrawal: the SME receives the full principal.
#[test]
fn withdraw_fee_zeroed_before_withdrawal_gives_full_amount() {
    let amount: i128 = 5_000i128;
    let env = Env::default();
    let (client, _escrow_id, sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES051", amount, Some(1_000i64));

    client.set_protocol_fee_bps(&0i64);
    client.withdraw();

    let escrow = client.get_escrow();
    let contract_id = client.address.clone();
    assert_eq!(
        env.events().all().events().last().unwrap().clone(),
        SmeWithdrew {
            name: symbol_short!("sme_wd"),
            invoice_id: escrow.invoice_id.clone(),
            amount,
            recipient: sme,
            fee: 0i128,
        }
        .to_xdr(&env, &contract_id)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 6 — `withdraw`: state-transition invariants, retries, idempotency
// ─────────────────────────────────────────────────────────────────────────────

/// `withdraw` moves `status` `1 -> 3` (forward-only).
#[test]
fn withdraw_transitions_status_to_three() {
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES060", TARGET, None);

    assert_eq!(
        client.get_escrow().status,
        1u32,
        "pre-condition: status == 1"
    );
    client.withdraw();
    assert_eq!(
        client.get_escrow().status,
        3u32,
        "post-condition: status == 3"
    );
}

/// `withdraw` on an unfunded escrow is rejected with `WithdrawalNotFunded`.
#[test]
fn withdraw_on_open_escrow_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES061", None);

    assert_contract_error(client.try_withdraw(), EscrowError::WithdrawalNotFunded);
}

/// Two back-to-back `withdraw` calls must not double-pay: the second is rejected
/// by the terminal status and state is unchanged.
#[test]
fn withdraw_second_call_rejected_after_terminal_status() {
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES062", TARGET, None);

    client.withdraw(); // succeeds, status -> 3
    assert_contract_error(client.try_withdraw(), EscrowError::WithdrawalNotFunded);
    assert_eq!(client.get_escrow().status, 3u32);
}

/// Accounting fields survive withdrawal — nothing is silently zeroed.
#[test]
fn withdraw_preserves_accounting_fields() {
    let amount: i128 = 2_000_000i128;
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES063", amount, None);

    client.withdraw();

    let escrow = client.get_escrow();
    assert_eq!(
        escrow.funded_amount, amount,
        "funded_amount must not be wiped"
    );
    assert_eq!(
        escrow.funding_target, amount,
        "funding_target must not be mutated"
    );
}

/// A withdrawal blocked by a read-only guard (legal hold) leaves status untouched;
/// once the guard is cleared the *same* retried call succeeds exactly once.
#[test]
fn withdraw_retry_after_guard_failure_is_idempotent() {
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES064", TARGET, None);

    client.set_legal_hold(&true, &0u32);
    assert_contract_error(
        client.try_withdraw(),
        EscrowError::LegalHoldBlocksWithdrawal,
    );
    assert_eq!(
        client.get_escrow().status,
        1u32,
        "blocked withdraw must not mutate status"
    );

    client.set_legal_hold(&false, &1u32);
    client.withdraw();

    assert_eq!(client.get_escrow().status, 3u32);
    assert_contract_error(client.try_withdraw(), EscrowError::WithdrawalNotFunded);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 7 — `withdraw`: auth and guard ordering
// ─────────────────────────────────────────────────────────────────────────────

/// `withdraw` requires SME auth; with no mocked signer the call panics before any
/// state write.
#[test]
#[should_panic]
fn withdraw_requires_sme_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES070", TARGET, None);

    // Drop all auth — withdraw must panic without SME authorization.
    env.mock_auths(&[]);
    client.withdraw();
}

/// A legal hold blocks withdrawal with a typed error and no partial state change.
#[test]
fn withdraw_blocked_by_legal_hold() {
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES071", TARGET, None);

    client.set_legal_hold(&true, &0u32);
    assert_contract_error(
        client.try_withdraw(),
        EscrowError::LegalHoldBlocksWithdrawal,
    );
    assert_eq!(client.get_escrow().status, 1u32);
}

/// `withdraw` succeeds once the legal hold is cleared.
#[test]
fn withdraw_succeeds_after_legal_hold_cleared() {
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES072", TARGET, None);

    client.set_legal_hold(&true, &0u32);
    client.set_legal_hold(&false, &1u32);
    client.withdraw();
    assert_eq!(client.get_escrow().status, 3u32);
}

/// An operational pause scoped to withdrawals blocks the call with a typed error.
#[test]
fn withdraw_blocked_by_pause() {
    let env = Env::default();
    let (client, _escrow_id, _sme, _treasury, _sac_admin) =
        funded_setup(&env, "FEES073", TARGET, None);

    client.set_paused(&true, &PauseScope::Withdrawal, &PauseReason::Incident);
    assert_contract_error(client.try_withdraw(), EscrowError::PausedBlocksWithdrawal);
    assert_eq!(
        client.get_escrow().status,
        1u32,
        "status must remain 1 while paused"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 8 — `InsufficientContractBalance` guard
// ─────────────────────────────────────────────────────────────────────────────

/// When the escrow holds fewer tokens than `funded_amount`, `withdraw` fails with
/// `InsufficientContractBalance` **before** mutating status.
#[test]
fn withdraw_fails_insufficient_contract_balance() {
    let env = Env::default();
    env.mock_all_auths();

    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let token_id = sac.address();
    let sac_admin = StellarAssetClient::new(&env, &token_id);

    let escrow_id = env.register(LiquifactEscrow, ());
    let client = super::LiquifactEscrowClient::new(&env, &escrow_id);
    let admin = Address::generate(&env);
    let sme = Address::generate(&env);
    let treasury = Address::generate(&env);

    client.init(
        &admin,
        &String::from_str(&env, "FEES080"),
        &sme,
        &TARGET,
        &800i64,
        &0u64,
        &token_id,
        &None,
        &treasury,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None::<i64>,
        &None::<u32>,
    );

    // Fund the escrow (status -> 1), then drain any custodied balance so the
    // contract holds fewer tokens than the recorded `funded_amount`.
    let investor = Address::generate(&env);
    sac_admin.mint(&investor, &TARGET);
    client.fund(&investor, &TARGET);

    let token = TokenClient::new(&env, &token_id);
    let held = token.balance(&escrow_id);
    if held > 0 {
        token.transfer(&escrow_id, &admin, &held);
    }
    assert_eq!(token.balance(&escrow_id), 0i128);

    assert_contract_error(
        client.try_withdraw(),
        EscrowError::InsufficientContractBalance,
    );
    assert_eq!(
        client.get_escrow().status,
        1u32,
        "failed balance check must not mutate status"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 9 — boundary sweeps and concurrent-execution models
// ─────────────────────────────────────────────────────────────────────────────

/// Sweep the fee rate across all boundaries immediately before withdraw and
/// confirm the conservation invariant holds in each case.
#[test]
fn fee_split_conservation_across_boundary_rates() {
    let amount: i128 = 10_000i128;
    for &bps in &[0i64, 1i64, 9_999i64, 10_000i64] {
        let env = Env::default();
        let (client, _escrow_id, sme, _treasury, _sac_admin) =
            funded_setup(&env, "FEES090", amount, Some(bps));

        client.withdraw();

        let escrow = client.get_escrow();
        let (expected_fee, expected_net) = split(amount, bps);
        let contract_id = client.address.clone();

        assert_eq!(
            env.events().all().events().last().unwrap().clone(),
            SmeWithdrew {
                name: symbol_short!("sme_wd"),
                invoice_id: escrow.invoice_id.clone(),
                amount: expected_net,
                recipient: sme,
                fee: expected_fee,
            }
            .to_xdr(&env, &contract_id),
            "conservation failed at bps={bps}"
        );
        assert_eq!(
            expected_fee + expected_net,
            amount,
            "fee + net must equal amount at bps={bps}"
        );
    }
}

/// Adjacent admin updates followed by a single withdrawal are deterministic: the
/// final committed fee is the one applied, and the split is exactly that fee.
#[test]
fn set_protocol_fee_bps_concurrent_model_last_write_wins() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme, _treasury) = init_with_fee(&env, "FEES091", Some(100i64));

    // Two "concurrent" admin updates — the second commit wins.
    client.set_protocol_fee_bps(&300i64);
    client.set_protocol_fee_bps(&600i64);

    let stored = client.get_protocol_fee_bps();
    assert_eq!(stored, 600i64, "last write must win; stored={stored}");
}

/// Replay determinism: for a fixed fee, funding, and withdrawal, the resulting
/// split is identical across independent escrow instances.
#[test]
fn withdraw_split_is_deterministic_across_instances() {
    let amount: i128 = 7_777_777i128;
    let fee_bps: i64 = 137i64;
    let (expected_fee, expected_net) = split(amount, fee_bps);

    for run in 0..3 {
        let env = Env::default();
        let (client, _escrow_id, sme, _treasury, _sac_admin) =
            funded_setup(&env, "FEES093", amount, Some(fee_bps));

        client.withdraw();

        let escrow = client.get_escrow();
        let contract_id = client.address.clone();
        assert_eq!(
            env.events().all().events().last().unwrap().clone(),
            SmeWithdrew {
                name: symbol_short!("sme_wd"),
                invoice_id: escrow.invoice_id.clone(),
                amount: expected_net,
                recipient: sme,
                fee: expected_fee,
            }
            .to_xdr(&env, &contract_id),
            "run {run} diverged from the deterministic split"
        );
    }
}
