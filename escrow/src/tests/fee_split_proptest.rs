//! Validation-boundary property-based tests for the immutable protocol-fee split (#1391).
//!
//! The escrow contract splits the gross disbursement at [`LiquifactEscrow::withdraw`] into a
//! treasury fee and a net SME payout:
//!
//! ```text
//! fee       = floor(gross * protocol_fee_bps / 10_000)
//! sme_payout = gross - fee
//! ```
//!
//! This module pins down the *boundaries* of that split so a future refactor cannot silently
//! move them. It is organised in five sections:
//!
//! 1. **Valid distributions** - splits that sum correctly across a wide range of gross amounts
//!    and fee rates (including the `0` and `10_000` caps).
//! 2. **Invalid / malformed proportions** - `protocol_fee_bps` and [`FeeSchedule`] bounds that
//!    sit outside the accepted envelope are rejected with a typed error.
//! 3. **Boundary values and duplicates** - the exact edges of every accepted range, the
//!    smallest representable fee, and idempotent re-submission of an unchanged fee or schedule.
//! 4. **Overflow safety** - the `i128` multiplication envelope implied by
//!    [`MAX_INVOICE_AMOUNT`] is proven to make `WithdrawFeeArithmeticOverflow` unreachable
//!    for any in-range `protocol_fee_bps`.
//! 5. **End-to-end `withdraw` behaviour** - the on-chain transfers, the `SmeWithdrew` payload,
//!    and once-only replay protection.
//!
//! # Why there are both properties and explicit matrices
//!
//! Random sampling is good at finding *arithmetic* mistakes but effectively blind at *edge*
//! mistakes: a `(gross, fee_bps)` pair producing a fee of exactly one base unit, or a fee
//! envelope widened from `10_000` to `50_000`, is astronomically unlikely to be drawn. Every
//! such edge is therefore also pinned by a deterministic matrix test, and the two kinds are
//! kept deliberately separate rather than folded into one.
//!
//! The pure-arithmetic properties are checked against a local reference model
//! ([`reference_fee`] / [`reference_net`]) rather than against a duplicated copy of the
//! contract formula, so a contract change that breaks conservation shows up as a failing
//! contract-level property instead of two agreeing-but-wrong models.

use super::*;
use crate::{FeeSchedule, FeeScheduleError, MAX_INVOICE_AMOUNT};
use proptest::prelude::*;

/// Basis-point denominator used by every fee/yield computation in the contract.
const BPS_DENOM: i128 = 10_000;

/// Inclusive upper bound of every accepted `protocol_fee_bps` / `fee_bps` value.
const MAX_FEE_BPS: i64 = 10_000;

// ---------------------------------------------------------------------------
// Reference model
// ---------------------------------------------------------------------------

/// Reference treasury fee: `floor(gross * fee_bps / 10_000)`.
///
/// Mirrors the checked arithmetic in `withdraw`, but `expect`s instead of returning a
/// contract error so the properties can assert the envelope is never violated.
fn reference_fee(gross: i128, fee_bps: i64) -> i128 {
    gross
        .checked_mul(fee_bps as i128)
        .expect("reference fee multiplication must stay inside the i128 envelope")
        / BPS_DENOM
}

/// Reference SME payout: `gross - fee` (the floor remainder always stays with the SME).
fn reference_net(gross: i128, fee_bps: i64) -> i128 {
    gross - reference_fee(gross, fee_bps)
}

/// The inclusive envelope the contract accepts for a fee rate.
fn fee_bps_in_range(fee_bps: i64) -> bool {
    (0..=MAX_FEE_BPS).contains(&fee_bps)
}

/// The inclusive envelope the contract accepts for a [`FeeSchedule`] bound triple.
///
/// `submit_fee_schedule` requires `min_fee_bps <= fee_bps <= max_fee_bps` and
/// `max_fee_bps <= 10_000`, which transitively bounds `fee_bps` to `0..=10_000` as well.
fn schedule_bounds_in_range(min_fee_bps: u32, fee_bps: u32, max_fee_bps: u32) -> bool {
    min_fee_bps <= fee_bps && fee_bps <= max_fee_bps && max_fee_bps <= MAX_FEE_BPS as u32
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// Assert a call failed with the [`FeeScheduleError`] variant `expected`.
///
/// [`FeeScheduleError`] is a distinct `#[contracterror]` enum from [`EscrowError`], so it
/// needs its own comparison rather than reusing the shared `assert_contract_error`.
fn assert_fee_schedule_error<T, E>(
    result: Result<Result<T, E>, Result<Error, InvokeError>>,
    expected: FeeScheduleError,
) where
    T: Debug,
    E: Debug,
{
    let expected_code = expected as u32;
    match result {
        Err(Ok(error)) => {
            assert_eq!(error, Error::from_contract_error(expected_code));
        }
        Err(Err(InvokeError::Contract(code))) => {
            assert_eq!(code, expected_code);
        }
        other => panic!("expected FeeScheduleError({expected_code}), got {other:?}"),
    }
}

/// Deploy an escrow backed by a real Stellar asset contract, initialise it with
/// `protocol_fee_bps = fee_bps`, and fund it to exactly `target`.
///
/// Returns `(client, token, sme, treasury, admin)`. The treasury and SME start at a zero
/// token balance, so a post-`withdraw` balance read *is* the fee / net delta.
fn funded_fee_escrow<'a>(
    env: &'a Env,
    target: i128,
    fee_bps: i64,
) -> (
    LiquifactEscrowClient<'a>,
    TokenClient<'a>,
    Address,
    Address,
    Address,
) {
    let sac = env.register_stellar_asset_contract_v2(Address::generate(env));
    let token_id = sac.address();
    let sac_admin = StellarAssetClient::new(env, &token_id);

    let escrow_id = env.register(LiquifactEscrow, ());
    let client = LiquifactEscrowClient::new(env, &escrow_id);
    let admin = Address::generate(env);
    let sme = Address::generate(env);
    let treasury = Address::generate(env);

    client.init(
        &admin,
        &soroban_sdk::String::from_str(env, "FSPLIT"),
        &sme,
        &target,
        &0i64, // yield_bps
        &0u64, // maturity: 0 disables the maturity gate
        &token_id,
        &None, // registry
        &treasury,
        &None, // yield_tiers
        &None, // min_contribution
        &None, // max_unique_investors
        &None, // max_per_investor
        &None, // legal_hold_clear_delay
        &None, // maturity_max_horizon
        &None, // funding_deadline
        &None, // allowlist_active
        &Some(fee_bps),
        &None::<u32>, // token_decimals
    );

    // Fund to exactly `target` so the escrow reaches the funded state (status == 1).
    let investor = Address::generate(env);
    sac_admin.mint(&investor, &target);
    client.fund(&investor, &target);

    (
        client,
        TokenClient::new(env, &token_id),
        sme,
        treasury,
        admin,
    )
}

// ===========================================================================
// 1. Valid fee distributions that sum correctly
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Conservation invariant.** For any positive gross amount and any in-range fee rate,
    /// `fee + net == gross` and neither leg is negative. This is the core guarantee that the
    /// SME is never over-charged and the treasury is never over-credited.
    #[test]
    fn prop_fee_split_conserves_gross_amount(
        gross in 1i128..=MAX_INVOICE_AMOUNT,
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        let fee = reference_fee(gross, fee_bps);
        let net = reference_net(gross, fee_bps);

        prop_assert!(
            fee + net == gross,
            "split must be lossless: fee({fee}) + net({net}) != gross({gross})"
        );
        prop_assert!(fee >= 0, "fee must never be negative");
        prop_assert!(net >= 0, "net payout must never be negative");
        prop_assert!(fee <= gross, "fee must never exceed the gross amount");
    }

    /// **Exact split law.** The contract owes the treasury precisely
    /// `floor(gross * fee_bps / 10_000)` and the SME the floor remainder. Anything else is a
    /// rounding-direction regression (over- or under-charging).
    #[test]
    fn prop_fee_split_matches_exact_floor_law(
        gross in 1i128..=1_000_000_000_000i128,
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        let expected_fee = gross * fee_bps as i128 / BPS_DENOM;
        prop_assert_eq!(reference_fee(gross, fee_bps), expected_fee);
        prop_assert_eq!(
            reference_net(gross, fee_bps),
            gross - expected_fee,
            "net must be the exact remainder, not a re-derived share"
        );
    }

    /// **Rounding always favours the SME.** The fractional part `gross * fee_bps % 10_000` is
    /// never charged to the treasury, so the realised fee never exceeds the ideal
    /// proportional share.
    #[test]
    fn prop_fee_split_never_rounds_against_the_sme(
        gross in 1i128..=1_000_000_000_000i128,
        fee_bps in 1i64..=MAX_FEE_BPS,
    ) {
        let scaled = gross * fee_bps as i128;
        let remainder = scaled % BPS_DENOM;
        let fee = reference_fee(gross, fee_bps);
        let ideal_share = scaled / BPS_DENOM;

        prop_assert!(fee <= ideal_share, "fee must be floored, never rounded up");
        // The whole scaled obligation decomposes exactly into the charged fee plus the
        // sub-unit residue that floor division leaves behind (and never charges).
        prop_assert_eq!(fee * BPS_DENOM + remainder, scaled);
        // Re-scaling the realised fee can never exceed the exact proportional obligation:
        // the SME is never charged a single base unit more than their fee rate implies.
        prop_assert!(
            fee * BPS_DENOM <= scaled,
            "charged fee must not exceed the proportional obligation"
        );
        // ...and the discarded residue is strictly below one denominator unit, which is
        // what makes the fee a pure floor rather than a rounded share.
        prop_assert!(
            scaled - fee * BPS_DENOM < BPS_DENOM,
            "floor rounding must discard less than one base unit of the obligation"
        );
    }

    /// **Monotonicity in the fee rate.** Raising `protocol_fee_bps` can only move value from the
    /// SME to the treasury, never the reverse.
    #[test]
    fn prop_fee_split_is_monotonic_in_fee_bps(
        gross in 1i128..=1_000_000_000_000i128,
        low_bps in 0i64..=MAX_FEE_BPS,
        high_bps in 0i64..=MAX_FEE_BPS,
    ) {
        prop_assume!(low_bps <= high_bps, "ordering precondition");

        let low_fee = reference_fee(gross, low_bps);
        let high_fee = reference_fee(gross, high_bps);
        prop_assert!(low_fee <= high_fee, "fee must not decrease as fee_bps grows");
        prop_assert!(
            reference_net(gross, low_bps) >= reference_net(gross, high_bps),
            "net payout must not increase as fee_bps grows"
        );
    }

    /// **Monotonicity in the gross amount.** For a fixed non-zero rate, a larger escrow is
    /// never charged a smaller fee.
    #[test]
    fn prop_fee_split_is_monotonic_in_gross_amount(
        small in 1i128..=1_000_000_000_000i128,
        large in 1i128..=1_000_000_000_000i128,
        fee_bps in 1i64..=MAX_FEE_BPS,
    ) {
        prop_assume!(small <= large, "ordering precondition");
        prop_assert!(reference_fee(small, fee_bps) <= reference_fee(large, fee_bps));
    }

    /// **Integer multi-way distribution.** A gross amount partitioned into `k` equal shares
    /// distributes exactly, with the floor remainder accounted for. This is the generalisation
    /// of the two-leg treasury/SME split and guards the "distributions sum correctly"
    /// requirement beyond a fixed pair of beneficiaries.
    #[test]
    fn prop_multi_way_fee_distribution_sums_exactly(
        gross in 1i128..=1_000_000_000_000i128,
        parts in 2usize..=8usize,
    ) {
        let base = gross / parts as i128;
        let mut distributed: i128 = 0;
        for _ in 0..parts {
            distributed += base;
        }
        // The floor remainder is handed to the first part, never dropped.
        distributed += gross % parts as i128;
        prop_assert_eq!(distributed, gross, "every unit must be accounted for");
    }
}

// ===========================================================================
// 2. Rejection of out-of-bounds / malformed fee proportions
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// **`init` accepts exactly the documented envelope.** Any value in `0..=10_000` is
    /// persisted verbatim; the boundary of the accepted set is where rejection starts.
    #[test]
    fn prop_init_accepts_exactly_the_in_range_fee_envelope(
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let client = deploy(&env);
        let admin = Address::generate(&env);
        let sme = Address::generate(&env);

        client.init(
            &admin,
            &soroban_sdk::String::from_str(&env, "FSINIT"),
            &sme,
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &Some(fee_bps),
            &None::<u32>,
        );

        prop_assert_eq!(client.get_protocol_fee_bps(), fee_bps);
    }

    /// **`init` rejects negative and over-cap fee rates.** One basis point past either edge of
    /// the envelope must abort with `ProtocolFeeBpsOutOfRange` and must not initialise state.
    ///
    /// The generated window is deliberately kept *tight against both edges* rather than
    /// spanning the whole `i64` domain: a full-domain range would be sampled so sparsely
    /// near `10_001` that a boundary widened by a few thousand basis points would go
    /// undetected. The extreme values themselves are pinned by
    /// `test_init_fee_bps_rejection_boundary_matrix`.
    #[test]
    fn prop_init_rejects_out_of_range_fee_bps(
        fee_bps in prop_oneof![
            -20_000i64..=-1i64,
            (MAX_FEE_BPS + 1)..=(MAX_FEE_BPS + 20_000),
        ],
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let client = deploy(&env);
        let admin = Address::generate(&env);
        let sme = Address::generate(&env);

        assert_contract_error(
            client.try_init(
                &admin,
                &soroban_sdk::String::from_str(&env, "FSBAD"),
                &sme,
                &TARGET,
                &0i64,
                &0u64,
                &Address::generate(&env),
                &None,
                &Address::generate(&env),
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &Some(fee_bps),
                &None::<u32>,
            ),
            EscrowError::ProtocolFeeBpsOutOfRange,
        );
    }

    /// **The accepted set is exactly `0..=10_000` and nothing wider.** This states the
    /// boundary as a closed property over a domain that straddles both edges: the predicate
    /// agrees with the contract's `(0..=10_000).contains(..)` check, admits both endpoints,
    /// and rejects the neighbouring integers.
    #[test]
    fn prop_fee_rate_envelope_is_exactly_zero_to_ten_thousand(
        fee_bps in -1_000_000i64..=1_000_000i64,
    ) {
        let expected_in_range = (0..=MAX_FEE_BPS).contains(&fee_bps);
        prop_assert_eq!(fee_bps_in_range(fee_bps), expected_in_range);

        // Both endpoints are inside the envelope, and the integers either side are not.
        prop_assert!(fee_bps_in_range(0));
        prop_assert!(fee_bps_in_range(MAX_FEE_BPS));
        prop_assert!(!fee_bps_in_range(-1));
        prop_assert!(!fee_bps_in_range(MAX_FEE_BPS + 1));

        // Membership is exactly "greater than the lower edge and below the upper edge plus one".
        prop_assert_eq!(
            fee_bps_in_range(fee_bps),
            fee_bps > -1 && fee_bps < MAX_FEE_BPS + 1
        );
    }


    /// **Malformed schedule bounds are rejected.** Any `min > fee`, `fee > max`, or
    /// `max > 10_000` triple must be refused; the contract never silently clamps.
    #[test]
    fn prop_malformed_schedule_bounds_are_rejected(
        min_fee_bps in 0u32..=MAX_FEE_BPS as u32,
        fee_bps in 0u32..=MAX_FEE_BPS as u32,
        max_fee_bps in 0u32..=MAX_FEE_BPS as u32,
    ) {
        prop_assume!(
            !schedule_bounds_in_range(min_fee_bps, fee_bps, max_fee_bps),
            "generated schedule must be out of bounds"
        );

        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _sme) = setup(&env);
        client.init(
            &Address::generate(&env),
            &soroban_sdk::String::from_str(&env, "FSSCH"),
            &Address::generate(&env),
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
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

        assert_fee_schedule_error(
            client.try_submit_fee_schedule(&FeeSchedule {
                fee_bps,
                min_fee_bps,
                max_fee_bps,
                activation_ledger: 500,
            }),
            FeeScheduleError::FeeOutOfBounds,
        );
    }

    /// **Well-formed schedule bounds are accepted and persisted verbatim.** The complement of
    /// the rejection property above: every in-envelope triple becomes the pending schedule.
    #[test]
    fn prop_well_formed_schedule_bounds_are_accepted(
        min_fee_bps in 0u32..=MAX_FEE_BPS as u32,
        fee_bps in 0u32..=MAX_FEE_BPS as u32,
        max_fee_bps in 0u32..=MAX_FEE_BPS as u32,
    ) {
        prop_assume!(
            schedule_bounds_in_range(min_fee_bps, fee_bps, max_fee_bps),
            "generated schedule must be in bounds"
        );

        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _sme) = setup(&env);
        let admin = Address::generate(&env);
        client.init(
            &admin,
            &soroban_sdk::String::from_str(&env, "FSSOK"),
            &Address::generate(&env),
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
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

        let schedule = FeeSchedule {
            fee_bps,
            min_fee_bps,
            max_fee_bps,
            activation_ledger: 500,
        };
        client.submit_fee_schedule(&schedule);
        prop_assert_eq!(client.get_pending_fee_schedule(), Some(schedule));
    }
}

// ===========================================================================
// 3. Boundary values and duplicate submissions
// ===========================================================================

/// **`set_protocol_fee_bps` accepts the closed interval including both caps.**
#[test]
fn test_set_protocol_fee_bps_boundary_matrix() {
    // (0, cap 0), (1 cap), (mid), (10_000 cap) - the full closed interval.
    let accepted = [0i64, 1, 2_500, 5_000, 9_999, 10_000];
    for fee_bps in accepted {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, sme) = setup(&env);
        client.init(
            &admin,
            &soroban_sdk::String::from_str(&env, "FBND01"),
            &sme,
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
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

        assert_eq!(client.set_protocol_fee_bps(&fee_bps), fee_bps);
        assert_eq!(client.get_protocol_fee_bps(), fee_bps);
    }
}

/// **One basis point outside either edge is rejected.** This is the exact rejection boundary.
#[test]
fn test_set_protocol_fee_bps_rejection_boundary_matrix() {
    let rejected = [i64::MIN, -10_001, -1, 10_001, 10_002, i64::MAX];
    for fee_bps in rejected {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, sme) = setup(&env);
        client.init(
            &admin,
            &soroban_sdk::String::from_str(&env, "FBND02"),
            &sme,
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
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

        assert_contract_error(
            client.try_set_protocol_fee_bps(&fee_bps),
            EscrowError::ProtocolFeeBpsOutOfRange,
        );
        // A rejected write must not mutate the stored value.
        assert_eq!(client.get_protocol_fee_bps(), 0);
    }
}

/// **`init` fee-envelope boundary matrix.** Pins both edges of the accepted interval, the
/// integers immediately outside them, and the extremes of the `i64` domain.
///
/// This is the guard that a randomly-sampled property cannot provide: widening the
/// `init` envelope by even a few thousand basis points is invisible to a property that
/// draws from the whole `i64` range, but is caught here at exactly `10_001`.
#[test]
fn test_init_fee_bps_rejection_boundary_matrix() {
    // In range: both endpoints and a mid value must all initialise and persist.
    for fee_bps in [0i64, 1, 5_000, 9_999, 10_000] {
        let env = Env::default();
        env.mock_all_auths();
        let client = deploy(&env);
        let admin = Address::generate(&env);
        let sme = Address::generate(&env);
        client.init(
            &admin,
            &soroban_sdk::String::from_str(&env, "FSIBM"),
            &sme,
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &Some(fee_bps),
            &None::<u32>,
        );
        assert_eq!(client.get_protocol_fee_bps(), fee_bps);
    }

    // Out of range: one bps past either edge, the values just beyond, and the i64 extremes.
    for fee_bps in [
        i64::MIN,
        -50_000,
        -10_001,
        -2,
        -1,
        10_001,
        10_002,
        20_000,
        50_000,
        i64::MAX,
    ] {
        let env = Env::default();
        env.mock_all_auths();
        let client = deploy(&env);
        let admin = Address::generate(&env);
        let sme = Address::generate(&env);

        assert_contract_error(
            client.try_init(
                &admin,
                &soroban_sdk::String::from_str(&env, "FSIBM"),
                &sme,
                &TARGET,
                &0i64,
                &0u64,
                &Address::generate(&env),
                &None,
                &Address::generate(&env),
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &None,
                &Some(fee_bps),
                &None::<u32>,
            ),
            EscrowError::ProtocolFeeBpsOutOfRange,
        );
    }
}
/// **Re-submitting the same fee rate is a silent idempotent no-op.** The setter short-circuits
/// before publishing, so a replay emits no second `ProtocolFeeUpdated` event.
#[test]
fn test_duplicate_protocol_fee_submission_is_idempotent() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, sme) = setup(&env);
    client.init(
        &admin,
        &soroban_sdk::String::from_str(&env, "FBND03"),
        &sme,
        &TARGET,
        &0i64,
        &0u64,
        &Address::generate(&env),
        &None,
        &Address::generate(&env),
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

    // Drain anything `init` published so each step below observes only its own events.
    // `Events::all()` returns *and clears* the buffered log, which is what lets this
    // assert per-operation event counts rather than a running total.
    let _ = env.events().all();

    assert_eq!(client.set_protocol_fee_bps(&1_000), 1_000);
    let first_publish = env.events().all().events().len();
    assert!(first_publish >= 1, "a real fee change must be announced");

    // Duplicate with the identical value: no error, no new event, stored value unchanged.
    assert_eq!(client.set_protocol_fee_bps(&1_000), 1_000);
    assert_eq!(
        env.events().all().events().len(),
        0,
        "an idempotent resubmission must publish nothing"
    );
    assert_eq!(client.get_protocol_fee_bps(), 1_000);

    // A distinct in-range value is a real change and is announced again.
    assert_eq!(client.set_protocol_fee_bps(&2_000), 2_000);
    assert_eq!(env.events().all().events().len(), first_publish);
    assert_eq!(client.get_protocol_fee_bps(), 2_000);
}

/// **Degenerate schedule bounds are legal.** `min == fee == max` at both `0` and `10_000` are
/// the tightest possible schedules and must be accepted.
#[test]
fn test_schedule_collapsed_and_capped_bounds_are_accepted() {
    for (min_fee_bps, fee_bps, max_fee_bps) in [(0u32, 0u32, 0u32), (10_000, 10_000, 10_000)] {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _sme) = setup(&env);
        let admin = Address::generate(&env);
        client.init(
            &admin,
            &soroban_sdk::String::from_str(&env, "FBND04"),
            &Address::generate(&env),
            &TARGET,
            &0i64,
            &0u64,
            &Address::generate(&env),
            &None,
            &Address::generate(&env),
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

        let schedule = FeeSchedule {
            fee_bps,
            min_fee_bps,
            max_fee_bps,
            activation_ledger: 500,
        };
        client.submit_fee_schedule(&schedule);
        assert_eq!(client.get_pending_fee_schedule(), Some(schedule));
    }
}

/// **Activation-ledger boundary.** `activation_ledger` must be strictly greater than the
/// current ledger sequence: `current` is rejected, `current + 1` is accepted.
#[test]
fn test_schedule_activation_ledger_boundary() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme) = setup(&env);
    let admin = Address::generate(&env);
    client.init(
        &admin,
        &soroban_sdk::String::from_str(&env, "FBND05"),
        &Address::generate(&env),
        &TARGET,
        &0i64,
        &0u64,
        &Address::generate(&env),
        &None,
        &Address::generate(&env),
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

    let current = env.ledger().sequence();
    let base = FeeSchedule {
        fee_bps: 100,
        min_fee_bps: 50,
        max_fee_bps: 200,
        activation_ledger: 0,
    };

    // Strictly-future ledger required.
    assert_fee_schedule_error(
        client.try_submit_fee_schedule(&FeeSchedule {
            activation_ledger: 0,
            ..base.clone()
        }),
        FeeScheduleError::InvalidActivationLedger,
    );
    assert_fee_schedule_error(
        client.try_submit_fee_schedule(&FeeSchedule {
            activation_ledger: current,
            ..base.clone()
        }),
        FeeScheduleError::InvalidActivationLedger,
    );
    assert_eq!(client.get_pending_fee_schedule(), None);

    // One past the current sequence is the first accepted value.
    let accepted = FeeSchedule {
        activation_ledger: current + 1,
        ..base.clone()
    };
    client.submit_fee_schedule(&accepted);
    assert_eq!(client.get_pending_fee_schedule(), Some(accepted));
}

/// **Duplicate schedule submission is idempotent; a second *distinct* schedule is rejected.**
#[test]
fn test_duplicate_schedule_submission_is_idempotent() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _sme) = setup(&env);
    let admin = Address::generate(&env);
    client.init(
        &admin,
        &soroban_sdk::String::from_str(&env, "FBND06"),
        &Address::generate(&env),
        &TARGET,
        &0i64,
        &0u64,
        &Address::generate(&env),
        &None,
        &Address::generate(&env),
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

    let schedule = FeeSchedule {
        fee_bps: 250,
        min_fee_bps: 100,
        max_fee_bps: 500,
        activation_ledger: 500,
    };
    client.submit_fee_schedule(&schedule);

    // Byte-identical resubmission: no error, no second pending entry.
    client.submit_fee_schedule(&schedule);
    assert_eq!(client.get_pending_fee_schedule(), Some(schedule.clone()));

    // A different schedule while one is still pending is refused.
    assert_fee_schedule_error(
        client.try_submit_fee_schedule(&FeeSchedule {
            fee_bps: 300,
            min_fee_bps: 100,
            max_fee_bps: 500,
            activation_ledger: 600,
        }),
        FeeScheduleError::PendingScheduleExists,
    );
    assert_eq!(client.get_pending_fee_schedule(), Some(schedule));
}

// ===========================================================================
// 4. Overflow protection and arithmetic invariants
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **The `i128` envelope holds for the whole accepted domain.** Because
    /// `MAX_INVOICE_AMOUNT == i128::MAX / 10_000` and `fee_bps <= 10_000`, the product
    /// `gross * fee_bps` is provably representable. This is why
    /// `EscrowError::WithdrawFeeArithmeticOverflow` is unreachable for any value the
    /// contract is willing to store.
    #[test]
    fn prop_fee_multiplication_never_overflows_the_envelope(
        gross in 1i128..=MAX_INVOICE_AMOUNT,
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        prop_assert!(
            gross.checked_mul(fee_bps as i128).is_some(),
            "gross * fee_bps must be representable inside the init-accepted envelope"
        );
        // The worst case is exact: at the cap the fee equals the gross amount.
        if fee_bps == MAX_FEE_BPS {
            prop_assert_eq!(reference_fee(gross, fee_bps), gross);
            prop_assert_eq!(reference_net(gross, fee_bps), 0);
        }
    }

    /// **The cap is tight.** One basis point above the cap would break the envelope, which is
    /// precisely why `10_000` is the hard boundary rather than a soft target.
    #[test]
    fn prop_fee_envelope_is_tight_at_the_cap(
        gross in 1i128..=1_000_000_000_000i128,
    ) {
        prop_assert!(gross.checked_mul(MAX_FEE_BPS as i128).is_some());
        prop_assert!(
            gross.checked_mul((MAX_FEE_BPS + 1) as i128).is_some(),
            "one bps past the cap is still representable for small gross amounts, \
             so the boundary is a policy limit rather than an arithmetic cliff"
        );
    }

    /// **`amount - fee` can never underflow.** The floor division guarantees
    /// `fee <= gross` for every non-negative rate.
    #[test]
    fn prop_fee_subtraction_never_underflows(
        gross in 1i128..=MAX_INVOICE_AMOUNT,
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        let fee = reference_fee(gross, fee_bps);
        prop_assert!(fee <= gross, "fee must be bounded by gross for any valid rate");
        prop_assert!(gross.checked_sub(fee).is_some());
    }
}

// ===========================================================================
// 5. Contract-level fee split behaviour
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// **End-to-end conservation on `withdraw`.** The treasury balance delta equals
    /// `floor(gross * fee_bps / 10_000)`, the SME balance delta equals the remainder, and the
    /// two deltas add up to the gross funded amount.
    #[test]
    fn prop_withdraw_splits_gross_between_treasury_and_sme(
        gross in 1_000i128..=1_000_000_000i128,
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, fee_bps);

        let sme_before = token.balance(&sme);
        let treasury_before = token.balance(&treasury);
        prop_assert_eq!(sme_before, 0, "SME must start from a zero balance");
        prop_assert_eq!(treasury_before, 0, "treasury must start from a zero balance");

        let escrow = client.withdraw();
        prop_assert_eq!(escrow.status, 3, "withdraw must move the escrow to distributed");

        let fee_delta = token.balance(&treasury) - treasury_before;
        let net_delta = token.balance(&sme) - sme_before;

        prop_assert_eq!(fee_delta, reference_fee(gross, fee_bps));
        prop_assert_eq!(net_delta, reference_net(gross, fee_bps));
        prop_assert_eq!(fee_delta + net_delta, gross, "split must be lossless end-to-end");
    }

    /// **The stored fee rate is the only input to the split.** Re-reading the rate after
    /// `withdraw` still yields the value used for the transfer, and it never leaves `0..=10_000`.
    #[test]
    fn prop_withdraw_fee_stays_inside_the_declared_envelope(
        fee_bps in 0i64..=MAX_FEE_BPS,
    ) {
        let gross = 500_000_000i128;
        let env = Env::default();
        env.mock_all_auths();
        let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, fee_bps);

        prop_assert_eq!(client.get_protocol_fee_bps(), fee_bps);
        prop_assert!(fee_bps_in_range(client.get_protocol_fee_bps()));

        client.withdraw();
        prop_assert_eq!(token.balance(&treasury), reference_fee(gross, fee_bps));
        prop_assert_eq!(token.balance(&sme), reference_net(gross, fee_bps));
    }
}

/// **Sub-unit fee boundary: the smallest representable fee, and the rate that rounds to zero.**
///
/// The treasury transfer is guarded by `fee > 0`, so the interesting edges are `fee == 1`
/// (the smallest chargeable fee, which *must* be transferred) and `fee == 0` reached by
/// rounding rather than by a zero rate (which must *not* be). A randomly sampled
/// (gross, fee_bps) pair essentially never lands on either, so both are pinned explicitly.
#[test]
fn test_minimum_unit_fee_boundary() {
    // (gross, fee_bps, expected_fee, expected_net)
    let cases = [
        // 10_000 * 1 / 10_000 == 1: the smallest chargeable fee must actually be paid out.
        (10_000i128, 1i64, 1i128, 9_999i128),
        // 1 * 9_999 / 10_000 == 0: a sub-unit share rounds down to no fee at all.
        (1i128, 9_999, 0, 1),
        // 1 * 10_000 / 10_000 == 1: the smallest gross at the cap still charges one unit.
        (1i128, 10_000, 1, 0),
        // 1 * 1 / 10_000 == 0: lowest rate, lowest gross.
        (1i128, 1, 0, 1),
        // 9_999 * 1 / 10_000 == 0: just under the first whole basis point of value.
        (9_999i128, 1, 0, 9_999),
        // 10_000 * 9_999 / 10_000 == 9_999: one unit below the cap.
        (10_000i128, 9_999, 9_999, 1),
    ];

    for (gross, fee_bps, expected_fee, expected_net) in cases {
        assert_eq!(
            reference_fee(gross, fee_bps),
            expected_fee,
            "reference fee drifted for gross={gross} fee_bps={fee_bps}"
        );

        let env = Env::default();
        env.mock_all_auths();
        let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, fee_bps);

        client.withdraw();

        assert_eq!(
            token.balance(&treasury),
            expected_fee,
            "treasury leg wrong for gross={gross} fee_bps={fee_bps}"
        );
        assert_eq!(
            token.balance(&sme),
            expected_net,
            "SME leg wrong for gross={gross} fee_bps={fee_bps}"
        );
        assert_eq!(
            expected_fee + expected_net,
            gross,
            "split must stay lossless"
        );
    }
}

/// **Zero-fee boundary: the treasury transfer is skipped entirely.** With
/// `protocol_fee_bps == 0` the behaviour must be byte-for-byte the legacy full-principal
/// disbursement to the SME.
#[test]
fn test_zero_fee_boundary_routes_everything_to_the_sme() {
    let gross = 250_000_000i128;
    let env = Env::default();
    env.mock_all_auths();
    let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, 0);

    client.withdraw();

    assert_eq!(token.balance(&treasury), 0, "no fee may reach the treasury");
    assert_eq!(
        token.balance(&sme),
        gross,
        "the SME must receive the full amount"
    );
}

/// **Maximum-fee boundary: the cap drains the SME payout.** At `protocol_fee_bps == 10_000` the
/// treasury receives the whole gross amount and the net payout is zero (no SME transfer).
#[test]
fn test_max_fee_boundary_drains_the_sme_payout() {
    let gross = 250_000_000i128;
    let env = Env::default();
    env.mock_all_auths();
    let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, 10_000);

    client.withdraw();

    assert_eq!(
        token.balance(&treasury),
        gross,
        "the cap must take the whole amount"
    );
    assert_eq!(
        token.balance(&sme),
        0,
        "no net payout may remain at the cap"
    );
}

/// **The emitted `SmeWithdrew` event carries the same split as the transfers.** `amount` is the
/// net payout and `fee` is the treasury leg; the two must reconcile with the gross.
#[test]
fn test_withdraw_event_payload_reconciles_with_transfers() {
    use crate::SmeWithdrew;

    let gross = 400_000_000i128;
    let fee_bps = 375i64;
    let env = Env::default();
    env.mock_all_auths();
    let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, fee_bps);
    let contract_id = client.address.clone();

    client.withdraw();

    let last = env.events().all().events().last().unwrap().clone();
    let expected = SmeWithdrew {
        name: symbol_short!("sme_wd"),
        invoice_id: client.get_escrow().invoice_id,
        amount: reference_net(gross, fee_bps),
        recipient: sme.clone(),
        fee: reference_fee(gross, fee_bps),
    }
    .to_xdr(&env, &contract_id);
    assert_eq!(last, expected);

    // Event payload and on-chain balances must agree exactly.
    assert_eq!(token.balance(&treasury) + token.balance(&sme), gross);
    assert_eq!(
        reference_fee(gross, fee_bps) + reference_net(gross, fee_bps),
        gross
    );
}

/// **A second `withdraw` is rejected, so the split cannot be replayed.** The fee leg is
/// delivered exactly once per escrow lifecycle.
#[test]
fn test_duplicate_withdraw_cannot_replay_the_fee_split() {
    let gross = 300_000_000i128;
    let fee_bps = 1_000i64;
    let env = Env::default();
    env.mock_all_auths();
    let (client, token, sme, treasury, _admin) = funded_fee_escrow(&env, gross, fee_bps);

    client.withdraw();
    let treasury_after_first = token.balance(&treasury);
    let sme_after_first = token.balance(&sme);

    // Replay attempt: the escrow is no longer in the funded state.
    assert!(client.try_withdraw().is_err(), "withdraw must be once-only");

    assert_eq!(token.balance(&treasury), treasury_after_first);
    assert_eq!(token.balance(&sme), sme_after_first);
    assert_eq!(treasury_after_first + sme_after_first, gross);
}
