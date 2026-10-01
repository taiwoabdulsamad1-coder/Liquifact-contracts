//! Boundary regressions for the SME collateral metadata state machine.
//!
//! A rejected or unauthorized operation must preserve the prior pledge. A successful
//! clear removes exactly the stored pledge and emits its immutable snapshot.

use super::{assert_contract_error, default_init, deploy_with_id, setup};
use crate::{CollateralClearedEvt, CollateralRecordedEvt, EscrowError};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _, Ledger as _},
    Address, Env, Symbol,
};

#[test]
fn record_and_same_timestamp_retries_preserve_replacement_invariant() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, client) = deploy_with_id(&env);
    let admin = Address::generate(&env);
    let sme = Address::generate(&env);
    default_init(&client, &env, &admin, &sme);
    let invoice_id = client.get_escrow().invoice_id;
    let timestamp = 20_000;
    env.ledger().set_timestamp(timestamp);

    let first_asset = Symbol::new(&env, "USDC");
    let first = client.record_sme_collateral_commitment(&first_asset, &100i128);
    assert_eq!(first.asset, first_asset);
    assert_eq!(first.amount, 100);
    assert_eq!(first.recorded_at, timestamp);

    let replacement_asset = Symbol::new(&env, "BTC");
    let replacement = client.record_sme_collateral_commitment(&replacement_asset, &250i128);
    assert_eq!(replacement.asset, replacement_asset);
    assert_eq!(replacement.amount, 250);
    assert_eq!(replacement.recorded_at, timestamp);
    assert_eq!(
        env.events().all().filter_by_contract(&contract_id).events()[0],
        CollateralRecordedEvt {
            name: symbol_short!("coll_rec"),
            invoice_id: invoice_id.clone(),
            amount: 250,
            prior_amount: 100,
        }
        .to_xdr(&env, &contract_id)
    );

    let retry = client.record_sme_collateral_commitment(&replacement_asset, &250i128);
    assert_eq!(retry, replacement);
    assert_eq!(
        env.events().all().filter_by_contract(&contract_id).events()[0],
        CollateralRecordedEvt {
            name: symbol_short!("coll_rec"),
            invoice_id,
            amount: 250,
            prior_amount: 250,
        }
        .to_xdr(&env, &contract_id)
    );
    assert_eq!(client.get_sme_collateral_commitment(), Some(retry));
}

#[test]
fn rejected_record_boundaries_leave_existing_pledge_unchanged() {
    let env = Env::default();
    let (client, admin, sme) = setup(&env);
    default_init(&client, &env, &admin, &sme);
    let asset = Symbol::new(&env, "GOLD");
    env.ledger().set_timestamp(5_000);
    let original = client.record_sme_collateral_commitment(&asset, &500i128);

    assert_contract_error(
        client.try_record_sme_collateral_commitment(&asset, &0i128),
        EscrowError::CollateralAmountNotPositive,
    );
    assert_eq!(client.get_sme_collateral_commitment(), Some(original.clone()));

    assert_contract_error(
        client.try_record_sme_collateral_commitment(&Symbol::new(&env, ""), &1i128),
        EscrowError::CollateralAssetEmpty,
    );
    assert_eq!(client.get_sme_collateral_commitment(), Some(original.clone()));

    env.ledger().set_timestamp(4_999);
    assert_contract_error(
        client.try_record_sme_collateral_commitment(&asset, &600i128),
        EscrowError::CollateralTimestampBackwards,
    );
    assert_eq!(client.get_sme_collateral_commitment(), Some(original));
}

#[test]
fn unauthorized_record_and_clear_leave_pledge_unchanged() {
    let env = Env::default();
    let (client, admin, sme) = setup(&env);
    default_init(&client, &env, &admin, &sme);
    let asset = Symbol::new(&env, "XLM");
    let original = client.record_sme_collateral_commitment(&asset, &700i128);

    env.mock_auths(&[]);
    assert!(client
        .try_record_sme_collateral_commitment(&asset, &800i128)
        .is_err());
    assert_eq!(client.get_sme_collateral_commitment(), Some(original.clone()));

    assert!(client.try_clear_sme_collateral_commitment().is_err());
    assert_eq!(client.get_sme_collateral_commitment(), Some(original));
}

#[test]
fn clear_emits_removed_snapshot_and_rejects_duplicate_clear() {
    let env = Env::default();
    env.mock_all_auths();
    let (contract_id, client) = deploy_with_id(&env);
    let admin = Address::generate(&env);
    let sme = Address::generate(&env);
    default_init(&client, &env, &admin, &sme);
    let invoice_id = client.get_escrow().invoice_id;
    let asset = Symbol::new(&env, "ETH");
    env.ledger().set_timestamp(30_000);
    let pledge = client.record_sme_collateral_commitment(&asset, &900i128);

    client.clear_sme_collateral_commitment();
    assert_eq!(
        env.events().all().filter_by_contract(&contract_id).events()[0],
        CollateralClearedEvt {
            name: symbol_short!("coll_clr"),
            invoice_id,
            asset: pledge.asset,
            amount: pledge.amount,
            recorded_at: pledge.recorded_at,
        }
        .to_xdr(&env, &contract_id)
    );
    assert!(client.get_sme_collateral_commitment().is_none());

    assert_contract_error(
        client.try_clear_sme_collateral_commitment(),
        EscrowError::NoCollateralToClear,
    );
    assert!(client.get_sme_collateral_commitment().is_none());
}