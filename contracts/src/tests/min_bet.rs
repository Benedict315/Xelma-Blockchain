// SPDX-License-Identifier: MIT
//! Tests for minimum-bet / dust protection (Issue #269).

use crate::contract::{VirtualTokenContract, VirtualTokenContractClient};
use crate::errors::ContractError;
use crate::types::BetSide;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Env,
};

fn setup(env: &Env) -> (VirtualTokenContractClient<'_>, Address, Address) {
    let contract_id = env.register(VirtualTokenContract, ());
    let client = VirtualTokenContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let oracle = Address::generate(env);

    env.mock_all_auths();
    client.initialize(&admin, &oracle);
    (client, admin, oracle)
}

fn schedule_and_apply_min_bet(env: &Env, client: &VirtualTokenContractClient, min: Option<i128>) {
    use crate::types::ConfigChangeKind;
    client.set_min_bet(&min);
    env.ledger().with_mut(|li| {
        li.sequence_number += crate::common::CONFIG_TIMELOCK_LEDGERS + 1;
    });
    client.apply_scheduled_changes(&ConfigChangeKind::MinBet);
}

#[test]
fn test_min_bet_disabled_by_default_accepts_any_positive_amount() {
    let env = Env::default();
    let (client, _admin, _oracle) = setup(&env);
    let user = Address::generate(&env);
    client.mint_initial(&user);
    client.create_round(&1_0000000, &None);

    assert_eq!(client.get_min_bet(), None);
    // 1 stroop bet accepted — pre-#269 behaviour preserved.
    client.place_bet(&user, &1, &BetSide::Up);
}

#[test]
fn test_min_bet_below_threshold_rejected_on_place_bet() {
    let env = Env::default();
    let (client, _admin, _oracle) = setup(&env);
    let user = Address::generate(&env);
    client.mint_initial(&user);

    schedule_and_apply_min_bet(&env, &client, Some(100));
    assert_eq!(client.get_min_bet(), Some(100));
    client.create_round(&1_0000000, &None);

    let result = client.try_place_bet(&user, &99, &BetSide::Up);
    assert_eq!(result, Err(Ok(ContractError::BelowMinBet)));

    // Exactly at the threshold is accepted.
    client.place_bet(&user, &100, &BetSide::Up);
}

#[test]
fn test_min_bet_below_threshold_rejected_on_precision_prediction() {
    let env = Env::default();
    let (client, _admin, _oracle) = setup(&env);
    let user = Address::generate(&env);
    client.mint_initial(&user);

    schedule_and_apply_min_bet(&env, &client, Some(500));
    client.create_round(&1_0000000, &Some(1u32));

    let result = client.try_place_precision_prediction(&user, &499, &2297);
    assert_eq!(result, Err(Ok(ContractError::BelowMinBet)));

    client.place_precision_prediction(&user, &500, &2297);
}

#[test]
fn test_min_bet_below_threshold_rejected_on_commit_prediction() {
    let env = Env::default();
    let (client, _admin, _oracle) = setup(&env);
    let user = Address::generate(&env);
    client.mint_initial(&user);

    schedule_and_apply_min_bet(&env, &client, Some(500));
    client.create_round(&1_0000000, &Some(1u32));

    let hash = soroban_sdk::BytesN::from_array(&env, &[7u8; 32]);
    let result = client.try_commit_prediction(&user, &hash, &499);
    assert_eq!(result, Err(Ok(ContractError::BelowMinBet)));

    client.commit_prediction(&user, &hash, &500);
}

#[test]
fn test_min_bet_disabled_after_being_cleared() {
    let env = Env::default();
    let (client, _admin, _oracle) = setup(&env);
    let user = Address::generate(&env);
    client.mint_initial(&user);

    schedule_and_apply_min_bet(&env, &client, Some(1000));
    client.create_round(&1_0000000, &None);
    let rejected = client.try_place_bet(&user, &1, &BetSide::Up);
    assert_eq!(rejected, Err(Ok(ContractError::BelowMinBet)));
    client.cancel_round(&0u32);

    schedule_and_apply_min_bet(&env, &client, None);
    assert_eq!(client.get_min_bet(), None);
    client.create_round(&1_0000000, &None);
    client.place_bet(&user, &1, &BetSide::Up);
}

#[test]
fn test_set_min_bet_rejects_non_positive_value() {
    let env = Env::default();
    let (client, _admin, _oracle) = setup(&env);

    let result = client.try_set_min_bet(&Some(0));
    assert_eq!(result, Err(Ok(ContractError::InvalidBetAmount)));

    let result = client.try_set_min_bet(&Some(-1));
    assert_eq!(result, Err(Ok(ContractError::InvalidBetAmount)));
}
