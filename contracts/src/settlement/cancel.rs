// SPDX-License-Identifier: MIT
//! Cancel module for emergency round cancellation and refunds.

use soroban_sdk::{symbol_short, Address, Env, Vec};

use crate::errors::ContractError;
use crate::types::{
    BetSide, DataKey, PrecisionCommitment, PrecisionPrediction, Round, RoundArchiveStatus,
    RoundMode, UserOutcomeType, UserPosition,
};

/// Cancels the active round and deterministically refunds all participant stakes.
///
/// Only admin may cancel. Intended for oracle-unavailable or emergency recovery
/// scenarios. After cancellation:
///  - All participant stakes are moved to their pending winnings.
///  - The active round is removed; no future settlement is possible.
///  - The round ID is marked cancelled to prevent any replay.
pub fn cancel_round(
    env: &Env,
    reason: u32,
    get_admin: impl Fn(&Env) -> Option<Address>,
    require_supported_schema: impl Fn(&Env) -> Result<(), ContractError>,
    accumulate_pending: impl Fn(&Env, Address, i128) -> Result<(), ContractError>,
    persist_user_outcome: impl Fn(
        &Env,
        u64,
        u32,
        &Address,
        u32,
        u128,
        i128,
        i128,
        UserOutcomeType,
    ),
    archive_round: impl Fn(&Env, &Round, RoundArchiveStatus, u128, u32),
) -> Result<(), ContractError> {
    require_supported_schema(env)?;
    let admin: Address = get_admin(env).ok_or(ContractError::AdminNotSet)?;
    admin.require_auth();

    let round: Round = env
        .storage()
        .persistent()
        .get(&DataKey::ActiveRound)
        .ok_or(ContractError::RoundNotCancellable)?;

    let round_id = round.round_id;

    // Refund all participants based on round mode
    let participants: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::RoundParticipants(round_id))
        .unwrap_or(Vec::new(env));

    match round.mode {
        RoundMode::UpDown => {
            for i in 0..participants.len() {
                if let Some(user) = participants.get(i) {
                    let pos_key = DataKey::Position(round_id, user.clone());
                    if let Some(pos) = env.storage().persistent().get::<_, UserPosition>(&pos_key) {
                        accumulate_pending(env, user.clone(), pos.amount)?;
                        let prediction_side = match pos.side {
                            BetSide::Up => 0,
                            BetSide::Down => 1,
                        };
                        persist_user_outcome(
                            env,
                            round_id,
                            0,
                            &user,
                            prediction_side,
                            0,
                            pos.amount,
                            pos.amount,
                            UserOutcomeType::Cancel,
                        );
                        env.storage().persistent().remove(&pos_key);
                    }
                }
            }
        }
        RoundMode::Precision => {
            for i in 0..participants.len() {
                if let Some(user) = participants.get(i) {
                    let pred_key = DataKey::PrecisionPosition(round_id, user.clone());
                    let commit_key = DataKey::PrecisionCommitment(round_id, user.clone());

                    let mut refund_amount = 0;
                    if let Some(pred) = env
                        .storage()
                        .persistent()
                        .get::<_, PrecisionPrediction>(&pred_key)
                    {
                        refund_amount = pred.amount;
                    } else if let Some(commit) = env
                        .storage()
                        .persistent()
                        .get::<_, PrecisionCommitment>(&commit_key)
                    {
                        refund_amount = commit.amount;
                    }

                    if refund_amount > 0 {
                        accumulate_pending(env, user.clone(), refund_amount)?;
                    }
                    persist_user_outcome(
                        env,
                        round_id,
                        1,
                        &user,
                        2,
                        0,
                        refund_amount,
                        refund_amount,
                        UserOutcomeType::Cancel,
                    );
                    env.storage().persistent().remove(&pred_key);
                    env.storage().persistent().remove(&commit_key);
                }
            }
        }
    }

    // Clean up participant list and mark round as cancelled
    let participant_count = participants.len();
    archive_round(
        env,
        &round,
        RoundArchiveStatus::Cancelled,
        0,
        participant_count,
    );

    env.storage()
        .persistent()
        .remove(&DataKey::RoundParticipants(round_id));
    env.storage()
        .persistent()
        .set(&DataKey::CancelledRound(round_id), &true);
    env.storage().persistent().remove(&DataKey::ActiveRound);

    // Emit cancellation event
    // Topic: ("round", "cancelled")
    // Payload: (round_id: u64, reason: u32, pool_up: i128, pool_down: i128)
    #[allow(deprecated)]
    env.events().publish(
        (symbol_short!("round"), symbol_short!("cancel")),
        (round_id, reason, round.pool_up, round.pool_down),
    );

    Ok(())
}
