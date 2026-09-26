// SPDX-License-Identifier: MIT
//! Archive module for persisting round summaries and enforcing FIFO retention.

use soroban_sdk::{symbol_short, Address, Env, Vec};

use crate::types::{
    ArchivedRoundSummary, DataKey, Round, RoundArchiveStatus, UserOutcomeType, UserRoundOutcome,
};

/// Default archived round summaries retained on-chain (FIFO pruning).
pub const DEFAULT_ARCHIVE_RETENTION: u32 = 128;

/// Persists a compact round summary and enforces FIFO archive retention.
pub fn archive_round(
    env: &Env,
    round: &Round,
    status: RoundArchiveStatus,
    final_price: u128,
    participant_count: u32,
    default_archive_retention: u32,
) {
    let summary = ArchivedRoundSummary {
        round_id: round.round_id,
        price_start: round.price_start,
        price_final: final_price,
        mode: round.mode.clone(),
        status,
        pool_up: round.pool_up,
        pool_down: round.pool_down,
        participant_count,
        settled_at_ledger: env.ledger().sequence(),
    };

    env.storage()
        .persistent()
        .set(&DataKey::ArchivedRound(round.round_id), &summary);

    let mut recent: Vec<u64> = env
        .storage()
        .persistent()
        .get(&DataKey::RecentArchivedRoundIds)
        .unwrap_or(Vec::new(env));

    recent.push_back(round.round_id);

    let retention_limit: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::ArchiveRetention)
        .unwrap_or(default_archive_retention);

    while recent.len() > retention_limit {
        if let Some(oldest) = recent.get(0) {
            env.storage()
                .persistent()
                .remove(&DataKey::ArchivedRound(oldest));

            #[allow(deprecated)]
            env.events().publish(
                (symbol_short!("archive"), symbol_short!("pruned")),
                (oldest, retention_limit),
            );
        }
        let mut trimmed = Vec::new(env);
        for i in 1..recent.len() {
            if let Some(id) = recent.get(i) {
                trimmed.push_back(id);
            }
        }
        recent = trimmed;
    }

    env.storage()
        .persistent()
        .set(&DataKey::RecentArchivedRoundIds, &recent);
}

/// Persists a user outcome record for historical queries.
/// Skips if a record already exists to prevent overwrites.
pub fn persist_user_outcome(
    env: &Env,
    round_id: u64,
    round_mode: u32,
    user: &Address,
    prediction_side: u32,
    predicted_price: u128,
    stake: i128,
    payout: i128,
    outcome: UserOutcomeType,
    extend_ttl: impl Fn(&Env, &DataKey),
) {
    let key = DataKey::UserRoundOutcome(round_id, user.clone());
    if env.storage().persistent().has(&key) {
        return;
    }
    let record = UserRoundOutcome {
        user: user.clone(),
        round_mode,
        prediction_side,
        predicted_price,
        stake,
        payout,
        outcome,
    };
    env.storage().persistent().set(&key, &record);
    extend_ttl(env, &key);
}
