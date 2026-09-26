// SPDX-License-Identifier: MIT
//! Resolve module for oracle-based round resolution and payout distribution.

use soroban_sdk::{symbol_short, Address, Env, Vec};

use crate::errors::ContractError;
use crate::types::{DataKey, OraclePayload, Round, RoundArchiveStatus, RoundMode};

/// Resolves the round with oracle payload (oracle only)
/// Mode 0 (Up/Down): Winners split losers' pool proportionally; ties get refunds
/// Mode 1 (Precision/Legends): Closest guess wins full pot; ties split evenly
pub fn resolve_round(
    env: &Env,
    payload: OraclePayload,
    require_supported_schema: impl Fn(&Env) -> Result<(), ContractError>,
    get_oracle: impl Fn(&Env) -> Option<Address>,
    ensure_not_paused: impl Fn(&Env) -> Result<(), ContractError>,
    extend_persistent_ttl: impl Fn(&Env, &DataKey),
    archive_round: impl Fn(&Env, &Round, RoundArchiveStatus, u128, u32),
    refund_under_threshold: impl Fn(&Env, &Round, &Vec<Address>) -> Result<(), ContractError>,
    resolve_updown_mode: impl Fn(&Env, &Round, u128) -> Result<bool, ContractError>,
    resolve_precision_mode: impl Fn(&Env, u64, u128) -> Result<(), ContractError>,
) -> Result<(), ContractError> {
    require_supported_schema(env)?;
    if payload.price == 0 {
        return Err(ContractError::InvalidPrice);
    }

    extend_persistent_ttl(env, &DataKey::Oracle);
    let oracle: Address = get_oracle(env).ok_or(ContractError::OracleNotSet)?;

    oracle.require_auth();
    ensure_not_paused(env)?;

    let round: Round = env
        .storage()
        .persistent()
        .get(&DataKey::ActiveRound)
        .ok_or(ContractError::NoActiveRound)?;

    // Verify round ID matches to prevent cross-round replays
    if payload.round_id != round.start_ledger {
        return Err(ContractError::InvalidOracleRound);
    }

    // ─── Domain-context validation (Issue #143) ─────────────────────────
    // Reject payloads targeting a different network or contract deployment.
    if payload.network_id != env.ledger().network_id() {
        return Err(ContractError::OracleNetworkMismatch);
    }
    if payload.contract_addr != env.current_contract_address() {
        return Err(ContractError::OracleContractMismatch);
    }

    // Verify data freshness (max 300 seconds / 5 minutes old)
    let current_time = env.ledger().timestamp();

    // Reject future timestamps to prevent time-skew manipulation
    if payload.timestamp > current_time {
        return Err(ContractError::FutureOracleData);
    }

    if current_time > payload.timestamp + 300 {
        return Err(ContractError::StaleOracleData);
    }

    // ─── Oracle deviation guardrails (circuit-breaker) ───────────────────
    // Compare settlement price against round start price (trusted baseline).
    // If configured, reject large jumps unless an admin-armed one-shot override is set.
    extend_persistent_ttl(env, &DataKey::OracleMaxDeviationBps);
    if let Some(max_bps) = env
        .storage()
        .persistent()
        .get::<_, u32>(&DataKey::OracleMaxDeviationBps)
    {
        let start_price = round.price_start;
        // start_price is validated at round creation; still guard division by zero.
        if start_price == 0 {
            return Err(ContractError::InvalidPrice);
        }

        let diff = if payload.price >= start_price {
            payload
                .price
                .checked_sub(start_price)
                .ok_or(ContractError::Overflow)?
        } else {
            start_price
                .checked_sub(payload.price)
                .ok_or(ContractError::Overflow)?
        };

        // Integer bps: floor(diff / start) * 10_000.
        // Use checked math so any u128 overflow maps to explicit errors.
        let diff_bps_u128 = diff
            .checked_mul(10_000u128)
            .ok_or(ContractError::Overflow)?
            / start_price;
        let diff_bps: u32 = diff_bps_u128
            .try_into()
            .map_err(|_| ContractError::Overflow)?;

        let override_armed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::OracleDeviationOverrideArmed)
            .unwrap_or(false);

        if diff_bps > max_bps && !override_armed {
            #[allow(deprecated)]
            env.events().publish(
                (symbol_short!("oracle"), symbol_short!("rejected")),
                (
                    round.round_id,
                    start_price,
                    payload.price,
                    diff_bps,
                    max_bps,
                ),
            );
            return Err(ContractError::OracleDeviationExceeded);
        }

        if diff_bps > max_bps && override_armed {
            // One-shot override is consumed on use.
            env.storage()
                .persistent()
                .remove(&DataKey::OracleDeviationOverrideArmed);

            #[allow(deprecated)]
            env.events().publish(
                (symbol_short!("oracle"), symbol_short!("override")),
                (
                    round.round_id,
                    start_price,
                    payload.price,
                    diff_bps,
                    max_bps,
                ),
            );
        }
    }

    // Per-round nonce replay guard (Issue #118).
    // Consume the nonce only after all validation passes so a rejected payload
    // doesn't permanently burn a nonce value.
    let nonce_key = DataKey::ConsumedOracleNonce(round.round_id, payload.nonce);
    if env.storage().persistent().has(&nonce_key) {
        return Err(ContractError::OracleNonceReused);
    }
    env.storage().persistent().set(&nonce_key, &true);

    // Verify round has reached end_ledger
    let current_ledger = env.ledger().sequence();
    if current_ledger < round.end_ledger {
        return Err(ContractError::RoundNotEnded);
    }

    // Store round ID before cleaning up
    let round_id = round.round_id;

    // ─── Minimum participants threshold check ────────────────────────────
    if let Some(min) = env
        .storage()
        .persistent()
        .get::<_, u32>(&DataKey::MinParticipants)
    {
        let threshold_participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round_id))
            .unwrap_or(Vec::new(env));
        let count = threshold_participants.len();
        if count < min {
            archive_round(
                env,
                &round,
                RoundArchiveStatus::FallbackRefund,
                payload.price,
                count,
            );
            refund_under_threshold(env, &round, &threshold_participants)?;
            #[allow(deprecated)]
            env.events().publish(
                (symbol_short!("round"), symbol_short!("fallback")),
                (round_id, count, min),
            );
            return Ok(());
        }
    }

    // Branch based on round mode
    match round.mode {
        RoundMode::UpDown => {
            let one_sided = resolve_updown_mode(env, &round, payload.price)?;
            if one_sided {
                // Emit here (public scope, env: Env) so the event is captured in tests.
                #[allow(deprecated)]
                env.events().publish(
                    (symbol_short!("pool"), symbol_short!("onesided")),
                    (round_id, round.pool_up, round.pool_down),
                );
            }
        }
        RoundMode::Precision => {
            resolve_precision_mode(env, round_id, payload.price)?;
        }
    }

    // Clean up indexed position keys and participant list
    let participants: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::RoundParticipants(round_id))
        .unwrap_or(Vec::new(env));
    let participant_count = participants.len();

    archive_round(
        env,
        &round,
        RoundArchiveStatus::Resolved,
        payload.price,
        participant_count,
    );

    for i in 0..participants.len() {
        if let Some(user) = participants.get(i) {
            env.storage()
                .persistent()
                .remove(&DataKey::Position(round_id, user.clone()));
            env.storage()
                .persistent()
                .remove(&DataKey::PrecisionPosition(round_id, user.clone()));
            env.storage()
                .persistent()
                .remove(&DataKey::PrecisionCommitment(round_id, user));
        }
    }
    env.storage()
        .persistent()
        .remove(&DataKey::RoundParticipants(round_id));

    // Clean up legacy map keys if present (migration compat)
    env.storage().persistent().remove(&DataKey::ActiveRound);
    env.storage().persistent().remove(&DataKey::Positions);
    env.storage().persistent().remove(&DataKey::UpDownPositions);
    env.storage()
        .persistent()
        .remove(&DataKey::PrecisionPositions);

    // Emit resolution event with round ID, price, and mode
    // Topic: ("round", "resolved")
    // Payload: (round_id: u64, final_price: u128, mode: u32 where 0=UpDown, 1=Precision)
    let mode_value: u32 = match round.mode {
        RoundMode::UpDown => 0,
        RoundMode::Precision => 1,
    };
    #[allow(deprecated)]
    env.events().publish(
        (symbol_short!("round"), symbol_short!("resolved")),
        (round_id, payload.price, mode_value),
    );

    Ok(())
}
