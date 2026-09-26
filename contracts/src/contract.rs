// SPDX-License-Identifier: MIT
//! Core contract implementation for the XLM Price Prediction Market.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, Address, Bytes, BytesN, Env, Map, Vec,
};

use crate::errors::ContractError;
use crate::settlement::{archive_round, cancel_round, resolve_round, DEFAULT_ARCHIVE_RETENTION};
use crate::types::{
    ArchivedRoundSummary, BetSide, ConfigChangeKind, ConfigChangePayload, DataKey,
    OracleHeartbeatRecord, OraclePayload, PendingConfigChange, PrecisionCommitment,
    PrecisionPrediction, ProtocolHealthStatus, Round, RoundArchiveStatus, RoundMode, RoundPhase,
    UserOutcomeType,
    UserPosition, UserRoundOutcome, UserStats,
};

// ─── Economic control limits ─────────────────────────────────────────────────
/// Minimum allowed value when setting an economic cap to prevent zero-value lockouts.
const MIN_CAP_VALUE: i128 = 1;
/// Upper bound on the minimum-participants config to prevent unbounded gas in resolution.
const MAX_MIN_PARTICIPANTS: u32 = 10_000;
const DEFAULT_MAX_PRECISION_PARTICIPANTS: u32 = 1_000;
const MAX_PRECISION_PARTICIPANTS_LIMIT: u32 = 10_000;
/// Maximum number of entries returned per page by paginated query methods,
/// regardless of the caller-requested `limit` (Issue #139).
const MAX_PAGE_SIZE: u32 = 100;

// ─── Oracle heartbeat limits ──────────────────────────────────────────────────
const DEFAULT_ORACLE_STALE_THRESHOLD: u64 = 3_600; // 1 hour
const MIN_ORACLE_STALE_THRESHOLD: u64 = 60; // 1 minute
const MAX_ORACLE_STALE_THRESHOLD: u64 = 86_400; // 24 hours

const DEFAULT_BET_WINDOW_LEDGERS: u32 = 6;
const DEFAULT_RUN_WINDOW_LEDGERS: u32 = 12;
const MAX_BET_WINDOW_LEDGERS: u32 = 1_440;
const MAX_RUN_WINDOW_LEDGERS: u32 = 2_880;

// ─── Oracle deviation guardrails ─────────────────────────────────────────────
/// Maximum allowed basis points for oracle deviation is bounded to avoid absurd configs.
/// 100_000 bp = 1000% deviation (effectively "off", but still explicit).
const MAX_ORACLE_DEVIATION_BPS: u32 = 100_000;

// ─── Protocol fee (Issue #162) ────────────────────────────────────────────────
/// Hard cap on the optional protocol settlement fee, in basis points
/// (1 bp = 0.01%). 1_000 bp = 10% of the round's total pot — the maximum an
/// admin may ever schedule via timelock. Larger values would risk turning
/// the protocol into a de-facto extraction mechanism and are explicitly
/// disallowed to preserve user trust and the conservation invariant.
const MAX_PROTOCOL_FEE_BPS: u32 = 1_000;
/// Denominator for bps math: `fee = total_pot * bps / BPS_DENOMINATOR`.
/// Pinned to 10_000 to match the universal "1 bp = 0.01%" convention.
const BPS_DENOMINATOR: i128 = 10_000;

// ─── Storage schema versioning ───────────────────────────────────────────────
const CURRENT_SCHEMA_VERSION: u32 = 3;
// ─── Start-price bounds (Issue #119) ─────────────────────────────────────────
/// Minimum start price in protocol units — prevents zero-value and dust rounds.
const MIN_START_PRICE: u128 = 1;
/// Maximum start price in protocol units — guards against overflow in payout math.
const MAX_START_PRICE: u128 = 1_000_000_000_000_000_000;
// ─── Storage TTL Lifecycle Limits (Issue #142) ──────────────────────────────
/// Minimum remaining ledgers before a persistent entry is extended.
const TTL_BUMP_THRESHOLD: u32 = 17_280; // ~1 day at 5-second ledgers
/// Amount of ledgers to extend a persistent entry to when below threshold.
const TTL_BUMP_AMOUNT: u32 = 518_400; // ~30 days at 5-second ledgers


/// Minimum archive retention limit — prevents accidental pruning of all history.
const MIN_ARCHIVE_RETENTION: u32 = 1;
/// Maximum archive retention limit — prevents unbounded storage growth.
const MAX_ARCHIVE_RETENTION: u32 = 10_000;
/// Ledgers to wait before a scheduled critical config change may be applied (~2 hours).
const CONFIG_TIMELOCK_LEDGERS: u32 = 1440;

#[contract]
pub struct VirtualTokenContract;

#[contractimpl]
impl VirtualTokenContract {
    /// Initializes the contract with admin and oracle addresses (one-time only)
    pub fn initialize(env: Env, admin: Address, oracle: Address) -> Result<(), ContractError> {
        admin.require_auth();

        if admin == oracle {
            return Err(ContractError::AdminIsOracle);
        }

        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Oracle, &oracle);
        env.storage().persistent().set(&DataKey::Paused, &false);
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion, &CURRENT_SCHEMA_VERSION);

        // Set default window values
        env.storage()
            .persistent()
            .set(&DataKey::BetWindowLedgers, &DEFAULT_BET_WINDOW_LEDGERS);
        env.storage()
            .persistent()
            .set(&DataKey::RunWindowLedgers, &DEFAULT_RUN_WINDOW_LEDGERS);

        Self::_extend_persistent_ttl(&env, &DataKey::Admin);
        Self::_extend_persistent_ttl(&env, &DataKey::Oracle);
        Self::_extend_persistent_ttl(&env, &DataKey::Paused);
        Self::_extend_persistent_ttl(&env, &DataKey::SchemaVersion);
        Self::_extend_persistent_ttl(&env, &DataKey::BetWindowLedgers);
        Self::_extend_persistent_ttl(&env, &DataKey::RunWindowLedgers);

        Ok(())
    }

    /// Returns the stored schema version. If unset, returns legacy version 1.
    pub fn get_schema_version(env: Env) -> u32 {
        let key = DataKey::SchemaVersion;
        Self::_extend_persistent_ttl(&env, &key);
        Self::_schema_version(&env).unwrap_or(1)
    }

    /// Migrates legacy schema version 1 → version 2 (admin only).
    ///
    /// Guardrails:
    /// - Must not have an active round (avoids partial state interpretation changes)
    pub fn migrate_schema_v1_to_v2(env: Env) -> Result<(), ContractError> {
        let admin_key = DataKey::Admin;
        Self::_extend_persistent_ttl(&env, &admin_key);
        let admin: Address = env
            .storage()
            .persistent()
            .get(&admin_key)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        if env.storage().persistent().has(&DataKey::ActiveRound) {
            return Err(ContractError::MigrationActiveRound);
        }

        let from = Self::_schema_version(&env).unwrap_or(1);
        const TARGET_VERSION: u32 = 2;
        if from != 1 {
            return Err(ContractError::InvalidMigrationPath);
        }

        let schema_key = DataKey::SchemaVersion;
        env.storage()
            .persistent()
            .set(&schema_key, &TARGET_VERSION);
        Self::_extend_persistent_ttl(&env, &schema_key);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("schema"), symbol_short!("migrated")),
            (from, TARGET_VERSION),
        );

        Ok(())
    }

    /// Migrates schema version 2 → version 3 (admin only).
    ///
    /// Schema v3 adds per-user archived round outcome records so operators
    /// can query user history without replaying events.
    ///
    /// Guardrails:
    /// - Must not have an active round
    pub fn migrate_schema_v2_to_v3(env: Env) -> Result<(), ContractError> {
        let admin_key = DataKey::Admin;
        Self::_extend_persistent_ttl(&env, &admin_key);
        let admin: Address = env
            .storage()
            .persistent()
            .get(&admin_key)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        if env.storage().persistent().has(&DataKey::ActiveRound) {
            return Err(ContractError::MigrationActiveRound);
        }

        let from = Self::_schema_version(&env).unwrap_or(1);
        const TARGET_VERSION: u32 = 3;
        if from != 2 {
            return Err(ContractError::InvalidMigrationPath);
        }

        let schema_key = DataKey::SchemaVersion;
        env.storage()
            .persistent()
            .set(&schema_key, &TARGET_VERSION);
        Self::_extend_persistent_ttl(&env, &schema_key);

        env.storage()
            .persistent()
            .set(&DataKey::MigratedToV3, &true);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("schema"), symbol_short!("migrated")),
            (from, TARGET_VERSION),
        );

        Ok(())
    }

    /// Returns whether the contract is currently paused
    pub fn is_paused(env: Env) -> bool {
        let key = DataKey::Paused;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key).unwrap_or(false)
    }

    /// Pauses the contract for emergency recovery (admin only)
    pub fn pause_contract(env: Env) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &true);
        Self::_extend_persistent_ttl(&env, &DataKey::Paused);

        Ok(())
    }

    /// Unpauses the contract after recovery (admin only)
    pub fn unpause_contract(env: Env) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &false);
        Self::_extend_persistent_ttl(&env, &DataKey::Paused);

        Ok(())
    }

    /// Creates a new prediction round (admin only)
    /// mode: 0 = Up/Down (default), 1 = Precision (Legends)
    pub fn create_round(
        env: Env,
        start_price: u128,
        mode: Option<u32>,
    ) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        if start_price < MIN_START_PRICE {
            return Err(ContractError::StartPriceTooLow);
        }
        if start_price > MAX_START_PRICE {
            return Err(ContractError::StartPriceTooHigh);
        }

        // Default to Up/Down mode (0) if not specified
        let mode_value = mode.unwrap_or(0);

        // Validate mode is either 0 or 1
        if mode_value > 1 {
            return Err(ContractError::InvalidMode);
        }

        let round_mode = if mode_value == 0 {
            RoundMode::UpDown
        } else {
            RoundMode::Precision
        };

        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;

        admin.require_auth();
        Self::_ensure_not_paused(&env)?;
        Self::assert_no_active_round(&env)?;

        // Get configured windows (with defaults)
        Self::_extend_persistent_ttl(&env, &DataKey::BetWindowLedgers);
        let bet_ledgers: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::BetWindowLedgers)
            .unwrap_or(DEFAULT_BET_WINDOW_LEDGERS);
        Self::_extend_persistent_ttl(&env, &DataKey::RunWindowLedgers);
        let run_ledgers: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::RunWindowLedgers)
            .unwrap_or(DEFAULT_RUN_WINDOW_LEDGERS);

        // Generate unique round ID
        Self::_extend_persistent_ttl(&env, &DataKey::LastRoundId);
        let last_round_id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::LastRoundId)
            .unwrap_or(0);
        let round_id = last_round_id
            .checked_add(1)
            .ok_or(ContractError::Overflow)?;
        env.storage()
            .persistent()
            .set(&DataKey::LastRoundId, &round_id);
        Self::_extend_persistent_ttl(&env, &DataKey::LastRoundId);

        let start_ledger = env.ledger().sequence();
        let bet_end_ledger = start_ledger
            .checked_add(bet_ledgers)
            .ok_or(ContractError::Overflow)?;
        let end_ledger = start_ledger
            .checked_add(run_ledgers)
            .ok_or(ContractError::Overflow)?;

        let round = Round {
            round_id,
            price_start: start_price,
            start_ledger,
            bet_end_ledger,
            end_ledger,
            pool_up: 0,
            pool_down: 0,
            mode: round_mode.clone(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::ActiveRound, &round);
        Self::_extend_persistent_ttl(&env, &DataKey::ActiveRound);

        // Note: individual position keys (DataKey::Position / DataKey::PrecisionPosition)
        // are cleaned up at resolve time; no bulk-map clearing needed here.

        // Emit round creation event with round ID and mode
        // Topic: ("round", "created")
        // Payload: (round_id: u64, start_price: u128, start_ledger: u32, bet_end_ledger: u32, end_ledger: u32, mode: u32)
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("round"), symbol_short!("created")),
            (
                round_id,
                start_price,
                start_ledger,
                bet_end_ledger,
                end_ledger,
                mode_value,
            ),
        );

        Ok(())
    }

    /// Returns the currently active round, if any
    pub fn get_active_round(env: Env) -> Option<Round> {
        env.storage().persistent().get(&DataKey::ActiveRound)
    }

    /// Returns the current lifecycle phase of the active round.
    ///
    /// Phase boundaries are deterministic:
    /// - `Betting` while `ledger < bet_end_ledger`
    /// - `Running` while `bet_end_ledger ≤ ledger < end_ledger`
    /// - `Resolvable` when `ledger ≥ end_ledger`
    ///
    /// Returns [`ContractError::NoActiveRound`] when no round is active.
    pub fn get_round_phase(env: Env) -> Result<RoundPhase, ContractError> {
        let round = env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
            .ok_or(ContractError::NoActiveRound)?;
        Ok(Self::_derive_round_phase(env.ledger().sequence(), &round))
    }

    /// Returns the ID of the last created round (0 if no rounds created yet)
    pub fn get_last_round_id(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::LastRoundId)
            .unwrap_or(0)
    }

    /// Returns a compact archived round summary by round id, if retained.
    pub fn get_archived_round(env: Env, round_id: u64) -> Option<ArchivedRoundSummary> {
        env.storage()
            .persistent()
            .get(&DataKey::ArchivedRound(round_id))
    }

    /// Returns up to `limit` most recently archived rounds (newest first).
    ///
    /// Pass `limit = 0` to receive an empty list. Values above the configured
    /// archive retention limit are capped automatically.
    pub fn get_recent_archived_rounds(env: Env, limit: u32) -> Vec<ArchivedRoundSummary> {
        let env_ref = &env;
        let recent: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::RecentArchivedRoundIds)
            .unwrap_or(Vec::new(env_ref));

        let mut result = Vec::new(env_ref);
        if limit == 0 || recent.is_empty() {
            return result;
        }

        let retention_limit = env
            .storage()
            .persistent()
            .get::<_, u32>(&DataKey::ArchiveRetention)
            .unwrap_or(DEFAULT_ARCHIVE_RETENTION);

        let fetch_cap = if limit > retention_limit {
            retention_limit
        } else {
            limit
        };

        let mut fetched: u32 = 0;
        let mut idx = recent.len();
        while idx > 0 && fetched < fetch_cap {
            idx -= 1;
            if let Some(round_id) = recent.get(idx) {
                if let Some(summary) = env
                    .storage()
                    .persistent()
                    .get(&DataKey::ArchivedRound(round_id))
                {
                    result.push_back(summary);
                    fetched += 1;
                }
            }
        }

        result
    }

    /// Returns a compact per-user outcome record for a specific archived round.
    ///
    /// Missing data returns `None` cleanly — the user either did not participate
    /// in the requested round or the round has not yet been archived.
    pub fn get_user_archived_participation(
        env: Env,
        user: Address,
        round_id: u64,
    ) -> Option<UserRoundOutcome> {
        let key = DataKey::UserRoundOutcome(round_id, user);
        env.storage().persistent().get(&key)
    }

    pub fn get_admin(env: Env) -> Option<Address> {
        let key = DataKey::Admin;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    pub fn get_oracle(env: Env) -> Option<Address> {
        let key = DataKey::Oracle;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    /// Schedules a timelocked oracle deviation update (alias for [`Self::schedule_oracle_deviation_bps`]).
    ///
    /// - `None`: disables deviation guardrails
    /// - `Some(bps)`: enables guardrails with a threshold in basis points (1 bp = 0.01%)
    pub fn set_oracle_max_deviation_bps(env: Env, bps: Option<u32>) -> Result<(), ContractError> {
        Self::schedule_oracle_deviation_bps(env, bps)
    }

    /// Returns the configured oracle max deviation bps, if set.
    pub fn get_oracle_max_deviation_bps(env: Env) -> Option<u32> {
        let key = DataKey::OracleMaxDeviationBps;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    /// Arms a one-shot override to bypass deviation checks for the next settlement (admin only).
    /// The flag is automatically cleared after a settlement uses it.
    pub fn arm_oracle_deviation_override(env: Env) -> Result<(), ContractError> {
        let admin_key = DataKey::Admin;
        Self::_extend_persistent_ttl(&env, &admin_key);
        let admin: Address = env
            .storage()
            .persistent()
            .get(&admin_key)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        let override_key = DataKey::OracleDeviationOverrideArmed;
        env.storage().persistent().set(&override_key, &true);
        Self::_extend_persistent_ttl(&env, &override_key);
        Ok(())
    }

    // ─── Oracle heartbeat and liveness (on-chain health tracking) ───────────

    /// Records an oracle heartbeat (oracle only).
    /// `status`: 0 = active, 1 = degraded, 2 = offline.
    /// Stores current ledger timestamp; emits `("oracle", "heartbeat")`.
    pub fn update_oracle_heartbeat(env: Env, status: u32) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        if status > 2 {
            return Err(ContractError::InvalidOracleStatus);
        }
        Self::_extend_persistent_ttl(&env, &DataKey::Oracle);
        let oracle: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Oracle)
            .ok_or(ContractError::OracleNotSet)?;
        oracle.require_auth();

        let ts = env.ledger().timestamp();
        let record = OracleHeartbeatRecord {
            timestamp: ts,
            status,
        };
        env.storage()
            .persistent()
            .set(&DataKey::OracleHeartbeat, &record);
        Self::_extend_persistent_ttl(&env, &DataKey::OracleHeartbeat);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("oracle"), symbol_short!("hbeat")),
            (ts, status),
        );
        Ok(())
    }

    /// Returns the most recent oracle heartbeat record, if any.
    pub fn get_oracle_heartbeat(env: Env) -> Option<OracleHeartbeatRecord> {
        let key = DataKey::OracleHeartbeat;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    /// Returns `true` if the oracle has a non-stale heartbeat with status not offline (2).
    /// Uses the configured stale threshold, defaulting to 3600 seconds.
    pub fn is_oracle_live(env: Env) -> bool {
        let heartbeat_key = DataKey::OracleHeartbeat;
        Self::_extend_persistent_ttl(&env, &heartbeat_key);
        let record: OracleHeartbeatRecord = match env.storage().persistent().get(&heartbeat_key) {
            Some(r) => r,
            None => return false,
        };
        if record.status == 2 {
            return false;
        }
        let threshold_key = DataKey::OracleStaleThreshold;
        Self::_extend_persistent_ttl(&env, &threshold_key);
        let threshold: u64 = env
            .storage()
            .persistent()
            .get(&threshold_key)
            .unwrap_or(DEFAULT_ORACLE_STALE_THRESHOLD);
        let current_time = env.ledger().timestamp();
        current_time <= record.timestamp.saturating_add(threshold)
    }

    /// Schedules a timelocked stale threshold update (alias for [`Self::schedule_oracle_stale_threshold`]).
    /// Allowed range: 60–86400 seconds (1 minute to 24 hours).
    pub fn set_oracle_stale_threshold(env: Env, seconds: u64) -> Result<(), ContractError> {
        Self::schedule_oracle_stale_threshold(env, seconds)
    }

    /// Returns a composite protocol health status aggregating pause state,
    /// oracle liveness, active round phase, and schema version.
    ///
    /// Read-only and deterministic — no authentication required.
    ///
    /// ## Status code reference
    ///
    /// | code | meaning         | when returned                          |
    /// |------|-----------------|----------------------------------------|
    /// | 0    | HEALTHY         | All subsystems nominal                 |
    /// | 1    | PAUSED          | Contract is emergency-paused           |
    /// | 2    | ORACLE_STALE    | Oracle heartbeat is stale or offline   |
    /// | 3    | ROUND_STALE     | Round resolvable but unresolved        |
    /// | 4    | NO_ACTIVE_ROUND | No round active, oracle healthy        |
    /// | 5    | MULTIPLE_ISSUES | Two or more simultaneous problems      |
    pub fn get_protocol_health(env: Env) -> ProtocolHealthStatus {
        let ledger_sequence = env.ledger().sequence();
        let ledger_timestamp = env.ledger().timestamp();

        // ─── Pause state ────────────────────────────────────────────────────
        let paused = Self::is_paused(env.clone());

        // ─── Oracle liveness ────────────────────────────────────────────────
        let heartbeat_key = DataKey::OracleHeartbeat;
        Self::_extend_persistent_ttl(&env, &heartbeat_key);
        let (oracle_live, oracle_status) = match env
            .storage()
            .persistent()
            .get::<_, OracleHeartbeatRecord>(&heartbeat_key)
        {
            None => (false, 3u32),
            Some(record) => {
                if record.status == 2 {
                    (false, record.status)
                } else {
                    let threshold_key = DataKey::OracleStaleThreshold;
                    Self::_extend_persistent_ttl(&env, &threshold_key);
                    let threshold: u64 = env
                        .storage()
                        .persistent()
                        .get(&threshold_key)
                        .unwrap_or(DEFAULT_ORACLE_STALE_THRESHOLD);
                    let live = ledger_timestamp <= record.timestamp.saturating_add(threshold);
                    (live, record.status)
                }
            }
        };

        // ─── Active round phase ─────────────────────────────────────────────
        let (has_active_round, active_round_phase) = match env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            None => (false, 0u32),
            Some(round) => {
                let phase = Self::_derive_round_phase(ledger_sequence, &round);
                (true, phase as u32)
            }
        };

        // ─── Schema version ─────────────────────────────────────────────────
        let schema_version = Self::_schema_version(&env).unwrap_or(1);

        // ─── Composite status code ──────────────────────────────────────────
        let mut issues: u32 = 0;
        if paused {
            issues += 1;
        }
        if !oracle_live {
            issues += 1;
        }
        if has_active_round && active_round_phase == 3 {
            issues += 1;
        }

        let status_code = if paused {
            1u32 // PAUSED
        } else if issues > 1 {
            5u32 // MULTIPLE_ISSUES
        } else if !oracle_live {
            2u32 // ORACLE_STALE
        } else if has_active_round && active_round_phase == 3 {
            3u32 // ROUND_STALE
        } else if !has_active_round {
            4u32 // NO_ACTIVE_ROUND
        } else {
            0u32 // HEALTHY
        };

        ProtocolHealthStatus {
            paused,
            oracle_live,
            oracle_status,
            has_active_round,
            active_round_phase,
            schema_version,
            ledger_sequence,
            ledger_timestamp,
            status_code,
        }
    }

    /// Returns the configured oracle stale threshold, or the default (3600 s) if not set.
    pub fn get_oracle_stale_threshold(env: Env) -> u64 {
        let key = DataKey::OracleStaleThreshold;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(DEFAULT_ORACLE_STALE_THRESHOLD)
    }

    /// Schedules a timelocked windows update (alias for [`Self::schedule_windows`]).
    /// bet_ledgers: Number of ledgers users can place bets
    /// run_ledgers: Total number of ledgers before round can be resolved
    pub fn set_windows(env: Env, bet_ledgers: u32, run_ledgers: u32) -> Result<(), ContractError> {
        Self::schedule_windows(env, bet_ledgers, run_ledgers)
    }

    // ─── Economic controls (Issue #113) ─────────────────────────────────────

    /// Schedules a timelocked max stake update (alias for [`Self::schedule_max_stake`]).
    /// Pass `None` to disable the cap.
    pub fn set_max_stake(env: Env, max_amount: Option<i128>) -> Result<(), ContractError> {
        Self::schedule_max_stake(env, max_amount)
    }

    /// Returns the current maximum stake cap, if set.
    pub fn get_max_stake(env: Env) -> Option<i128> {
        let key = DataKey::MaxStake;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    /// Schedules a timelocked exposure cap update (alias for [`Self::schedule_max_user_exposure`]).
    /// Pass `None` to disable the cap.
    pub fn set_max_user_exposure(
        env: Env,
        max_exposure: Option<i128>,
    ) -> Result<(), ContractError> {
        Self::schedule_max_user_exposure(env, max_exposure)
    }

    /// Returns the current per-user round exposure cap, if set.
    pub fn get_max_user_exposure(env: Env) -> Option<i128> {
        let key = DataKey::MaxUserRoundExposure;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    // ─── Accounting safety (Issue #120) ─────────────────────────────────────

    /// Schedules a timelocked pending winnings cap update (alias for [`Self::schedule_max_pending_winnings`]).
    /// Pass `None` to disable the cap.
    pub fn set_max_pending_winnings(
        env: Env,
        max_pending: Option<i128>,
    ) -> Result<(), ContractError> {
        Self::schedule_max_pending_winnings(env, max_pending)
    }

    // ─── Timelocked critical config (governance safety) ─────────────────────

    /// Schedules a timelocked update to betting and execution windows (admin only).
    /// The change is stored pending until `apply_scheduled_changes` is called after the delay.
    pub fn schedule_windows(
        env: Env,
        bet_ledgers: u32,
        run_ledgers: u32,
    ) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_windows(bet_ledgers, run_ledgers)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::Windows,
            ConfigChangePayload::Windows(bet_ledgers, run_ledgers),
        )
    }

    /// Schedules a timelocked update to the maximum stake cap (admin only).
    pub fn schedule_max_stake(env: Env, max_amount: Option<i128>) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_max_stake(max_amount)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::MaxStake,
            ConfigChangePayload::MaxStake(max_amount),
        )
    }

    /// Schedules a timelocked update to the per-user round exposure cap (admin only).
    pub fn schedule_max_user_exposure(
        env: Env,
        max_exposure: Option<i128>,
    ) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_max_stake(max_exposure)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::MaxUserRoundExposure,
            ConfigChangePayload::MaxUserRoundExposure(max_exposure),
        )
    }

    /// Schedules a timelocked update to the pending winnings cap (admin only).
    pub fn schedule_max_pending_winnings(
        env: Env,
        max_pending: Option<i128>,
    ) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_max_stake(max_pending)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::MaxPendingWinnings,
            ConfigChangePayload::MaxPendingWinnings(max_pending),
        )
    }

    /// Schedules a timelocked update to the oracle stale threshold (admin only).
    pub fn schedule_oracle_stale_threshold(env: Env, seconds: u64) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_oracle_stale_threshold(seconds)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::OracleStaleThreshold,
            ConfigChangePayload::OracleStaleThreshold(seconds),
        )
    }

    /// Schedules a timelocked update to the oracle max deviation threshold (admin only).
    pub fn schedule_oracle_deviation_bps(env: Env, bps: Option<u32>) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_oracle_max_deviation_bps(bps)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::OracleMaxDeviationBps,
            ConfigChangePayload::OracleMaxDeviationBps(bps),
        )
    }

    // ─── Protocol fee (Issue #162) ─────────────────────────────────────────

    /// Schedules a timelocked update to the optional protocol settlement fee
    /// (admin only). Pass `None` to disable fee collection entirely
    /// (preserves pre-issue-#162 behaviour byte-for-byte: no fee ever
    /// collected, treasury stays at 0, no fee events emitted).
    /// Pass `Some(bps)` to enable a fee of `bps / 10_000` (capped at
    /// `MAX_PROTOCOL_FEE_BPS`) of the round's total pot, deducted on every
    /// competitive settlement and routed to the on-chain treasury.
    pub fn schedule_protocol_fee_bps(env: Env, bps: Option<u32>) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_validate_protocol_fee_bps(bps)?;
        Self::_schedule_config_change(
            &env,
            ConfigChangeKind::ProtocolFeeBps,
            ConfigChangePayload::ProtocolFeeBps(bps),
        )
    }

    /// Alias for [`Self::schedule_protocol_fee_bps`]. Mirrors the
    /// `set_max_stake` / `set_windows` naming convention.
    pub fn set_protocol_fee_bps(env: Env, bps: Option<u32>) -> Result<(), ContractError> {
        Self::schedule_protocol_fee_bps(env, bps)
    }

    /// Returns the configured protocol fee in bps, if enabled.
    /// `None` (key absent) means fee disabled — no behaviour change.
    pub fn get_protocol_fee_bps(env: Env) -> Option<u32> {
        let key = DataKey::ProtocolFeeBps;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    /// Returns the accumulated, on-chain protocol fee treasury balance
    /// (stroops). Starts at 0; grows monotonically with every competitive
    /// settlement when the fee is enabled. Only the admin can drain it
    /// via [`Self::withdraw_protocol_fee`].
    pub fn get_protocol_fee_treasury(env: Env) -> i128 {
        let key = DataKey::ProtocolFeeTreasury;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Withdraws `amount` stroops from the protocol fee treasury to
    /// `recipient` (admin only). The transfer uses the existing
    /// per-user balance ledger; the recipient must already exist
    /// (`mint_initial` first or already have a balance from prior activity).
    /// Errors with `FeeTreasuryUnderflow` if `amount` exceeds the
    /// accumulated treasury.
    pub fn withdraw_protocol_fee(
        env: Env,
        recipient: Address,
        amount: i128,
    ) -> Result<i128, ContractError> {
        Self::_require_supported_schema(&env)?;
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        if amount <= 0 {
            return Err(ContractError::InvalidBetAmount);
        }

        let treasury_key = DataKey::ProtocolFeeTreasury;
        let current: i128 = env.storage().persistent().get(&treasury_key).unwrap_or(0);
        let new_treasury = current
            .checked_sub(amount)
            .ok_or(ContractError::FeeTreasuryUnderflow)?;
        env.storage().persistent().set(&treasury_key, &new_treasury);
        Self::_extend_persistent_ttl(&env, &treasury_key);

        // Credit recipient — reuse the existing balance helper. create a
        // balance row if recipient has none yet (treasury recipient may
        // not have minted).
        let recipient_bal: i128 = Self::balance(env.clone(), recipient.clone());
        let new_bal = Self::payout_add(recipient_bal, amount)?;
        Self::_set_balance(&env, recipient.clone(), new_bal);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("protocol"), symbol_short!("fee_with")),
            (recipient, amount, new_treasury),
        );

        Ok(amount)
    }

    /// Returns a pending timelocked config change for the given kind, if any.
    pub fn get_pending_config_change(
        env: Env,
        kind: ConfigChangeKind,
    ) -> Option<PendingConfigChange> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingConfigChange(kind))
    }

    /// Applies a scheduled critical config change after its activation ledger (any caller).
    pub fn apply_scheduled_changes(env: Env, kind: ConfigChangeKind) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        Self::_ensure_not_paused(&env)?;

        let key = DataKey::PendingConfigChange(kind.clone());
        let pending: PendingConfigChange = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::CommitmentNotFound)?;

        let current_ledger = env.ledger().sequence();
        if current_ledger < pending.activation_ledger {
            return Err(ContractError::RoundNotEnded);
        }

        Self::_apply_config_payload(&env, &kind, &pending.payload)?;
        env.storage().persistent().remove(&key);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("config"), symbol_short!("applied")),
            (kind, pending.activation_ledger),
        );

        Ok(())
    }

    /// Cancels a pending timelocked config change before activation (admin only).
    pub fn cancel_config_change(env: Env, kind: ConfigChangeKind) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        let key = DataKey::PendingConfigChange(kind.clone());
        let pending: PendingConfigChange = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::CommitmentNotFound)?;

        if env.ledger().sequence() >= pending.activation_ledger {
            return Err(ContractError::RoundNotCancellable);
        }

        let cancelled_at = env.ledger().sequence();

        env.storage().persistent().remove(&key);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("config"), symbol_short!("cancel")),
            (kind, cancelled_at),
        );

        Ok(())
    }

    /// Returns the current maximum pending winnings cap, if set.
    pub fn get_max_pending_winnings(env: Env) -> Option<i128> {
        let key = DataKey::MaxPendingWinnings;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    // ─── Minimum participants (competitive settlement integrity) ─────────────

    /// Sets the minimum participant count required for competitive settlement (admin only).
    /// Rounds that end below this threshold are refunded to all participants.
    /// Pass `None` to disable the threshold.
    pub fn set_min_participants(env: Env, min: Option<u32>) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        let key = DataKey::MinParticipants;
        let old_min: Option<u32> = env.storage().persistent().get(&key);
        if let Some(v) = min {
            if v == 0 || v > MAX_MIN_PARTICIPANTS {
                return Err(ContractError::InvalidMinParticipants);
            }
            env.storage().persistent().set(&key, &v);
            Self::_extend_persistent_ttl(&env, &key);
        } else {
            env.storage().persistent().remove(&key);
        }
        Self::_emit_config_updated(
            &env,
            ConfigChangeKind::MinParticipants,
            ConfigChangePayload::MinParticipants(old_min),
            ConfigChangePayload::MinParticipants(min),
        );
        Ok(())
    }

    /// Returns the current minimum participant threshold, if set.
    pub fn get_min_participants(env: Env) -> Option<u32> {
        let key = DataKey::MinParticipants;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key)
    }

    /// Sets the maximum participant count for Precision rounds (admin only).
    /// The value must be in the range 1..=10_000. Unset contracts use the
    /// protocol default of 1_000 participants.
    pub fn set_max_precision_participants(env: Env, max: u32) -> Result<(), ContractError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        if max == 0 || max > MAX_PRECISION_PARTICIPANTS_LIMIT {
            return Err(ContractError::InvalidPrecisionParticipantCap);
        }

        let key = DataKey::MaxPrecisionParticipants;
        let old_max: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(DEFAULT_MAX_PRECISION_PARTICIPANTS);
        env.storage().persistent().set(&key, &max);
        Self::_extend_persistent_ttl(&env, &key);
        Self::_emit_config_updated(
            &env,
            ConfigChangeKind::MaxPrecisionParticipants,
            ConfigChangePayload::MaxPrecisionParticipants(old_max),
            ConfigChangePayload::MaxPrecisionParticipants(max),
        );
        Ok(())
    }

    /// Returns the configured Precision participant cap, or the default if unset.
    pub fn get_max_precision_participants(env: Env) -> u32 {
        let key = DataKey::MaxPrecisionParticipants;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(DEFAULT_MAX_PRECISION_PARTICIPANTS)
    }

    /// Sets the maximum number of mints allowed per ledger (admin only).
    /// Pass 0 to disable the limit.
    pub fn set_mint_limit(env: Env, limit: u32) -> Result<(), ContractError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        let old_limit: u32 = env
            .storage()
            .instance()
            .get(&DataKey::MintLimitConfig)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::MintLimitConfig, &limit);
        Self::_emit_config_updated(
            &env,
            ConfigChangeKind::MintLimit,
            ConfigChangePayload::MintLimit(old_limit),
            ConfigChangePayload::MintLimit(limit),
        );
        Ok(())
    }

    /// Returns the configured mint limit per ledger, or 0 if disabled.
    pub fn get_mint_limit(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::MintLimitConfig)
            .unwrap_or(0)
    }

    /// Sets the archive retention limit — the maximum number of ArchivedRound
    /// entries retained on-chain before the oldest are pruned (FIFO) (admin only).
    ///
    /// Valid range: `MIN_ARCHIVE_RETENTION..=MAX_ARCHIVE_RETENTION` (1..=10_000).
    /// Changes apply to future archive writes; existing entries are not
    /// retroactively pruned on config change.
    pub fn set_archive_retention(env: Env, limit: u32) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(&env)?;

        if limit < MIN_ARCHIVE_RETENTION || limit > MAX_ARCHIVE_RETENTION {
            return Err(ContractError::InvalidArchiveRetention);
        }

        let key = DataKey::ArchiveRetention;
        let old_limit: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(DEFAULT_ARCHIVE_RETENTION);
        env.storage().persistent().set(&key, &limit);
        Self::_extend_persistent_ttl(&env, &key);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("archive"), symbol_short!("retention")),
            (limit,),
        );
        Self::_emit_config_updated(
            &env,
            ConfigChangeKind::ArchiveRetention,
            ConfigChangePayload::ArchiveRetention(old_limit),
            ConfigChangePayload::ArchiveRetention(limit),
        );

        Ok(())
    }

    /// Returns the configured archive retention limit, or the protocol default (128) if unset.
    pub fn get_archive_retention(env: Env) -> u32 {
        let key = DataKey::ArchiveRetention;
        Self::_extend_persistent_ttl(&env, &key);
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(DEFAULT_ARCHIVE_RETENTION)
    }

    /// Returns user statistics (wins, losses, streaks)
    pub fn get_user_stats(env: Env, user: Address) -> UserStats {
        let key = DataKey::UserStats(user);
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key).unwrap_or(UserStats {
            total_wins: 0,
            total_losses: 0,
            current_streak: 0,
            best_streak: 0,
        })
    }

    /// Returns user's claimable winnings
    pub fn get_pending_winnings(env: Env, user: Address) -> i128 {
        let key = DataKey::PendingWinnings(user);
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Places a bet on the active round (Up/Down mode only).
    ///
    /// Storage layout: each participant's position is stored under its own
    /// composite key `DataKey::Position(round_id, user)` — O(1) read/write
    /// regardless of how many other participants exist. An ordered participant
    /// list `DataKey::RoundParticipants(round_id)` is maintained for O(n)
    /// iteration at resolution time only.
    pub fn place_bet(
        env: Env,
        user: Address,
        amount: i128,
        side: BetSide,
    ) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        user.require_auth();
        Self::_ensure_not_paused(&env)?;

        if amount <= 0 {
            return Err(ContractError::InvalidBetAmount);
        }

        // Enforce max stake cap (Issue #113)
        if let Some(max_stake) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxStake)
        {
            if amount > max_stake {
                return Err(ContractError::StakeExceedsMax);
            }
        }

        // Single read of the active round — cache in call scope
        let mut round: Round = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveRound)
            .ok_or(ContractError::NoActiveRound)?;

        // Enforce per-user round exposure cap (Issue #113)
        if let Some(max_exposure) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxUserRoundExposure)
        {
            if amount > max_exposure {
                return Err(ContractError::ExposureCapExceeded);
            }
        }

        // Verify round is in Up/Down mode
        if round.mode != RoundMode::UpDown {
            return Err(ContractError::WrongModeForPrediction);
        }

        let current_ledger = env.ledger().sequence();
        if current_ledger >= round.bet_end_ledger {
            return Err(ContractError::RoundEnded);
        }

        let user_balance = Self::balance(env.clone(), user.clone());
        if user_balance < amount {
            return Err(ContractError::InsufficientBalance);
        }

        // O(1) duplicate-bet check — read one small key, not the full map
        let pos_key = DataKey::Position(round.round_id, user.clone());
        if env.storage().persistent().has(&pos_key) {
            return Err(ContractError::AlreadyBet);
        }

        // Deduct balance
        let new_balance = user_balance
            .checked_sub(amount)
            .ok_or(ContractError::Overflow)?;
        Self::_set_balance(&env, user.clone(), new_balance);

        // Write single-user position key — O(1), constant-size entry
        let position = UserPosition {
            amount,
            side: side.clone(),
        };
        env.storage().persistent().set(&pos_key, &position);

        // Append to participant list (needed for O(n) resolution iteration)
        let participants_key = DataKey::RoundParticipants(round.round_id);
        let mut participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&participants_key)
            .unwrap_or(Vec::new(&env));
        participants.push_back(user.clone());
        env.storage()
            .persistent()
            .set(&participants_key, &participants);

        // Update cached round pools and write once
        match side {
            BetSide::Up => {
                round.pool_up = round
                    .pool_up
                    .checked_add(amount)
                    .ok_or(ContractError::Overflow)?;
            }
            BetSide::Down => {
                round.pool_down = round
                    .pool_down
                    .checked_add(amount)
                    .ok_or(ContractError::Overflow)?;
            }
        }
        env.storage()
            .persistent()
            .set(&DataKey::ActiveRound, &round);

        // Emit bet placed event
        // Topic: ("bet", "placed")
        // Payload: (user: Address, round_id: u64, amount: i128, side: u32 where 0=Up, 1=Down)
        let side_value: u32 = match side {
            BetSide::Up => 0,
            BetSide::Down => 1,
        };
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("bet"), symbol_short!("placed")),
            (user, round.round_id, amount, side_value),
        );

        Ok(())
    }

    /// Places a precision prediction on the active round (Precision/Legends mode only)
    /// predicted_price: price scaled to 4 decimals (e.g., 0.2297 → 2297)
    ///
    /// Per-user key `DataKey::PrecisionPosition(round_id, user)` gives O(1)
    /// write cost independent of participant count.
    pub fn place_precision_prediction(
        env: Env,
        user: Address,
        amount: i128,
        predicted_price: u128,
    ) -> Result<(), ContractError> {
        Self::_require_supported_schema(&env)?;
        user.require_auth();
        Self::_ensure_not_paused(&env)?;

        if amount <= 0 {
            return Err(ContractError::InvalidBetAmount);
        }

        // Enforce max stake cap (Issue #113)
        if let Some(max_stake) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxStake)
        {
            if amount > max_stake {
                return Err(ContractError::StakeExceedsMax);
            }
        }

        // Validate price scale (must be 4 decimal places, max value 9999 for 0.9999)
        // Reasonable max: 99999999 (9999.9999 XLM)
        if predicted_price > 99_999_999 {
            return Err(ContractError::InvalidPriceScale);
        }

        // Single read of the active round — cache in call scope
        let round: Round = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveRound)
            .ok_or(ContractError::NoActiveRound)?;

        // Enforce per-user round exposure cap (Issue #113)
        if let Some(max_exposure) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxUserRoundExposure)
        {
            if amount > max_exposure {
                return Err(ContractError::ExposureCapExceeded);
            }
        }

        // Verify round is in Precision mode
        if round.mode != RoundMode::Precision {
            return Err(ContractError::WrongModeForPrediction);
        }

        let current_ledger = env.ledger().sequence();
        if current_ledger >= round.bet_end_ledger {
            return Err(ContractError::RoundEnded);
        }

        // O(1) duplicate-prediction check — single composite key read
        let pred_key = DataKey::PrecisionPosition(round.round_id, user.clone());
        let commit_key = DataKey::PrecisionCommitment(round.round_id, user.clone());
        if env.storage().persistent().has(&pred_key) || env.storage().persistent().has(&commit_key)
        {
            return Err(ContractError::AlreadyBet);
        }

        let participants_key = DataKey::RoundParticipants(round.round_id);
        let mut participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&participants_key)
            .unwrap_or(Vec::new(&env));
        let max_precision_participants = Self::get_max_precision_participants(env.clone());
        if participants.len() >= max_precision_participants {
            return Err(ContractError::PrecisionParticipantCapExceeded);
        }

        let user_balance = Self::balance(env.clone(), user.clone());
        if user_balance < amount {
            return Err(ContractError::InsufficientBalance);
        }

        // Deduct balance
        let new_balance = user_balance
            .checked_sub(amount)
            .ok_or(ContractError::Overflow)?;
        Self::_set_balance(&env, user.clone(), new_balance);

        // Write single-user prediction key — O(1), constant-size entry
        let prediction = PrecisionPrediction {
            user: user.clone(),
            predicted_price,
            amount,
        };
        env.storage().persistent().set(&pred_key, &prediction);

        // Append to shared participant list
        participants.push_back(user.clone());
        env.storage()
            .persistent()
            .set(&participants_key, &participants);

        // Emit event for precision prediction
        // Topic: ("predict", "price")
        // Payload: (user: Address, round_id: u64, predicted_price: u128, amount: i128)
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("predict"), symbol_short!("price")),
            (user, round.round_id, predicted_price, amount),
        );

        Ok(())
    }

    /// Alias for place_precision_prediction - allows users to submit exact price predictions
    /// guessed_price: price scaled to 4 decimals (e.g., 0.2297 → 2297)
    pub fn predict_price(
        env: Env,
        user: Address,
        guessed_price: u128,
        amount: i128,
    ) -> Result<(), ContractError> {
        Self::place_precision_prediction(env, user, amount, guessed_price)
    }

    /// Commits a hashed prediction and stake amount (Precision mode only)
    pub fn commit_prediction(
        env: Env,
        user: Address,
        hash: BytesN<32>,
        amount: i128,
    ) -> Result<(), ContractError> {
        user.require_auth();
        Self::_ensure_not_paused(&env)?;

        if amount <= 0 {
            return Err(ContractError::InvalidBetAmount);
        }

        // Enforce max stake cap
        if let Some(max_stake) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxStake)
        {
            if amount > max_stake {
                return Err(ContractError::StakeExceedsMax);
            }
        }

        // Single read of the active round
        let round: Round = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveRound)
            .ok_or(ContractError::NoActiveRound)?;

        // Enforce per-user round exposure cap
        if let Some(max_exposure) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxUserRoundExposure)
        {
            if amount > max_exposure {
                return Err(ContractError::ExposureCapExceeded);
            }
        }

        // Verify round is in Precision mode
        if round.mode != RoundMode::Precision {
            return Err(ContractError::WrongModeForPrediction);
        }

        let current_ledger = env.ledger().sequence();
        if current_ledger >= round.bet_end_ledger {
            return Err(ContractError::RoundEnded);
        }

        let user_balance = Self::balance(env.clone(), user.clone());
        if user_balance < amount {
            return Err(ContractError::InsufficientBalance);
        }

        // Check duplicate bet or commitment
        let pred_key = DataKey::PrecisionPosition(round.round_id, user.clone());
        let commit_key = DataKey::PrecisionCommitment(round.round_id, user.clone());
        if env.storage().persistent().has(&pred_key) || env.storage().persistent().has(&commit_key)
        {
            return Err(ContractError::AlreadyBet);
        }

        // Deduct balance
        let new_balance = user_balance
            .checked_sub(amount)
            .ok_or(ContractError::Overflow)?;
        Self::_set_balance(&env, user.clone(), new_balance);

        // Store commitment
        let commitment = PrecisionCommitment {
            hash: hash.clone(),
            amount,
            revealed: false,
        };
        env.storage().persistent().set(&commit_key, &commitment);

        // Append to shared participant list
        let participants_key = DataKey::RoundParticipants(round.round_id);
        let mut participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&participants_key)
            .unwrap_or(Vec::new(&env));
        participants.push_back(user.clone());
        env.storage()
            .persistent()
            .set(&participants_key, &participants);

        // Emit commit prediction event
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("commit"), symbol_short!("predict")),
            (user, round.round_id, hash, amount),
        );

        Ok(())
    }

    /// Reveals a previously committed prediction (Precision mode only)
    pub fn reveal_prediction(
        env: Env,
        user: Address,
        predicted_price: u128,
        salt: BytesN<32>,
    ) -> Result<(), ContractError> {
        user.require_auth();
        Self::_ensure_not_paused(&env)?;

        // Single read of the active round
        let round: Round = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveRound)
            .ok_or(ContractError::NoActiveRound)?;

        // Verify round is in Precision mode
        if round.mode != RoundMode::Precision {
            return Err(ContractError::WrongModeForPrediction);
        }

        // Enforce reveal window: bet_end_ledger <= ledger < end_ledger
        let current_ledger = env.ledger().sequence();
        if current_ledger < round.bet_end_ledger || current_ledger >= round.end_ledger {
            return Err(ContractError::InvalidRevealWindow);
        }

        // Retrieve commitment
        let commit_key = DataKey::PrecisionCommitment(round.round_id, user.clone());
        let mut commitment: PrecisionCommitment = env
            .storage()
            .persistent()
            .get(&commit_key)
            .ok_or(ContractError::CommitmentNotFound)?;

        if commitment.revealed {
            return Err(ContractError::AlreadyRevealed);
        }

        // Verify hash
        let mut preimage = Bytes::new(&env);
        preimage.append(&predicted_price.to_xdr(&env));
        preimage.append(&salt.to_xdr(&env));
        let computed_hash = env.crypto().sha256(&preimage);
        let computed_hash_bytes: BytesN<32> = computed_hash.into();

        if computed_hash_bytes != commitment.hash {
            return Err(ContractError::HashMismatch);
        }

        // Mark revealed and write
        commitment.revealed = true;
        env.storage().persistent().set(&commit_key, &commitment);

        // Store prediction for resolution
        let pred_key = DataKey::PrecisionPosition(round.round_id, user.clone());
        let prediction = PrecisionPrediction {
            user: user.clone(),
            predicted_price,
            amount: commitment.amount,
        };
        env.storage().persistent().set(&pred_key, &prediction);

        // Emit reveal prediction event
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("reveal"), symbol_short!("predict")),
            (user, round.round_id, predicted_price, commitment.amount),
        );

        Ok(())
    }

    /// Returns user's position in the current round (Up/Down mode).
    ///
    /// Reads a single composite key `DataKey::Position(round_id, user)` — O(1).
    /// Falls back to legacy `UpDownPositions` / `Positions` map blobs for
    /// one-time migration compatibility.
    pub fn get_user_position(env: Env, user: Address) -> Option<UserPosition> {
        if let Some(round) = env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            let pos_key = DataKey::Position(round.round_id, user.clone());
            if let Some(pos) = env.storage().persistent().get(&pos_key) {
                return Some(pos);
            }
        }

        // Legacy read-only fallback for migration data
        let legacy_updown: Map<Address, UserPosition> = env
            .storage()
            .persistent()
            .get(&DataKey::UpDownPositions)
            .unwrap_or(Map::new(&env));
        if let Some(p) = legacy_updown.get(user.clone()) {
            return Some(p);
        }
        let legacy_positions: Map<Address, UserPosition> = env
            .storage()
            .persistent()
            .get(&DataKey::Positions)
            .unwrap_or(Map::new(&env));
        legacy_positions.get(user)
    }

    /// Returns user's precision prediction in the current round (Precision mode).
    ///
    /// Reads a single composite key `DataKey::PrecisionPosition(round_id, user)` — O(1).
    /// Falls back to legacy `PrecisionPositions` map for migration compatibility.
    pub fn get_user_precision_prediction(env: Env, user: Address) -> Option<PrecisionPrediction> {
        if let Some(round) = env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            let pred_key = DataKey::PrecisionPosition(round.round_id, user.clone());
            if let Some(p) = env
                .storage()
                .persistent()
                .get::<_, PrecisionPrediction>(&pred_key)
            {
                return Some(p);
            }
        }
        let legacy: Map<Address, PrecisionPrediction> = env
            .storage()
            .persistent()
            .get(&DataKey::PrecisionPositions)
            .unwrap_or(Map::new(&env));
        legacy.get(user)
    }

    /// Returns all precision predictions for the current round.
    ///
    /// Reads the participant list once, then fetches each prediction individually.
    /// Total reads: 1 (participant list) + N (predictions) instead of 1 large map blob.
    pub fn get_precision_predictions(env: Env) -> Vec<PrecisionPrediction> {
        let round = match env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            Some(r) => r,
            None => return Vec::new(&env),
        };

        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round.round_id))
            .unwrap_or(Vec::new(&env));

        let mut result: Vec<PrecisionPrediction> = Vec::new(&env);
        for i in 0..participants.len() {
            if let Some(user) = participants.get(i) {
                let pred_key = DataKey::PrecisionPosition(round.round_id, user.clone());
                if let Some(pred) = env.storage().persistent().get(&pred_key) {
                    result.push_back(pred);
                }
            }
        }

        // Legacy fallback: pre-migration data lives in the bulk map
        if result.is_empty() {
            let legacy: Map<Address, PrecisionPrediction> = env
                .storage()
                .persistent()
                .get(&DataKey::PrecisionPositions)
                .unwrap_or(Map::new(&env));
            return legacy.values();
        }
        result
    }

    /// Returns all Up/Down positions for the current round.
    ///
    /// Reads the participant list once, then fetches each position individually.
    pub fn get_updown_positions(env: Env) -> Map<Address, UserPosition> {
        let round = match env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            Some(r) => r,
            None => return Map::new(&env),
        };

        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round.round_id))
            .unwrap_or(Vec::new(&env));

        let mut result: Map<Address, UserPosition> = Map::new(&env);
        for i in 0..participants.len() {
            if let Some(user) = participants.get(i) {
                let pos_key = DataKey::Position(round.round_id, user.clone());
                if let Some(pos) = env.storage().persistent().get(&pos_key) {
                    result.set(user, pos);
                }
            }
        }

        // Legacy fallback: pre-migration data lives in the bulk map
        if result.is_empty() {
            return env
                .storage()
                .persistent()
                .get(&DataKey::UpDownPositions)
                .unwrap_or(Map::new(&env));
        }
        result
    }
    // ─── Pagination (Issue #139) ─────────────────────────────────────────────

    /// Returns a deterministic slice of Precision-mode predictions for the
    /// active round, ordered by ascending participant address (the same
    /// canonical order used internally for payout-remainder assignment).
    ///
    /// `offset` is the zero-based index into the ordered participant list.
    /// `limit` is the maximum number of entries to return and is capped at
    /// `MAX_PAGE_SIZE` to bound gas/read costs regardless of caller input.
    ///
    /// Returns an empty `Vec` if there is no active round, if `offset` is
    /// beyond the number of available entries, or if `limit` is zero — this
    /// is not an error condition, matching standard pagination semantics
    /// (asking past the end of a list yields an empty page, not a fault).
    ///
    /// This does not replace [`Self::get_precision_predictions`], which
    /// remains available unchanged for full-set reads on small rounds.
    pub fn get_precision_predictions_page(
        env: Env,
        offset: u32,
        limit: u32,
    ) -> Vec<PrecisionPrediction> {
        let limit = limit.min(MAX_PAGE_SIZE);
        if limit == 0 {
            return Vec::new(&env);
        }

        let round = match env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            Some(r) => r,
            None => return Vec::new(&env),
        };

        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round.round_id))
            .unwrap_or(Vec::new(&env));
        let participants = Self::sort_addresses(participants);

        let total = participants.len();
        if offset >= total {
            return Vec::new(&env);
        }

        let end = offset.saturating_add(limit).min(total);

        let mut result: Vec<PrecisionPrediction> = Vec::new(&env);
        for i in offset..end {
            if let Some(user) = participants.get(i) {
                let pred_key = DataKey::PrecisionPosition(round.round_id, user.clone());
                if let Some(pred) = env.storage().persistent().get(&pred_key) {
                    result.push_back(pred);
                }
            }
        }

        result
    }

    /// Returns a deterministic slice of Up/Down positions for the active
    /// round, ordered by ascending participant address, as `(Address,
    /// UserPosition)` pairs.
    ///
    /// A `Vec` of pairs is used instead of a `Map` because pagination over a
    /// `Map` has no stable, caller-controllable slice semantics in Soroban —
    /// pairs preserve the exact offset/limit window the caller requested.
    ///
    /// See [`Self::get_precision_predictions_page`] for the offset/limit/empty-page
    /// contract, which is identical here. This does not replace
    /// [`Self::get_updown_positions`], which remains available unchanged.
    pub fn get_updown_positions_page(
        env: Env,
        offset: u32,
        limit: u32,
    ) -> Vec<(Address, UserPosition)> {
        let limit = limit.min(MAX_PAGE_SIZE);
        if limit == 0 {
            return Vec::new(&env);
        }

        let round = match env
            .storage()
            .persistent()
            .get::<_, Round>(&DataKey::ActiveRound)
        {
            Some(r) => r,
            None => return Vec::new(&env),
        };

        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round.round_id))
            .unwrap_or(Vec::new(&env));
        let participants = Self::sort_addresses(participants);

        let total = participants.len();
        if offset >= total {
            return Vec::new(&env);
        }

        let end = offset.saturating_add(limit).min(total);

        let mut result: Vec<(Address, UserPosition)> = Vec::new(&env);
        for i in offset..end {
            if let Some(user) = participants.get(i) {
                let pos_key = DataKey::Position(round.round_id, user.clone());
                if let Some(pos) = env.storage().persistent().get(&pos_key) {
                    result.push_back((user, pos));
                }
            }
        }

        result
    }

    /// Resolves the round with oracle payload (oracle only)
    /// Mode 0 (Up/Down): Winners split losers' pool proportionally; ties get refunds
    /// Mode 1 (Precision/Legends): Closest guess wins full pot; ties split evenly
    pub fn resolve_round(env: Env, payload: OraclePayload) -> Result<(), ContractError> {
        resolve_round(
            &env,
            payload,
            |e| Self::_require_supported_schema(e).map(|_| ()),
            |e| e.storage().persistent().get(&DataKey::Oracle),
            Self::_ensure_not_paused,
            Self::_extend_persistent_ttl,
            |e, r, s, p, c| archive_round(e, r, s, p, c, DEFAULT_ARCHIVE_RETENTION),
            Self::_refund_under_threshold,
            Self::_resolve_updown_mode,
            Self::_resolve_precision_mode,
        )
    }

    /// Resolves Up/Down mode round using indexed per-user position keys.
    ///
    /// Reads: 1 (participants list) + N (individual positions).
    /// Migration fallback: if the participant list is empty but the legacy
    /// `UpDownPositions` map is present, the resolver iterates the legacy map
    /// — preserves correctness for any in-flight pre-migration round.
    /// Returns `true` when a one-sided pool was detected (winning side exists but
    /// losing pool is empty). The caller is responsible for emitting the event.
    fn _resolve_updown_mode(
        env: &Env,
        round: &Round,
        final_price: u128,
    ) -> Result<bool, ContractError> {
        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round.round_id))
            .unwrap_or(Vec::new(env));
        let participants = Self::sort_addresses(participants);

        let price_went_up = final_price > round.price_start;
        let price_went_down = final_price < round.price_start;
        let price_unchanged = final_price == round.price_start;

        // One-sided liquidity: winning side exists but losing pool is empty.
        // Policy: refund all participants — no fund loss, transparent outcome.
        let is_one_sided = (price_went_up && round.pool_down == 0 && round.pool_up > 0)
            || (price_went_down && round.pool_up == 0 && round.pool_down > 0);

        if !participants.is_empty() {
            if price_unchanged || is_one_sided {
                Self::_record_refunds_indexed(env, round.round_id, 0, &participants)?;
            } else if price_went_up {
                Self::_record_winnings_indexed(
                    env,
                    round.round_id,
                    &participants,
                    BetSide::Up,
                    round.pool_up,
                    round.pool_down,
                )?;
            } else if price_went_down {
                Self::_record_winnings_indexed(
                    env,
                    round.round_id,
                    &participants,
                    BetSide::Down,
                    round.pool_down,
                    round.pool_up,
                )?;
            }
        } else {
            // Migration fallback: legacy single-map layout
            let positions: Map<Address, UserPosition> = env
                .storage()
                .persistent()
                .get(&DataKey::UpDownPositions)
                .unwrap_or(Map::new(env));
            if !positions.is_empty() {
                if price_unchanged {
                    Self::_record_refunds_legacy(env, round.round_id, &positions)?;
                } else if price_went_up {
                    Self::_record_winnings_legacy(
                        env,
                        round.round_id,
                        &positions,
                        BetSide::Up,
                        round.pool_up,
                        round.pool_down,
                    )?;
                } else if price_went_down {
                    Self::_record_winnings_legacy(
                        env,
                        round.round_id,
                        &positions,
                        BetSide::Down,
                        round.pool_down,
                        round.pool_up,
                    )?;
                }
            }
        }

        Ok(is_one_sided)
    }

    /// Legacy refund path — reads the bulk Map blob.
    /// Used only when migrating pre-existing rounds; new rounds use indexed keys.
    fn _record_refunds_legacy(
        env: &Env,
        round_id: u64,
        positions: &Map<Address, UserPosition>,
    ) -> Result<(), ContractError> {
        let keys: Vec<Address> = positions.keys();
        for i in 0..keys.len() {
            if let Some(user) = keys.get(i) {
                if let Some(position) = positions.get(user.clone()) {
                    Self::_accumulate_pending(env, user.clone(), position.amount)?;
                    let prediction_side = match position.side {
                        BetSide::Up => 0,
                        BetSide::Down => 1,
                    };
                    Self::_persist_user_outcome(
                        env,
                        round_id,
                        0,
                        &user,
                        prediction_side,
                        0,
                        position.amount,
                        position.amount,
                        UserOutcomeType::Refund,
                    );
                }
            }
        }
        Ok(())
    }

    /// Legacy winnings path — reads the bulk Map blob.
    ///
    /// `round_id` is threaded in so that the per-loser `("outcome", "loss")`
    /// observability event (Issue #168) emitted in the loser branch can carry
    /// the correct round identifier without an extra storage read.
    fn _record_winnings_legacy(
        env: &Env,
        round_id: u64,
        positions: &Map<Address, UserPosition>,
        winning_side: BetSide,
        winning_pool: i128,
        losing_pool: i128,
    ) -> Result<(), ContractError> {
        if winning_pool == 0 {
            return Ok(());
        }

        // Apply protocol fee (Issue #162); see `_record_winnings_indexed`.
        let (winning_pool, losing_pool, _fee_amount) =
            Self::_apply_protocol_fee_updown(env, round_id, winning_pool, losing_pool)?;

        let keys: Vec<Address> = positions.keys();
        for i in 0..keys.len() {
            if let Some(user) = keys.get(i) {
                if let Some(position) = positions.get(user.clone()) {
                    if position.side == winning_side {
                        // Compute all payout math before any storage write
                        let share_numerator = Self::payout_mul(position.amount, losing_pool)?;
                        let share = share_numerator / winning_pool;
                        let payout = Self::payout_add(position.amount, share)?;

                        Self::_accumulate_pending(env, user.clone(), payout)?;
                        Self::_update_stats_win(env, user.clone())?;

                        let side_value = match position.side {
                            BetSide::Up => 0,
                            BetSide::Down => 1,
                        };
                        Self::_persist_user_outcome(
                            env,
                            round_id,
                            0,
                            &user,
                            side_value,
                            0,
                            position.amount,
                            payout,
                            UserOutcomeType::Win,
                        );
                    } else {
                        // Emit outcome loss event for UpDown loser (Issue #168).
                        // Topic: ("outcome", "loss")
                        // Payload: (user, round_id, mode=0=UpDown, amount, side, predicted_price=0)
                        // `predicted_price` is fixed at 0 for UpDown since this
                        // field is only meaningful in Precision mode.
                        let side_value: u32 = match position.side {
                            BetSide::Up => 0,
                            BetSide::Down => 1,
                        };
                        #[allow(deprecated)]
                        env.events().publish(
                            (symbol_short!("outcome"), symbol_short!("loss")),
                            (
                                user.clone(),
                                round_id,
                                0u32,
                                position.amount,
                                side_value,
                                0u128,
                            ),
                        );
                        Self::_update_stats_loss(env, user.clone())?;

                        Self::_persist_user_outcome(
                            env,
                            round_id,
                            0,
                            &user,
                            side_value,
                            0,
                            position.amount,
                            0,
                            UserOutcomeType::Loss,
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn _resolve_precision_mode(
        env: &Env,
        round_id: u64,
        final_price: u128,
    ) -> Result<(), ContractError> {
        let mut participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::RoundParticipants(round_id))
            .unwrap_or(Vec::new(env));
        participants = Self::sort_addresses(participants);

        if participants.is_empty() {
            // Migration fallback to legacy bulk map
            let legacy: Map<Address, PrecisionPrediction> = env
                .storage()
                .persistent()
                .get(&DataKey::PrecisionPositions)
                .unwrap_or(Map::new(env));
            if legacy.is_empty() {
                return Ok(());
            }
            return Self::_resolve_precision_legacy(env, round_id, &legacy, final_price);
        }

        // Find minimum difference and collect all winners.
        //
        // We also cache `(amount, predicted_price)` per participant during this
        // first pass so the loser branch (which emits the `("outcome", "loss")`
        // observability event introduced by Issue #168) does not need to fetch
        // the same composite keys a second time. Halving the per-loser read
        // count is material for rounds at the participant cap (1 000).
        let mut min_diff: Option<u128> = None;
        let mut winners: Vec<PrecisionPrediction> = Vec::new(env);
        let mut total_pot: i128 = 0;
        // Per-participant snapshot of (amount, predicted_price-or-0-for-unrevealed).
        // Indexed by the same order as `participants`; each loser can be looked
        // up directly by its position without any extra storage access.
        let mut participant_amounts: Vec<i128> = Vec::new(env);
        let mut participant_prices: Vec<u128> = Vec::new(env);
        // Per-participant winner flag, populated in lockstep with the amount /
        // price snapshots above. Used by the loser branch to do O(N) winner
        // detection (instead of the O(N^2) `winners.iter().any(...)` lookup).
        // Index `i` corresponds to `participants[i]` by construction.
        let mut is_winner_mask: Vec<bool> = Vec::new(env);

        for i in 0..participants.len() {
            if let Some(user) = participants.get(i) {
                let pred_key = DataKey::PrecisionPosition(round_id, user.clone());
                let commit_key = DataKey::PrecisionCommitment(round_id, user.clone());

                let pred_opt = env
                    .storage()
                    .persistent()
                    .get::<_, PrecisionPrediction>(&pred_key);

                let commitment_opt = env
                    .storage()
                    .persistent()
                    .get::<_, PrecisionCommitment>(&commit_key);

                // Add amount to total pot from prediction (revealed) or commitment (unrevealed).
                // Also snapshot the amount and (revealed-or-zero) price so the
                // loser branch below can emit the loss event without re-reading.
                let amount = if let Some(ref pred) = pred_opt {
                    pred.amount
                } else if let Some(ref commit) = commitment_opt {
                    commit.amount
                } else {
                    0
                };
                let cached_price = pred_opt
                    .as_ref()
                    .map(|p| p.predicted_price)
                    .unwrap_or(0u128);

                total_pot = total_pot
                    .checked_add(amount)
                    .ok_or(ContractError::Overflow)?;
                participant_amounts.push_back(amount);
                participant_prices.push_back(cached_price);
                // Default to loser; flipped to `true` only when this
                // participant holds the currently smallest diff, and reset
                // to `false` if a tighter minimum is found later in the pass.
                is_winner_mask.push_back(false);

                if let Some(pred) = pred_opt {
                    let diff = if pred.predicted_price >= final_price {
                        pred.predicted_price
                            .checked_sub(final_price)
                            .ok_or(ContractError::Overflow)?
                    } else {
                        final_price
                            .checked_sub(pred.predicted_price)
                            .ok_or(ContractError::Overflow)?
                    };

                    match min_diff {
                        None => {
                            min_diff = Some(diff);
                            winners.push_back(pred.clone());
                            is_winner_mask.set(i, true);
                        }
                        Some(current_min) => {
                            if diff < current_min {
                                min_diff = Some(diff);
                                winners = Vec::new(env);
                                winners.push_back(pred.clone());
                                // Reset any prior winners; index `i` now holds
                                // the sole winning prediction.
                                for j in 0..i {
                                    is_winner_mask.set(j, false);
                                }
                                is_winner_mask.set(i, true);
                            } else if diff == current_min {
                                winners.push_back(pred.clone());
                                is_winner_mask.set(i, true);
                            }
                        }
                    }
                }
            }
        }

        // Distribute winnings to winner(s).
        // Remainder policy: `participants` is sorted lexicographically; `winners` is built
        // in that same sorted order, so index 0 is always the winner with the lowest Address.
        // Any integer remainder from the even split is assigned to that winner, making the
        // distribution fully deterministic.
        if !winners.is_empty() && total_pot > 0 {
            // Apply protocol fee (Issue #162) before splitting the pot.
            // Conservation invariant `distributable + fee == total_pot`.
            let (payout_pool, _fee_amount) =
                Self::_apply_protocol_fee_precision(env, round_id, total_pot)?;
            let winner_count = winners.len() as i128;
            let payout_per_winner = payout_pool / winner_count;
            let remainder = payout_pool % winner_count;

            // Award to each winner
            for i in 0..winners.len() {
                if let Some(winner) = winners.get(i) {
                    // First winner (lowest XDR-ordered Address) absorbs the remainder.
                    let payout = if i == 0 {
                        payout_per_winner
                            .checked_add(remainder)
                            .ok_or(ContractError::Overflow)?
                    } else {
                        payout_per_winner
                    };

                    Self::_accumulate_pending(env, winner.user.clone(), payout)?;
                    Self::_update_stats_win(env, winner.user.clone())?;

                    Self::_persist_user_outcome(
                        env,
                        round_id,
                        1,
                        &winner.user,
                        2,
                        winner.predicted_price,
                        winner.amount,
                        payout,
                        UserOutcomeType::Win,
                    );
                }
            }

            // Update stats and emit loss events for losers (Issue #168).
            //
            // The loss event payload mirrors [`Self::_record_winnings_indexed`]:
            // for Precision mode the relevant metadata is `predicted_price`,
            // so `side` is fixed at 0 while `mode = 1`.
            //
            // `stake` and `predicted_price` are read from the cached snapshot
            // populated during the winner-detection pass above, so this loop
            // does not need to re-read the per-user precision/commitment keys.
            //
            // Ordering note: the per-loser `("outcome", "loss")` event is
            // emitted BEFORE `_update_stats_loss` is called. Tests and indexers
            // rely on this sequence — flipping the order would change the
            // observable on-chain event stream for a loss-less winner-loss
            // pair.
            //
            // For unrevealed commitments the guess is unknowable on-chain
            // until reveal, so `predicted_price` is published as 0 to keep the
            // payload shape uniform across all losers.
            for i in 0..participants.len() {
                if let Some(user) = participants.get(i) {
                    // O(1) winner lookup; the mask is filled in lockstep with
                    // `participants` so the index is always valid.
                    let was_winner = is_winner_mask.get(i).unwrap_or(false);
                    if !was_winner {
                        // Snapshot-driven. By construction `participants`,
                        // `participant_amounts`, `participant_prices` and
                        // `is_winner_mask` are all pushed exactly once per
                        // iteration of the winner-detection pass above, so
                        // index drift between the two passes is impossible.
                        // `unwrap` would surface any future drift instead of
                        // silently publishing a 0-stake loss event.
                        let stake = participant_amounts.get(i).unwrap();
                        let predicted_price = participant_prices.get(i).unwrap();

                        // Emit outcome loss event for Precision loser (Issue #168).
                        // Topic: ("outcome", "loss")
                        // Payload: (user, round_id, mode=1=Precision, amount, side=0, predicted_price)
                        #[allow(deprecated)]
                        env.events().publish(
                            (symbol_short!("outcome"), symbol_short!("loss")),
                            (user.clone(), round_id, 1u32, stake, 0u32, predicted_price),
                        );
                        Self::_update_stats_loss(env, user.clone())?;

                         Self::_persist_user_outcome(
                             env,
                             round_id,
                             1,
                             &user,
                             2,
                             predicted_price,
                             stake,
                             0,
                             UserOutcomeType::Loss,
                         );
                    }
                }
            }
        }

        Ok(())
    }

    /// Legacy precision-mode resolution path — reads the bulk Map blob.
    /// Used only as a migration fallback; new rounds use indexed per-user keys.
    ///
    /// `round_id` is threaded in so the per-loser `("outcome", "loss")`
    /// observability event (Issue #168) carries the correct round id.
    fn _resolve_precision_legacy(
        env: &Env,
        round_id: u64,
        predictions_map: &Map<Address, PrecisionPrediction>,
        final_price: u128,
    ) -> Result<(), ContractError> {
        let predictions = predictions_map.values();
        if predictions.is_empty() {
            return Ok(());
        }

        let mut min_diff: Option<u128> = None;
        let mut winners: Vec<PrecisionPrediction> = Vec::new(env);

        for i in 0..predictions.len() {
            if let Some(pred) = predictions.get(i) {
                let diff = if pred.predicted_price >= final_price {
                    pred.predicted_price
                        .checked_sub(final_price)
                        .ok_or(ContractError::Overflow)?
                } else {
                    final_price
                        .checked_sub(pred.predicted_price)
                        .ok_or(ContractError::Overflow)?
                };

                match min_diff {
                    None => {
                        min_diff = Some(diff);
                        winners.push_back(pred.clone());
                    }
                    Some(current_min) => {
                        if diff < current_min {
                            min_diff = Some(diff);
                            winners = Vec::new(env);
                            winners.push_back(pred.clone());
                        } else if diff == current_min {
                            winners.push_back(pred.clone());
                        }
                    }
                }
            }
        }

        let mut total_pot: i128 = 0;
        for i in 0..predictions.len() {
            if let Some(pred) = predictions.get(i) {
                total_pot = Self::payout_add(total_pot, pred.amount)?;
            }
        }

        // Remainder policy: `predictions_map` is a `Map<Address, PrecisionPrediction>`, which
        // Soroban keeps sorted by XDR-encoded key bytes. `winners` is built by iterating
        // `predictions_map.values()` in that stable key order, so index 0 always refers to
        // the lexicographically-lowest Address. Any integer remainder from the even split is
        // assigned exclusively to that winner, making the distribution fully deterministic.
        if !winners.is_empty() && total_pot > 0 {
            // Apply protocol fee (Issue #162) before splitting the pot.
            let (payout_pool, _fee_amount) =
                Self::_apply_protocol_fee_precision(env, round_id, total_pot)?;
            let winner_count = winners.len() as i128;
            let payout_per_winner = payout_pool / winner_count;
            let remainder = payout_pool % winner_count;

            // Award to each winner — all arithmetic checked before writing
            for i in 0..winners.len() {
                if let Some(winner) = winners.get(i) {
                    let payout = if i == 0 {
                        Self::payout_add(payout_per_winner, remainder)?
                    } else {
                        payout_per_winner
                    };
                    Self::_accumulate_pending(env, winner.user.clone(), payout)?;
                    Self::_update_stats_win(env, winner.user.clone())?;

                    Self::_persist_user_outcome(
                        env,
                        round_id,
                        1,
                        &winner.user,
                        2,
                        winner.predicted_price,
                        winner.amount,
                        payout,
                        UserOutcomeType::Win,
                    );
                }
            }

            for i in 0..predictions.len() {
                if let Some(pred) = predictions.get(i) {
                    let is_winner = winners.iter().any(|w| w.user == pred.user);
                    if !is_winner {
                        // Emit outcome loss event for Precision loser (Issue #168).
                        // Topic: ("outcome", "loss")
                        // Payload: (user, round_id, mode=1=Precision, amount, side=0, predicted_price)
                        #[allow(deprecated)]
                        env.events().publish(
                            (symbol_short!("outcome"), symbol_short!("loss")),
                            (
                                pred.user.clone(),
                                round_id,
                                1u32,
                                pred.amount,
                                0u32,
                                pred.predicted_price,
                            ),
                        );
                        Self::_update_stats_loss(env, pred.user.clone())?;

                        Self::_persist_user_outcome(
                            env,
                            round_id,
                            1,
                            &pred.user,
                            2,
                            pred.predicted_price,
                            pred.amount,
                            0,
                            UserOutcomeType::Loss,
                        );
                    }
                }
            }
        }

        Ok(())
    }

    // ─── Lifecycle resilience (Issue #111) ──────────────────────────────────

    /// Cancels the active round and deterministically refunds all participant stakes.
    ///
    /// Only admin may cancel. Intended for oracle-unavailable or emergency recovery
    /// scenarios. After cancellation:
    ///  - All participant stakes are moved to their pending winnings.
    ///  - The active round is removed; no future settlement is possible.
    ///  - The round ID is marked cancelled to prevent any replay.
    pub fn cancel_round(env: Env, reason: u32) -> Result<(), ContractError> {
        cancel_round(
            &env,
            reason,
            |e| e.storage().persistent().get(&DataKey::Admin),
            |e| Self::_require_supported_schema(e).map(|_| ()),
            Self::_accumulate_pending,
            |e, rid, rm, u, ps, pp, s, p, o| {
                Self::_persist_user_outcome(e, rid, rm, u, ps, pp, s, p, o)
            },
            |e, r, s, p, c| archive_round(e, r, s, p, c, DEFAULT_ARCHIVE_RETENTION),
        )
    }

    /// Returns true if the given round_id was cancelled.
    pub fn is_round_cancelled(env: Env, round_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::CancelledRound(round_id))
            .unwrap_or(false)
    }

    /// Claims pending winnings and adds to balance
    pub fn claim_winnings(env: Env, user: Address) -> Result<i128, ContractError> {
        Self::_require_supported_schema(&env)?;
        user.require_auth();
        Self::_ensure_not_paused(&env)?;

        let key = DataKey::PendingWinnings(user.clone());
        let pending: i128 = env.storage().persistent().get(&key).unwrap_or(0);

        if pending == 0 {
            return Ok(0);
        }

        let current_balance = Self::balance(env.clone(), user.clone());
        // Compute new balance before writing — all-or-nothing guarantee
        let new_balance = Self::payout_add(current_balance, pending)?;

        // Remove pending winnings before increasing balance (CEI pattern)
        env.storage().persistent().remove(&key);
        Self::_set_balance(&env, user.clone(), new_balance);

        // Emit claim event
        // Topic: ("claim", "winnings")
        // Payload: (user: Address, amount: i128)
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("claim"), symbol_short!("winnings")),
            (user, pending),
        );

        Ok(pending)
    }

    /// Records refunds when price unchanged — indexed variant.
    ///
    /// Reads N individual position keys (O(1) each); no full-map deserialisation.
    fn _record_refunds_indexed(
        env: &Env,
        round_id: u64,
        round_mode: u32,
        participants: &Vec<Address>,
    ) -> Result<(), ContractError> {
        for i in 0..participants.len() {
            if let Some(user) = participants.get(i) {
                let pos_key = DataKey::Position(round_id, user.clone());
                if let Some(position) = env.storage().persistent().get::<_, UserPosition>(&pos_key) {
                    Self::_accumulate_pending(env, user.clone(), position.amount)?;
                    let prediction_side = match position.side {
                        BetSide::Up => 0,
                        BetSide::Down => 1,
                    };
                    Self::_persist_user_outcome(
                        env,
                        round_id,
                        round_mode,
                        &user,
                        prediction_side,
                        0,
                        position.amount,
                        position.amount,
                        UserOutcomeType::Refund,
                    );
                }
            }
        }
        Ok(())
    }

    /// Records winnings for winning side — indexed variant.
    ///
    /// Formula: payout = bet + (bet / winning_pool) * losing_pool
    /// Reads N individual position keys; no full-map deserialisation.
    ///
    /// Also emits a per-loser `("outcome", "loss")` event (Issue #168) so
    /// indexers no longer need to infer losses from absence of payout
    /// events.
    fn _record_winnings_indexed(
        env: &Env,
        round_id: u64,
        participants: &Vec<Address>,
        winning_side: BetSide,
        winning_pool: i128,
        losing_pool: i128,
    ) -> Result<(), ContractError> {
        if winning_pool == 0 {
            return Ok(());
        }

        // Apply protocol fee (Issue #162). Conservation invariant
        // `dist_winning + dist_losing + fee == winning + losing` always
        // holds; in the pathological case `fee > losing_pool` the spillover
        // is taken from `winning_pool`. Fee event already emitted inside
        // the helper.
        let (winning_pool, losing_pool, _fee_amount) =
            Self::_apply_protocol_fee_updown(env, round_id, winning_pool, losing_pool)?;

        for i in 0..participants.len() {
            if let Some(user) = participants.get(i) {
                let pos_key = DataKey::Position(round_id, user.clone());
                if let Some(position) = env.storage().persistent().get::<_, UserPosition>(&pos_key) {
                    if position.side == winning_side {
                        // Compute all payout math before any storage write
                        let share_numerator = Self::payout_mul(position.amount, losing_pool)?;
                        let share = share_numerator / winning_pool;
                        let payout = Self::payout_add(position.amount, share)?;

                        Self::_accumulate_pending(env, user.clone(), payout)?;
                        Self::_update_stats_win(env, user.clone())?;

                        let side_value = match position.side {
                            BetSide::Up => 0,
                            BetSide::Down => 1,
                        };
                        Self::_persist_user_outcome(
                            env,
                            round_id,
                            0,
                            &user,
                            side_value,
                            0,
                            position.amount,
                            payout,
                            UserOutcomeType::Win,
                        );
                    } else {
                        // Emit outcome loss event for UpDown loser (Issue #168).
                        // Topic: ("outcome", "loss")
                        // Payload: (user, round_id, mode=0=UpDown, amount, side, predicted_price=0)
                        // `predicted_price` is fixed at 0 for UpDown since this
                        // field is only meaningful in Precision mode.
                        let side_value: u32 = match position.side {
                            BetSide::Up => 0,
                            BetSide::Down => 1,
                        };
                        #[allow(deprecated)]
                        env.events().publish(
                            (symbol_short!("outcome"), symbol_short!("loss")),
                            (
                                user.clone(),
                                round_id,
                                0u32,
                                position.amount,
                                side_value,
                                0u128,
                            ),
                        );
                        Self::_update_stats_loss(env, user.clone())?;

                        Self::_persist_user_outcome(
                            env,
                            round_id,
                            0,
                            &user,
                            side_value,
                            0,
                            position.amount,
                            0,
                            UserOutcomeType::Loss,
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Persists a compact round summary and enforces FIFO archive retention.
    fn _archive_round(
        env: &Env,
        round: &Round,
        status: RoundArchiveStatus,
        final_price: u128,
        participant_count: u32,
    ) {
        archive_round(env, round, status, final_price, participant_count, DEFAULT_ARCHIVE_RETENTION)
    }

    fn _persist_user_outcome(
        env: &Env,
        round_id: u64,
        round_mode: u32,
        user: &Address,
        prediction_side: u32,
        predicted_price: u128,
        stake: i128,
        payout: i128,
        outcome: UserOutcomeType,
    ) {
        crate::settlement::persist_user_outcome(
            env,
            round_id,
            round_mode,
            user,
            prediction_side,
            predicted_price,
            stake,
            payout,
            outcome,
            Self::_extend_persistent_ttl,
        )
    }

    /// Refunds all participant stakes when the minimum-participants threshold is not met.
    /// Performs the same key cleanup as normal resolution so the contract is left consistent.
    fn _refund_under_threshold(
        env: &Env,
        round: &Round,
        participants: &Vec<Address>,
    ) -> Result<(), ContractError> {
        let round_id = round.round_id;
        let round_mode = match round.mode {
            RoundMode::UpDown => 0,
            RoundMode::Precision => 1,
        };
        match round.mode {
            RoundMode::UpDown => {
                for i in 0..participants.len() {
                    if let Some(user) = participants.get(i) {
                        let pos_key = DataKey::Position(round_id, user.clone());
                        if let Some(pos) =
                            env.storage().persistent().get::<_, UserPosition>(&pos_key)
                        {
                            Self::_accumulate_pending(env, user.clone(), pos.amount)?;
                            let prediction_side = match pos.side {
                                BetSide::Up => 0,
                                BetSide::Down => 1,
                            };
                            Self::_persist_user_outcome(
                                env,
                                round_id,
                                round_mode,
                                &user,
                                prediction_side,
                                0,
                                pos.amount,
                                pos.amount,
                                UserOutcomeType::Refund,
                            );
                        }
                    }
                }
            }
            RoundMode::Precision => {
                for i in 0..participants.len() {
                    if let Some(user) = participants.get(i) {
                        let pred_key = DataKey::PrecisionPosition(round_id, user.clone());
                        if let Some(pred) = env
                            .storage()
                            .persistent()
                            .get::<_, PrecisionPrediction>(&pred_key)
                        {
                            Self::_accumulate_pending(env, user.clone(), pred.amount)?;
                            Self::_persist_user_outcome(
                                env,
                                round_id,
                                round_mode,
                                &user,
                                2,
                                0,
                                pred.amount,
                                pred.amount,
                                UserOutcomeType::Refund,
                            );
                        }
                    }
                }
            }
        }
        for i in 0..participants.len() {
            if let Some(user) = participants.get(i) {
                env.storage()
                    .persistent()
                    .remove(&DataKey::Position(round_id, user.clone()));
                env.storage()
                    .persistent()
                    .remove(&DataKey::PrecisionPosition(round_id, user));
            }
        }
        env.storage()
            .persistent()
            .remove(&DataKey::RoundParticipants(round_id));
        env.storage().persistent().remove(&DataKey::ActiveRound);
        env.storage().persistent().remove(&DataKey::Positions);
        env.storage().persistent().remove(&DataKey::UpDownPositions);
        env.storage()
            .persistent()
            .remove(&DataKey::PrecisionPositions);
        Ok(())
    }

    pub(crate) fn _update_stats_win(env: &Env, user: Address) -> Result<(), ContractError> {
        let key = DataKey::UserStats(user);
        let mut stats: UserStats = env.storage().persistent().get(&key).unwrap_or(UserStats {
            total_wins: 0,
            total_losses: 0,
            current_streak: 0,
            best_streak: 0,
        });

        stats.total_wins = stats
            .total_wins
            .checked_add(1)
            .ok_or(ContractError::Overflow)?;
        stats.current_streak = stats
            .current_streak
            .checked_add(1)
            .ok_or(ContractError::Overflow)?;

        if stats.current_streak > stats.best_streak {
            stats.best_streak = stats.current_streak;
        }

        env.storage().persistent().set(&key, &stats);
        Self::_extend_persistent_ttl(env, &key);
        Ok(())
    }

    pub(crate) fn _update_stats_loss(env: &Env, user: Address) -> Result<(), ContractError> {
        let key = DataKey::UserStats(user);
        let mut stats: UserStats = env.storage().persistent().get(&key).unwrap_or(UserStats {
            total_wins: 0,
            total_losses: 0,
            current_streak: 0,
            best_streak: 0,
        });

        stats.total_losses = stats
            .total_losses
            .checked_add(1)
            .ok_or(ContractError::Overflow)?;
        stats.current_streak = 0;

        env.storage().persistent().set(&key, &stats);
        Self::_extend_persistent_ttl(env, &key);
        Ok(())
    }

    /// Mints 1000 vXLM for new users (one-time only)
    pub fn mint_initial(env: Env, user: Address) -> i128 {
        user.require_auth();
        if let Err(e) = Self::_require_supported_schema(&env) {
            panic_with_error!(&env, e);
        }
        if Self::is_paused(env.clone()) {
            panic_with_error!(&env, ContractError::ContractPaused);
        }

        let key = DataKey::Balance(user.clone());

        if let Some(existing_balance) = env.storage().persistent().get(&key) {
            Self::_extend_persistent_ttl(&env, &key);
            return existing_balance;
        }

        // Rate limit check: retrieve current ledger height and check against limit config.
        let sequence = env.ledger().sequence();
        if let Some(limit) = env
            .storage()
            .instance()
            .get::<_, u32>(&DataKey::MintLimitConfig)
        {
            if limit > 0 {
                let counter_key = DataKey::LedgerMintCounter(sequence);
                let current_count = env
                    .storage()
                    .temporary()
                    .get::<_, u32>(&counter_key)
                    .unwrap_or(0);
                if current_count >= limit {
                    panic_with_error!(&env, ContractError::MintLimitExceeded);
                }
                env.storage()
                    .temporary()
                    .set(&counter_key, &(current_count + 1));
            }
        }

        let initial_amount: i128 = 1000_0000000;
        env.storage().persistent().set(&key, &initial_amount);
        Self::_extend_persistent_ttl(&env, &key);

        // Emit mint event
        // Topic: ("mint", "initial")
        // Payload: (user: Address, amount: i128)
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("mint"), symbol_short!("initial")),
            (user, initial_amount),
        );

        initial_amount
    }

    /// Returns user's vXLM balance
    pub fn balance(env: Env, user: Address) -> i128 {
        let key = DataKey::Balance(user);
        Self::_extend_persistent_ttl(&env, &key);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub(crate) fn _set_balance(env: &Env, user: Address, amount: i128) {
        let key = DataKey::Balance(user);
        env.storage().persistent().set(&key, &amount);
        Self::_extend_persistent_ttl(env, &key);
    }

    fn _ensure_not_paused(env: &Env) -> Result<(), ContractError> {
        Self::_extend_persistent_ttl(env, &DataKey::Paused);
        if Self::is_paused(env.clone()) {
            return Err(ContractError::ContractPaused);
        }

        Ok(())
    }

    /// Derives the round lifecycle phase for `round` at `ledger_sequence`.
    fn _derive_round_phase(ledger_sequence: u32, round: &Round) -> RoundPhase {
        if ledger_sequence < round.bet_end_ledger {
            RoundPhase::Betting
        } else if ledger_sequence < round.end_ledger {
            RoundPhase::Running
        } else {
            RoundPhase::Resolvable
        }
    }

    fn _schema_version(env: &Env) -> Option<u32> {
        env.storage().persistent().get(&DataKey::SchemaVersion)
    }

    fn _require_supported_schema(env: &Env) -> Result<u32, ContractError> {
        Self::_extend_persistent_ttl(env, &DataKey::SchemaVersion);
        if env.storage().persistent().has(&DataKey::Admin) {
            Self::_extend_persistent_ttl(env, &DataKey::Admin);
        }
        let v = Self::_schema_version(env).unwrap_or(1);
        if v == 0 || v > CURRENT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchemaVersion);
        }
        Ok(v)
    }

    fn assert_no_active_round(env: &Env) -> Result<(), ContractError> {
        if env.storage().persistent().has(&DataKey::ActiveRound) {
            return Err(ContractError::RoundAlreadyActive);
        }

        Ok(())
    }

    /// Checked addition for payout accumulation.
    ///
    /// All payout aggregation (refunds, winnings, precision payouts) routes
    /// through this helper so overflow always maps to the stable
    /// `PayoutOverflow` variant rather than a generic `Overflow`. This makes
    /// the failure mode auditable and distinguishable from non-financial
    /// overflow (e.g. round-ID counter, ledger arithmetic).
    ///
    /// All-or-nothing guarantee: callers must not mutate storage before all
    /// payout math is complete and checked. The functions below enforce this
    /// by computing the new value first and only writing it afterward.
    #[inline(always)]
    fn payout_add(a: i128, b: i128) -> Result<i128, ContractError> {
        a.checked_add(b).ok_or(ContractError::PayoutOverflow)
    }

    #[inline(always)]
    fn payout_mul(a: i128, b: i128) -> Result<i128, ContractError> {
        a.checked_mul(b).ok_or(ContractError::PayoutOverflow)
    }

    /// Accumulates `amount` into a user's pending winnings, enforcing the cap if set (Issue #120).
    ///
    /// Reads and writes `DataKey::PendingWinnings(user)` in one place, ensuring the cap
    /// check and overflow protection are applied consistently across all payout paths.
    fn _accumulate_pending(env: &Env, user: Address, amount: i128) -> Result<(), ContractError> {
        let key = DataKey::PendingWinnings(user);
        let existing: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_pending = Self::payout_add(existing, amount)?;

        // Enforce pending winnings cap if configured
        if let Some(cap) = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::MaxPendingWinnings)
        {
            if new_pending > cap {
                return Err(ContractError::PendingWinningsCapExceeded);
            }
        }

        env.storage().persistent().set(&key, &new_pending);
        Self::_extend_persistent_ttl(env, &key);
        Ok(())
    }

    fn _validate_windows(bet_ledgers: u32, run_ledgers: u32) -> Result<(), ContractError> {
        if bet_ledgers == 0 || run_ledgers == 0 {
            return Err(ContractError::InvalidDuration);
        }
        if bet_ledgers > MAX_BET_WINDOW_LEDGERS || run_ledgers > MAX_RUN_WINDOW_LEDGERS {
            return Err(ContractError::WindowOutOfRange);
        }
        if bet_ledgers >= run_ledgers {
            return Err(ContractError::InvalidDuration);
        }
        Ok(())
    }

    fn _validate_max_stake(max_amount: Option<i128>) -> Result<(), ContractError> {
        if let Some(v) = max_amount {
            if v < MIN_CAP_VALUE {
                return Err(ContractError::InvalidBetAmount);
            }
        }
        Ok(())
    }

    fn _validate_oracle_stale_threshold(seconds: u64) -> Result<(), ContractError> {
        if !(MIN_ORACLE_STALE_THRESHOLD..=MAX_ORACLE_STALE_THRESHOLD).contains(&seconds) {
            return Err(ContractError::InvalidStaleThreshold);
        }
        Ok(())
    }

    fn _validate_oracle_max_deviation_bps(bps: Option<u32>) -> Result<(), ContractError> {
        if let Some(v) = bps {
            if v == 0 || v > MAX_ORACLE_DEVIATION_BPS {
                return Err(ContractError::InvalidOracleDeviationBps);
            }
        }
        Ok(())
    }

    /// Validates a requested protocol-fee bps (Issue #162).
    /// `None` always allowed (disables fee entirely, restoring pre-#162
    /// byte-for-byte behaviour). `Some(0)` is rejected — only explicit `None`
    /// is the legitimate way to express "fee disabled". `Some(bps)` must
    /// satisfy `1 <= bps <= MAX_PROTOCOL_FEE_BPS`.
    fn _validate_protocol_fee_bps(bps: Option<u32>) -> Result<(), ContractError> {
        if let Some(v) = bps {
            if v == 0 || v > MAX_PROTOCOL_FEE_BPS {
                return Err(ContractError::InvalidProtocolFeeBps);
            }
        }
        Ok(())
    }

    /// Reads the currently-configured protocol fee in bps (Issue #162).
    /// Bumps TTL only when the key is present (avoids extra storage writes
    /// on the hot "fee disabled" path through every competitive settlement).
    fn _read_protocol_fee_bps(env: &Env) -> Option<u32> {
        let key = DataKey::ProtocolFeeBps;
        let v: Option<u32> = env.storage().persistent().get(&key);
        if v.is_some() {
            Self::_extend_persistent_ttl(env, &key);
        }
        v
    }

    /// Credits `fee_amount` stroops to the protocol fee treasury and emits
    /// `("protocol", "fee_collected")` (Issue #162). TTL on the treasury
    /// key is extended on every write so the cumulative balance never
    /// falls into archival. Payload mirrors the active bps so indexers
    /// do not need an extra storage read.
    fn _collect_protocol_fee(
        env: &Env,
        round_id: u64,
        fee_amount: i128,
        bps_active: Option<u32>,
    ) -> Result<(), ContractError> {
        if fee_amount <= 0 {
            return Ok(());
        }
        let treasury_key = DataKey::ProtocolFeeTreasury;
        let current: i128 = env.storage().persistent().get(&treasury_key).unwrap_or(0);
        let new_treasury = current
            .checked_add(fee_amount)
            .ok_or(ContractError::Overflow)?;
        env.storage().persistent().set(&treasury_key, &new_treasury);
        Self::_extend_persistent_ttl(env, &treasury_key);

        let bps_value: u32 = bps_active.unwrap_or(0);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("protocol"), symbol_short!("fee_coll")),
            (round_id, fee_amount, new_treasury, bps_value),
        );

        Ok(())
    }

    /// Splits a `(winning_pool, losing_pool)` pair into the post-fee pools
    /// and the treasury's cut, used by both UpDown settlement paths
    /// (Issue #162). Conservation invariant
    ///   dist_winning + dist_losing + fee == winning + losing
    /// holds ALWAYS, even in the pathological case `fee > losing_pool`
    /// (very thin losing-side liquidity near the bps cap): the spillover
    /// is then deducted from `winning_pool`, so winners lose a portion
    /// of their principal rather than the fee being silently dropped.
    /// Behaviour is documented in `docs/EVENT_SCHEMA.md` and exercised
    /// by `test_protocol_fee_thin_losing_pool`.
    fn _apply_protocol_fee_updown(
        env: &Env,
        round_id: u64,
        winning_pool: i128,
        losing_pool: i128,
    ) -> Result<(i128, i128, i128), ContractError> {
        let bps = Self::_read_protocol_fee_bps(env);
        if bps.is_none() {
            return Ok((winning_pool, losing_pool, 0));
        }
        let bps_value = bps.unwrap();
        let total_pot = Self::payout_add(winning_pool, losing_pool)?;
        let fee_amount = total_pot
            .checked_mul(bps_value as i128)
            .ok_or(ContractError::Overflow)?
            / BPS_DENOMINATOR;
        if fee_amount == 0 {
            return Ok((winning_pool, losing_pool, 0));
        }
        let fee_from_losing = fee_amount.min(losing_pool);
        let fee_from_winning = fee_amount
            .checked_sub(fee_from_losing)
            .ok_or(ContractError::Overflow)?;
        let dist_winning = winning_pool
            .checked_sub(fee_from_winning)
            .ok_or(ContractError::Overflow)?;
        let dist_losing = losing_pool
            .checked_sub(fee_from_losing)
            .ok_or(ContractError::Overflow)?;
        Self::_collect_protocol_fee(env, round_id, fee_amount, Some(bps_value))?;
        Ok((dist_winning, dist_losing, fee_amount))
    }

    /// Splits a precision-mode `total_pot` into the distributable amount
    /// (split among winners per the existing remainder policy) and the
    /// treasury's cut (Issue #162). Returns `(distributable, fee_amount)`.
    fn _apply_protocol_fee_precision(
        env: &Env,
        round_id: u64,
        total_pot: i128,
    ) -> Result<(i128, i128), ContractError> {
        let bps = Self::_read_protocol_fee_bps(env);
        if bps.is_none() || total_pot <= 0 {
            return Ok((total_pot, 0));
        }
        let bps_value = bps.unwrap();
        let fee_amount = total_pot
            .checked_mul(bps_value as i128)
            .ok_or(ContractError::Overflow)?
            / BPS_DENOMINATOR;
        let distributable = total_pot
            .checked_sub(fee_amount)
            .ok_or(ContractError::Overflow)?;
        if fee_amount > 0 {
            Self::_collect_protocol_fee(env, round_id, fee_amount, Some(bps_value))?;
        }
        Ok((distributable, fee_amount))
    }

    fn _emit_config_updated(
        env: &Env,
        kind: ConfigChangeKind,
        old_value: ConfigChangePayload,
        new_value: ConfigChangePayload,
    ) {
        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("config"), symbol_short!("updated")),
            (kind, old_value, new_value),
        );
    }

    fn _current_config_payload(env: &Env, kind: &ConfigChangeKind) -> ConfigChangePayload {
        match kind {
            ConfigChangeKind::Windows => {
                let bet: u32 = env
                    .storage()
                    .persistent()
                    .get(&DataKey::BetWindowLedgers)
                    .unwrap_or(DEFAULT_BET_WINDOW_LEDGERS);
                let run: u32 = env
                    .storage()
                    .persistent()
                    .get(&DataKey::RunWindowLedgers)
                    .unwrap_or(DEFAULT_RUN_WINDOW_LEDGERS);
                ConfigChangePayload::Windows(bet, run)
            }
            ConfigChangeKind::MaxStake => {
                ConfigChangePayload::MaxStake(env.storage().persistent().get(&DataKey::MaxStake))
            }
            ConfigChangeKind::MaxUserRoundExposure => ConfigChangePayload::MaxUserRoundExposure(
                env.storage()
                    .persistent()
                    .get(&DataKey::MaxUserRoundExposure),
            ),
            ConfigChangeKind::MaxPendingWinnings => ConfigChangePayload::MaxPendingWinnings(
                env.storage().persistent().get(&DataKey::MaxPendingWinnings),
            ),
            ConfigChangeKind::OracleStaleThreshold => ConfigChangePayload::OracleStaleThreshold(
                env.storage()
                    .persistent()
                    .get(&DataKey::OracleStaleThreshold)
                    .unwrap_or(DEFAULT_ORACLE_STALE_THRESHOLD),
            ),
            ConfigChangeKind::OracleMaxDeviationBps => ConfigChangePayload::OracleMaxDeviationBps(
                env.storage()
                    .persistent()
                    .get(&DataKey::OracleMaxDeviationBps),
            ),
            ConfigChangeKind::ProtocolFeeBps => ConfigChangePayload::ProtocolFeeBps(
                env.storage().persistent().get(&DataKey::ProtocolFeeBps),
            ),
            ConfigChangeKind::MinParticipants => ConfigChangePayload::MinParticipants(
                env.storage().persistent().get(&DataKey::MinParticipants),
            ),
            ConfigChangeKind::MaxPrecisionParticipants => {
                ConfigChangePayload::MaxPrecisionParticipants(
                    env.storage()
                        .persistent()
                        .get(&DataKey::MaxPrecisionParticipants)
                        .unwrap_or(DEFAULT_MAX_PRECISION_PARTICIPANTS),
                )
            }
            ConfigChangeKind::MintLimit => ConfigChangePayload::MintLimit(
                env.storage()
                    .instance()
                    .get(&DataKey::MintLimitConfig)
                    .unwrap_or(0),
            ),
            ConfigChangeKind::ArchiveRetention => ConfigChangePayload::ArchiveRetention(
                env.storage()
                    .persistent()
                    .get(&DataKey::ArchiveRetention)
                    .unwrap_or(DEFAULT_ARCHIVE_RETENTION),
            ),
        }
    }

    fn _schedule_config_change(
        env: &Env,
        kind: ConfigChangeKind,
        payload: ConfigChangePayload,
    ) -> Result<(), ContractError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ContractError::AdminNotSet)?;
        admin.require_auth();
        Self::_ensure_not_paused(env)?;

        let key = DataKey::PendingConfigChange(kind.clone());
        if env.storage().persistent().has(&key) {
            return Err(ContractError::RoundAlreadyActive);
        }

        let scheduled_at_ledger = env.ledger().sequence();
        let activation_ledger = scheduled_at_ledger
            .checked_add(CONFIG_TIMELOCK_LEDGERS)
            .ok_or(ContractError::Overflow)?;

        let pending = PendingConfigChange {
            payload,
            activation_ledger,
            scheduled_at_ledger,
        };
        env.storage().persistent().set(&key, &pending);
        Self::_extend_persistent_ttl(env, &key);

        #[allow(deprecated)]
        env.events().publish(
            (symbol_short!("config"), symbol_short!("sched")),
            (kind, activation_ledger),
        );

        Ok(())
    }

    fn _apply_config_payload(
        env: &Env,
        kind: &ConfigChangeKind,
        payload: &ConfigChangePayload,
    ) -> Result<(), ContractError> {
        let old_value = Self::_current_config_payload(env, kind);
        match (kind, payload) {
            (ConfigChangeKind::Windows, ConfigChangePayload::Windows(bet, run)) => {
                Self::_validate_windows(*bet, *run)?;
                env.storage()
                    .persistent()
                    .set(&DataKey::BetWindowLedgers, bet);
                Self::_extend_persistent_ttl(env, &DataKey::BetWindowLedgers);
                env.storage()
                    .persistent()
                    .set(&DataKey::RunWindowLedgers, run);
                Self::_extend_persistent_ttl(env, &DataKey::RunWindowLedgers);
                #[allow(deprecated)]
                env.events().publish(
                    (symbol_short!("windows"), symbol_short!("updated")),
                    (*bet, *run),
                );
            }
            (ConfigChangeKind::MaxStake, ConfigChangePayload::MaxStake(max)) => {
                Self::_validate_max_stake(*max)?;
                let key = DataKey::MaxStake;
                if let Some(v) = max {
                    env.storage().persistent().set(&key, v);
                    Self::_extend_persistent_ttl(env, &key);
                } else {
                    env.storage().persistent().remove(&key);
                }
            }
            (
                ConfigChangeKind::MaxUserRoundExposure,
                ConfigChangePayload::MaxUserRoundExposure(max),
            ) => {
                Self::_validate_max_stake(*max)?;
                let key = DataKey::MaxUserRoundExposure;
                if let Some(v) = max {
                    env.storage().persistent().set(&key, v);
                    Self::_extend_persistent_ttl(env, &key);
                } else {
                    env.storage().persistent().remove(&key);
                }
            }
            (
                ConfigChangeKind::MaxPendingWinnings,
                ConfigChangePayload::MaxPendingWinnings(max),
            ) => {
                Self::_validate_max_stake(*max)?;
                let key = DataKey::MaxPendingWinnings;
                if let Some(v) = max {
                    env.storage().persistent().set(&key, v);
                    Self::_extend_persistent_ttl(env, &key);
                } else {
                    env.storage().persistent().remove(&key);
                }
            }
            (
                ConfigChangeKind::OracleStaleThreshold,
                ConfigChangePayload::OracleStaleThreshold(seconds),
            ) => {
                Self::_validate_oracle_stale_threshold(*seconds)?;
                let key = DataKey::OracleStaleThreshold;
                env.storage().persistent().set(&key, seconds);
                Self::_extend_persistent_ttl(env, &key);
            }
            (
                ConfigChangeKind::OracleMaxDeviationBps,
                ConfigChangePayload::OracleMaxDeviationBps(bps),
            ) => {
                Self::_validate_oracle_max_deviation_bps(*bps)?;
                let key = DataKey::OracleMaxDeviationBps;
                if let Some(v) = bps {
                    env.storage().persistent().set(&key, v);
                    Self::_extend_persistent_ttl(env, &key);
                } else {
                    env.storage().persistent().remove(&key);
                }
            }

            (ConfigChangeKind::ProtocolFeeBps, ConfigChangePayload::ProtocolFeeBps(bps)) => {
                Self::_validate_protocol_fee_bps(*bps)?;
                let key = DataKey::ProtocolFeeBps;
                if let Some(v) = bps {
                    env.storage().persistent().set(&key, v);
                    Self::_extend_persistent_ttl(env, &key);
                } else {
                    env.storage().persistent().remove(&key);
                }
                #[allow(deprecated)]
                env.events().publish(
                    (symbol_short!("protocol"), symbol_short!("fee_bps")),
                    (bps.clone(),),
                );
            }
            _ => return Err(ContractError::InvalidMode),
        }
        Self::_emit_config_updated(env, kind.clone(), old_value, payload.clone());
        Ok(())
    }

    /// Bumps/extends the TTL of the given persistent storage key if its remaining TTL
    /// is less than the threshold. Enforces rent policy (Issue #142).
    fn _extend_persistent_ttl(env: &Env, key: &DataKey) {
        if env.storage().persistent().has(key) {
            env.storage()
                .persistent()
                .extend_ttl(key, TTL_BUMP_THRESHOLD, TTL_BUMP_AMOUNT);
        }
    }

    fn sort_addresses(addresses: Vec<Address>) -> Vec<Address> {
        let mut sorted = Vec::new(addresses.env());
        for addr in addresses.iter() {
            let mut inserted = false;
            for i in 0..sorted.len() {
                if addr < sorted.get_unchecked(i) {
                    sorted.insert(i, addr.clone());
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                sorted.push_back(addr);
            }
        }
        sorted
    }
}
