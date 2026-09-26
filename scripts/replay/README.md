# Deterministic Round Replay (Issue #369)

Offline tooling to recompute Xelma round outcomes from a canonical input transcript.
Replay uses the same `settlement_math` code path as live settlement via the
`xelma-replay` workspace crate.

## Quick start

```bash
# Run all replay parity tests (golden + property)
cargo test -p xelma-replay

# Build the CLI
cargo build -p xelma-replay --release

# Verify a transcript (live == replay)
./scripts/replay/replay.sh replay-engine/fixtures/updown_resolve_golden.json

# Print transcript SHA-256 commitment
./scripts/replay/replay.sh --hash replay-engine/fixtures/updown_cancel.json
```

## Transcript schema (v1)

| Field | Description |
|-------|-------------|
| `schema_version` | Must be `1` |
| `mode` | `updown` or `precision` |
| `terminal` | `resolve`, `cancel`, `void`, `fallback_refund` |
| `participants` | Sorted by ascending `index` (canonical ordering) |
| `oracle` | Settlement price payload (`price`, `timestamp`, `round_id`, `nonce`) |
| `expected` | Live outcome captured at record time; replay must match |

Each participant row includes stake `amount`, optional UpDown `side_up`, and
commit/reveal fields (`revealed`, `predicted_price`, optional `commit_hash_hex`).

## Terminal paths

- **resolve** — runs `compute_updown_payouts` or `compute_precision_payouts`
- **cancel** / **void** — full stake refund (`void` outcome)
- **fallback_refund** — full refund when `participant_count < min_participants`

## Mismatch diagnostics

When verification fails, the CLI prints field-level diffs (`archive_status`,
`total_fee`, per-participant `payout` / `outcome`).

## Hash commitments

`transcript_commitment_hex` SHA-256-hashes the canonical JSON encoding. Use
`--hash` to obtain an audit anchor without re-running settlement math.

## Layout

```
replay-engine/          Rust crate (transcript, hash, engine, tests)
replay-engine/fixtures/ Golden transcripts
scripts/replay/         Shell wrapper + this README
```
