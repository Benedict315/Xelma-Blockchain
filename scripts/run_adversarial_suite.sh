#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run the adversarial simulation suite and generate markdown + JSON reports (Issue #372).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUTPUT_DIR="${ADVERSARIAL_OUTPUT_DIR:-$ROOT/adversarial-reports}"
LOG="$OUTPUT_DIR/test-output.log"
mkdir -p "$OUTPUT_DIR"

echo "=== Adversarial Simulation Suite (Issue #372) ==="
echo "Output directory: $OUTPUT_DIR"
echo ""

cargo test --package xelma-contract --lib tests::adversarial --locked -- --nocapture 2>&1 | tee "$LOG"

python3 "$ROOT/scripts/adversarial_report.py" "$LOG" "$OUTPUT_DIR"

echo ""
echo "Reports:"
echo "  $OUTPUT_DIR/adversarial-report.md"
echo "  $OUTPUT_DIR/adversarial-report.json"
