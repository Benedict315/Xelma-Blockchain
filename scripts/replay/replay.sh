#!/usr/bin/env bash
# One-command replay verifier for round transcripts (Issue #369).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

exec cargo run -q -p xelma-replay --bin xelma-replay -- "$@"
