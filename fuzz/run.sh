#!/usr/bin/env bash
# Run one cargo-fuzz target from its committed seeds: fuzz/run.sh <target> [seconds]
# (or `mise run fuzz <target> [seconds]`). Installs the pinned nightly on first use.
set -euo pipefail
NIGHTLY=nightly-2026-11-01
here="$(cd "$(dirname "$0")" && pwd)"
target="${1:?usage: fuzz/run.sh <target> [seconds]}"
secs="${2:-60}"
if ! rustup toolchain list | grep -q "^${NIGHTLY}"; then
  rustup toolchain install "$NIGHTLY" --profile minimal
fi
mkdir -p "$here/corpus/$target"
cd "$here"
cargo "+$NIGHTLY" fuzz run "$target" "corpus/$target" "seeds/$target" -- -max_total_time="$secs"
