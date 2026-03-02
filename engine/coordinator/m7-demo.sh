#!/usr/bin/env bash
# Milestone 7 end-to-end demo: the ON-CHAIN signing request drives the REAL
# NETWORKED operators (the M6 separate-process GG20 set, over authenticated TCP),
# the resulting signature is recorded on-chain, and it INDEPENDENTLY ecrecover-
# verifies to the group's Ethereum address. Plus a negative control: a required
# operator is dropped → the on-chain request gets NO valid signature (clean, no
# garbage). Localnet only; devnet is never touched.
#
#   cd engine/coordinator && ./m7-demo.sh
#
# Stands up a fresh solana-test-validator with the (reconciled M3) program,
# builds the net-demo coordinator + the M6 operator binaries, runs the full
# loop, then tears the validator down.
set -euo pipefail
cd "$(dirname "$0")"

export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:/opt/homebrew/bin:$PATH"
export COPYFILE_DISABLE=1   # macOS genesis-tar AppleDouble workaround (SHARED_NOTES)

PROGRAM_ID="4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6"
SO="../target/deploy/distin.so"
LEDGER="$(mktemp -d /tmp/distin-m7-ledger.XXXXXX)"
# NOTE: BSD/macOS mktemp does NOT expand X's when a suffix follows them, so the
# template must END in the X's (no ".log" after) — otherwise it makes a literal
# file that collides on the next run.
VLOG="$(mktemp /tmp/distin-m7-validator.XXXXXX)"

if [[ ! -f "$SO" ]]; then
  echo "missing program artifact $SO — build it first (cargo-build-sbf)"; exit 1
fi

cleanup() {
  [[ -n "${VALIDATOR_PID:-}" ]] && kill "$VALIDATOR_PID" 2>/dev/null || true
  wait "${VALIDATOR_PID:-}" 2>/dev/null || true
  rm -rf "$LEDGER"
}
trap cleanup EXIT

echo "### building the net-demo coordinator (release)"
cargo build --release --bin net-demo

echo
echo "### starting solana-test-validator with the reconciled program (localnet)"
solana-test-validator --reset --quiet --ledger "$LEDGER" \
  --bpf-program "$PROGRAM_ID" "$SO" >"$VLOG" 2>&1 &
VALIDATOR_PID=$!

echo "validator PID $VALIDATOR_PID; waiting for RPC to come up..."
for i in $(seq 1 60); do
  if solana --url http://127.0.0.1:8899 cluster-version >/dev/null 2>&1; then
    echo "RPC is up."
    break
  fi
  sleep 1
  if ! kill -0 "$VALIDATOR_PID" 2>/dev/null; then
    echo "validator died on startup; log:"; tail -20 "$VLOG"; exit 1
  fi
done

echo "confirming the program is loaded on-chain:"
solana --url http://127.0.0.1:8899 program show "$PROGRAM_ID" || {
  echo "program not loaded"; exit 1; }

echo
echo "### running Milestone 7 — on-chain request → networked operators → on-chain → ecrecover"
echo
cargo run --release --bin net-demo

echo
echo "### M7 demo finished (exit 0). validator log: $VLOG"
