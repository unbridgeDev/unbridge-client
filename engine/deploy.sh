#!/usr/bin/env bash
# Distin program deploy — reproducible SBF build + cluster deploy.
#
#   bash deploy.sh devnet     build + deploy to devnet
#   bash deploy.sh mainnet    build + deploy to mainnet-beta (gated, see DEPLOY.md)
#
# This script deploys ONLY the on-chain program. The bond-mint (Token-2022 LST)
# and protocol `initialize` call are operational steps the operator runs after
# the program is live, with the real LST mint and Pyth feed — see DEPLOY.md.
#
# It never sets a hot key as the upgrade authority on mainnet: the recommended
# flow is to deploy, then transfer upgrade authority to a Squads multisig (the
# script prints that command rather than doing it for you).
set -euo pipefail

NETWORK="${1:-devnet}"
PROGRAM_NAME="distin"
KEYPAIR="target/deploy/${PROGRAM_NAME}-keypair.json"

case "$NETWORK" in
  devnet)  CLUSTER="https://api.devnet.solana.com" ;;
  mainnet) CLUSTER="https://api.mainnet-beta.solana.com" ;;
  *) echo "usage: bash deploy.sh [devnet|mainnet]"; exit 1 ;;
esac

# Use the newer Solana toolchain (3.x: rustc 1.89, platform-tools v1.52) that can
# compile solana-program 2.x; 1.18 cannot. PATH is set non-interactively here so
# the script works in CI-less, bare shells too.
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"

echo "=== [1/4] reproducible SBF build ==="
cargo-build-sbf

if [ ! -f "$KEYPAIR" ]; then
  echo "ERROR: $KEYPAIR missing — it is the program identity (declare_id). Do not regenerate." >&2
  exit 1
fi
PROGRAM_ID="$(solana-keygen pubkey "$KEYPAIR")"
DECLARED="$(grep -oE 'declare_id!\("[^"]+"\)' programs/${PROGRAM_NAME}/src/lib.rs | grep -oE '[1-9A-HJ-NP-Za-km-z]{32,44}')"
echo "Program ID (keypair):  $PROGRAM_ID"
echo "declare_id! (source):  $DECLARED"
if [ "$PROGRAM_ID" != "$DECLARED" ]; then
  echo "ERROR: keypair pubkey != declare_id!. Sync them before deploying." >&2
  exit 1
fi

echo "=== [2/4] preflight: balance on $NETWORK ==="
solana balance --url "$CLUSTER" || true

if [ "$NETWORK" = "mainnet" ]; then
  echo
  echo "!!! MAINNET DEPLOY of $PROGRAM_ID !!!"
  echo "Confirm you have read DEPLOY.md, funded ~7.5 SOL, and intend a REAL deploy."
  read -r -p "Type the program id to proceed: " confirm
  [ "$confirm" = "$PROGRAM_ID" ] || { echo "aborted."; exit 0; }
fi

echo "=== [3/4] deploy program ==="
# `solana program deploy` (not raw `anchor deploy`) so we control the upgrade
# authority and buffer explicitly. Default reserves 2x size for future upgrades.
solana program deploy \
  --url "$CLUSTER" \
  --program-id "$KEYPAIR" \
  target/deploy/${PROGRAM_NAME}.so

echo "=== [4/4] verify ==="
solana program show "$PROGRAM_ID" --url "$CLUSTER"

cat <<EOF

=== deployed ===
Network:    $NETWORK
Program ID: $PROGRAM_ID
Explorer:   https://explorer.solana.com/address/$PROGRAM_ID?cluster=$NETWORK

NEXT (mainnet): move the upgrade authority OFF this hot key to a Squads multisig:
  solana program set-upgrade-authority $PROGRAM_ID \\
    --new-upgrade-authority <SQUADS_VAULT_PDA> \\
    --url $CLUSTER
Then run the protocol \`initialize\` with the real LST mint + Pyth feed (DEPLOY.md).
EOF
