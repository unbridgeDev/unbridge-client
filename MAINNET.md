# Mainnet deployment runbook

Decision 2026-07-02: external audit skipped by owner decision — mainnet gates
on funding only. This is the exact path; every step was already exercised on
devnet with the same binaries and keys.

## Pre-verified facts

- **Same program ID on mainnet**: `target/deploy/distin-keypair.json` →
  `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6` (web constants unchanged).
- **Pyth SOL/USD feed exists at the SAME address on mainnet**
  (`7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE`, owner `rec5EKMG…`,
  live ~$81) — no oracle repoint needed.
- Deploy artifact: `engine/target/deploy/distin.so` (475 KB, built from the
  audit-ref lineage — dd45c54 layout + Pyth deltas).

## Cost

- Program deploy (rent-exempt for ~2× .so + buffer + fees): **~3.5 SOL**
- initialize + operator registrations (6–9 ops × ~0.055 SOL incl. funding
  authorities): **~0.5 SOL**
- Working margin: **total ~4.5 SOL** into the deploy wallet
  `YZykTqXgx91g2FSXoTh7q46HJnbwEH17jRhbNzbfppf` (owner funds; never assume).

## Steps (each maps to a command already proven on devnet)

1. `solana program deploy engine/target/deploy/distin.so --program-id
   engine/target/deploy/distin-keypair.json -u mainnet-beta -k <admin>`
2. `DISTIN_RPC_URL=https://api.mainnet-beta.solana.com signerd bootstrap`
   (init protocol + FROST operator set; keys stay the sealed ones or fresh —
   decision below)
3. `… bootstrap-gg20` and `… bootstrap-frostnet` (networked sets; frostnet
   lowers threshold_bps to 2000 as on devnet)
4. Daemon: set `DISTIN_RPC_URL` in the launchd plist (or run the Docker image
   with `-e DISTIN_RPC_URL=…` on a cloud host) — same keys volume, same
   passphrases.
5. Web: `.env.local` → mainnet RPC + NETWORK label; program ID unchanged.
6. Smoke: one `request` + one `request-gg20`, verify signatures exactly as the
   devnet proofs did (ed25519 vs group key; ecrecover vs group address).

## Open decisions (owner)

1. **Bond asset.** On devnet the bond mint is a demo Token-2022 mint with
   admin as mint authority. On mainnet that is NOT a real LST — economic
   security claims would be marketing, not fact. Options:
   (a) launch beta with the demo mint and say so honestly ("testnet-grade
   collateral on mainnet rails"), or (b) real LST bonding — requires actual
   LST capital per operator and a `compute_stake_weight` feed matching that
   asset (`set_lst_price_feed`).
2. **Fresh keys vs devnet keys.** Recommended: run `bootstrap` with a FRESH
   `DISTIN_KEYS_DIR` for mainnet (new group keys, sealed with a new
   passphrase) — devnet keys have lived on this laptop unsealed in the past.
3. **No audit.** Deploying an unaudited threshold-signing program to mainnet
   is a real risk the owner has accepted; `AUDIT_SCOPE.md` gaps #2 (admin
   single-key surface) and #5 (offset-based Pyth parse) are the two most
   load-bearing unreviewed surfaces. Keep bonds small until reviewed.
