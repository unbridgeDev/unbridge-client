# Distin — Mainnet deploy runbook (M12)

This is the operator's runbook to put the `distin` program on mainnet-beta. The
program is **deploy-ready**; this document is the exact procedure plus a clear
statement of what still gates real value. **Deploying is the operator's step —
this repo does not deploy.**

Program id: `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6`
(the `target/deploy/distin-keypair.json` pubkey == `declare_id!` in `src/lib.rs`;
the deploy script refuses to proceed if they ever drift.)

## Toolchain (already installed; do not reinstall)

`cargo-build-sbf` must be the **Solana 3.x** toolchain (rustc 1.89,
platform-tools v1.52). The 1.18 line cannot compile `solana-program` 2.x. If a
shell shows the old one, point the active release at 3.1.10:

```bash
ln -sfn ~/.local/share/solana/install/releases/3.1.10/solana-release \
        ~/.local/share/solana/install/active_release
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
solana --version          # solana-cli 3.1.10
cargo-build-sbf --version # 3.1.10, platform-tools v1.52, rustc 1.89.0
```

## Reproducible build

```bash
cd engine
cargo-build-sbf            # -> target/deploy/distin.so  (~502 KiB)
```

The release profile pins `overflow-checks = true`, `lto = "fat"`,
`codegen-units = 1`, `opt-level = 3` (see `Cargo.toml`), so the artifact is
deterministic for a given toolchain + lockfile.

## SOL required

For a fresh upgradeable deploy, mainnet reserves rent for the program account
plus a ProgramData account. `solana program deploy` defaults to **2x** the
program size so future upgrades fit without reallocating:

| Item | Bytes | Rent (SOL) |
|------|-------|-----------|
| Program account | 36 | ~0.001 |
| ProgramData (2x headroom, default) | 45 + 2·514384 | ~7.16 |
| **Total (default)** | | **~7.2 SOL** |
| ProgramData (`--max-len`, exact, no upgrade headroom) | 45 + 514384 | ~3.58 → **~3.6 SOL total** |

Plus a few thousand lamports of transaction fees and a transient deploy buffer
(refunded on success). **Fund the deployer with ~7.5 SOL** for the default path,
or ~4 SOL if you deploy with `--max-len 514384` and accept no in-place upgrade
headroom. The buffer is auto-closed/refunded by `solana program deploy`; if a
deploy is interrupted, reclaim stranded buffers with `solana program
show --buffers` then `solana program close <BUFFER>`.

## The program keypair

`target/deploy/distin-keypair.json` **is the program's on-chain identity**. Never
regenerate it (it would change `declare_id` and orphan every PDA derived against
the program id) and never commit it (it is in `.gitignore`). Back it up offline.

## Deploy

```bash
cd engine
bash deploy.sh devnet     # rehearse on devnet first
bash deploy.sh mainnet    # gated: prompts for the program id to confirm
```

`deploy.sh` builds, checks `keypair == declare_id`, shows your balance, deploys
with `solana program deploy --program-id <keypair>`, and verifies with
`solana program show`. The mainnet path requires you to type the program id.

## Upgrade authority — use a multisig, not a hot key

By default the deployer key becomes the upgrade authority, meaning **one hot key
can replace the program bytecode** — for a program that custodies bonded
collateral that is unacceptable for real value. Immediately after the deploy,
move the upgrade authority to a [Squads](https://squads.so) multisig vault:

```bash
solana program set-upgrade-authority 4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6 \
  --new-upgrade-authority <SQUADS_VAULT_PDA> \
  --url https://api.mainnet-beta.solana.com
```

Uncomment and point `[provider.mainnet]` in `Anchor.toml` at that vault for any
subsequent `anchor upgrade`. Consider making the program **immutable**
(`--final`) once the design is settled — that removes the upgrade attack surface
entirely, at the cost of no future fixes.

## Post-deploy bring-up (operational, not part of the deploy)

The program is inert until `initialize` runs. That call wires the real economic
parameters and is where the operator makes the calls only they can make:

1. **Bond mint** — create or choose the Token-2022 LST mint accepted as
   collateral. `initialize` stores it as `bond_mint`; the vault + slash pool are
   created as protocol-owned Token-2022 accounts in the same instruction.
2. **Pyth feed** — pass the real LST/SOL Pyth price account as `lst_price_feed`.
   See "What still gates real value" — the oracle read is currently a 1:1 stub.
3. **Parameters** — `threshold_bps`, `min_bond`, `unbonding_slots`,
   `request_fee`, `max_validity_slots`. Note the threshold interaction below.
4. **Admin** — set `admin` to a multisig too; admin can pause and discretionarily
   slash. Use the two-step `transfer_admin` → `accept_admin` handover.

### Threshold ↔ attester-count interaction (read before setting `threshold_bps`)

The identifiable-abort slash requires
`required_attesters = ceil(operator_count · threshold_bps / 10000)` DISTINCT
honest attesters, and the culprit cannot attest against itself. So with a small
set a high `threshold_bps` can make the culprit unslashable: e.g. 3 operators at
6667 bps needs `ceil(2.0001) = 3` attesters, but only 2 non-culprit operators
exist. Pick `threshold_bps` so `required_attesters ≤ operator_count − 1` for your
expected set size (e.g. 5000 bps over 3 ops needs 2, which 2 honest ops can
meet). This is a parameterization constraint, not a bug.

## What is deploy-ready vs. what still gates real value

**Deploy-ready now:**
- Program builds reproducibly (`cargo-build-sbf`, 3.1.10 toolchain).
- `cargo clippy -- -D warnings` clean; `cargo audit` 0 vulnerabilities.
- 16 unit tests + a **litesvm integration suite that moves a real bond**
  (`tests-litesvm/`): the M9 attested slash is proven end-to-end in a real SVM
  transaction — quorum slash debits the vault and credits the slash pool, jails
  below `min_bond`, and minority / wrong-digest / duplicate-key bundles are
  rejected on-chain.
- Account-constraint security reviewed as an attacker (see `SECURITY.md`); one
  real finding (duplicate-attestation-key double-count) was found by the
  integration test and **fixed** this pass.

**Still gates real value (operator's call, flagged honestly):**
1. **Third-party audit.** The bytecode is public; a professional audit of this
   program AND the off-chain `kobe-*` signing libraries is the operator's risk
   decision. No real value should touch the code until it is done. (Per
   `core.verified` / `HARDENING.md`.)
2. **Pyth oracle is a 1:1 stub.** `compute_stake_weight` treats the bond mint as
   a 1:1 SOL-pegged LST. Wiring the real Pyth read (with the documented
   staleness guard) changes weight accounting and is a deploy-affecting change —
   do it before bonding a non-pegged LST.
3. **Operator network maturity.** GG20 is networked + hardened (M8–M11); FROST
   networking is deferred (`HARDENING.md`, decision F3). The on-chain program is
   scheme-agnostic, but live SVM/Cosmos Schnorr signing is not yet networked.
4. **No revocation in the operator PKI.** The mTLS PKI is static-enrolment; a
   churning operator set needs CRL/OCSP before rotating members (M8 limitation).
