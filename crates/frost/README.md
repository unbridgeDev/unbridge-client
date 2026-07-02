# frost

FROST threshold signing over Baby Jubjub for Unbridge. Produces the
EdDSA-Poseidon signature `(R8, S)` that the pool's `spend_auth.circom`
circuit verifies, from `t` of `n` participants, without ever assembling
the group signing key.

## Why this crate exists

The scanner-visible answer to "does Unbridge actually implement FROST"
should not be "read the circom files." The circom side proves that a
signature `(R8, S)` under `A = (Ax, Ay)` is valid; this Rust crate is
the reference implementation of how that signature is produced by a
threshold group. Together they close the loop: FROST partial signatures
aggregate into an EdDSA-Poseidon signature, that signature is what
`pool_tx.circom` accepts as spend authorisation, and the aggregated
signature is what the on-chain program verifies inside the Groth16 proof.

## Modules

| Module     | Purpose                                                          |
|------------|------------------------------------------------------------------|
| `group`    | Participant ids, group public key, Lagrange interpolation at 0.  |
| `key`      | `SecretShare` (zeroed on drop) and `VerificationShare`.          |
| `nonce`    | Fresh nonce pair generation with one-time-use enforcement.       |
| `dkg`      | Three-round dealerless DKG (Feldman VSS).                         |
| `signing`  | Two-round FROST signing plus aggregation and pre-flight verify.  |
| `errors`   | Typed errors with the failing participant id where relevant.     |

## Usage sketch

```rust
use frost::{DkgSession, Participant, NoncePair, prepare_signing_package, sign, aggregate, verify};
use rand_core::OsRng;

// Setup: dealerless DKG over 2-of-3.
let ps = vec![Participant::new(1)?, Participant::new(2)?, Participant::new(3)?];
let mut sessions: Vec<DkgSession> = ps.iter()
    .map(|me| DkgSession::start(*me, 2, ps.clone(), &mut OsRng))
    .collect::<Result<_, _>>()?;
let r1: Vec<_> = sessions.iter().map(|s| s.round1()).collect();
let all_r2: Vec<_> = sessions.iter().map(|s| s.round2()).collect();
// each participant finalises with the round2 msgs addressed to them ...

// Sign a spend: each active participant runs round 1 -> round 2.
let mut my_nonces = NoncePair::fresh(&mut OsRng);
let commitments = /* the round-1 NonceCommitments of every signer */;
let pkg = prepare_signing_package(spend_msg, commitments)?;
let my_partial = sign(&pkg, &my_key_material.secret_share, &mut my_nonces, &my_key_material.group_public_key)?;

// Aggregation is public. Any party can do it.
let sig = aggregate(&pkg, &all_partials)?;
verify(&sig, &my_key_material.group_public_key, &spend_msg)?;
// sig.to_bytes() is what goes into the on-chain instruction data.
```

## Security notes

- **Nonce pairs are one-shot.** `NoncePair::consume` marks the pair used
  and returns `NonceReused` on a second call. Two signing sessions must
  never share a nonce pair; doing so leaks the participant's key share.
- **Debug output redacts scalars.** Neither `SecretShare` nor `NoncePair`
  prints the raw scalar in its `Debug` impl; both zero on drop.
- **The scheme identifier is baked into every transcript.** Changing
  `SCHEME_ID` invalidates every partial under the old identifier, so an
  aggregator cannot mix rounds from two scheme versions.
- **Aggregation is public.** No private material is needed to aggregate,
  so a relayer or coordinator can do it without becoming trusted.

## Status

Reference implementation used by the client crates and mirrored in the
on-chain circuit. Not a general-purpose FROST library; the encoding
choices (Baby Jubjub scalars, Poseidon binding factor, EdDSA-Poseidon
output form) are pinned to what the pool circuit consumes. Unaudited.
