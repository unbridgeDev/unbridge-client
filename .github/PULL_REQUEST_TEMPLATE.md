## Summary

What does this PR change and why. One paragraph.

## Scope

- [ ] on-chain program (`engine/programs/distin`)
- [ ] FROST signer (`engine/kobe`)
- [ ] GG20 signer (`engine/kobe-ecdsa`)
- [ ] coordinator / operator daemon (`engine/coordinator`)
- [ ] web app (`web/`)
- [ ] docs / meta

## Verification

How you confirmed the change works.

- [ ] `cargo check --workspace` passes locally
- [ ] Affected unit / integration tests pass
- [ ] If touching the on-chain program: litesvm tests updated
- [ ] If touching the signer: threshold recovery still verifies against an
      independent verifier (`ed25519-dalek` for FROST; `Ecrecover` /
      libsecp256k1 for GG20)

## Security-sensitive change?

- [ ] Yes — see notes below.
- [ ] No.

If yes, describe the threat model delta and the invariant this preserves.

## Related

Issues / discussions this closes or references.
