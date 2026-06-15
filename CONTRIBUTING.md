# Contributing to Unbridge

Thanks for looking at Unbridge. This is a cryptography-first project, so the bar
for a change is simple: **the proofs still pass, and reviewers can reproduce
what you claim.**

## Start by running the proofs

Before changing anything, confirm the two core proofs pass on your machine:

```bash
cd engine/kobe       && cargo test                 # FROST Ed25519, ~10s
cd engine/kobe-ecdsa && go test -v -timeout 600s   # GG20 ECDSA (ETH/BTC/Tron), ~110s
```

Both are green on `main` and run in CI on every push. If they fail on a clean
clone, that is itself a bug worth an issue.

## Making a change

1. Fork and branch from `main`.
2. Keep changes surgical. Every changed line should trace to the stated goal;
   do not restyle or refactor unrelated code in the same PR.
3. Add or update tests for behavior you change. A crypto change with no test is
   not reviewable.
4. Run the relevant suite (and `cargo fmt --all -- --check` for Rust) before
   pushing.
5. Open a PR describing what changed, why, and how you verified it.

## Commit messages

Conventional Commits, present tense, one logical change per commit:

```
feat(kobe-ecdsa): add Tron base58check envelope + known-vector test
fix(coordinator): reject partials past the slot deadline
docs(readme): link the confirmed Bitcoin transaction
```

Prefixes in use: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`.

## What NOT to commit

Secrets, keypairs, MPC share files, `.env`, and build artifacts are gitignored
and must stay out of history. If you generate keys or shares while testing, keep
them local.

## Reporting security issues

Not here. See [`SECURITY.md`](SECURITY.md) for private disclosure.

## License

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
