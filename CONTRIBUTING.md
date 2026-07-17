# Contributing to Unbridge

Thanks for looking at Unbridge. This repository is the protocol documentation. The most
valuable contributions right now are to the documentation and to the open trusted-setup
ceremony.

## Documentation

The docs must stay honest and verifiable. A change is welcome if it is accurate against
the live system and does not overclaim.

1. Fork and branch from `main`.
2. Keep changes surgical. Every changed line should trace to the stated goal.
3. Do not add claims that cannot be checked on-chain or in the app. No invented metrics,
   partners, audit status, or features that do not exist.
4. Open a PR describing what changed and how you confirmed it is accurate.

If you find a statement in the docs that is wrong, misleading, or unbackable, an issue or
PR that corrects it is exactly the kind of contribution we want.

## The trusted-setup ceremony

The strongest contribution you can make to the protocol's security is entropy for the
proving setup. Anyone can contribute at [unbridge.dev/ceremony](https://unbridge.dev/ceremony).
One honest external contributor makes the setup sound.

## Commit messages

Conventional Commits, present tense, one logical change per commit:

```
docs(security): clarify what the relayer can observe
docs(readme): correct the program verification command
```

Prefixes in use: `docs`, `fix`, `chore`.

## What not to commit

Secrets, keypairs, key shares, `.env`, and build artifacts must stay out of history.

## Reporting security issues

Not here. See [`SECURITY.md`](SECURITY.md) for private disclosure.

## License

By contributing you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
