.PHONY: help build check test lint format clean idl verify

help:
	@echo "Unbridge build targets:"
	@echo "  make build     - Build the on-chain program (requires cargo-build-sbf)"
	@echo "  make check     - Type-check the workspace without producing binaries"
	@echo "  make test      - Run unit tests"
	@echo "  make lint      - Run clippy warnings-only"
	@echo "  make format    - Format all Rust source with rustfmt"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make idl       - Regenerate the program IDL"
	@echo "  make verify    - Compare local build against the deployed mainnet binary length"

build:
	cargo build-sbf --manifest-path programs/zkcash/Cargo.toml

check:
	cargo check --workspace --all-targets

test:
	cargo test --workspace --lib

lint:
	cargo clippy --workspace --all-targets -- -W warnings

format:
	cargo fmt --all

format-check:
	cargo fmt --all -- --check

clean:
	cargo clean
	rm -rf target programs/zkcash/target

idl:
	anchor idl build --program-name zkcash --out programs/zkcash/idl/zkcash.json

verify:
	@echo "Building program..."
	@$(MAKE) build
	@echo "Local build size:"
	@ls -la target/deploy/zkcash.so 2>/dev/null || ls -la programs/zkcash/target/deploy/zkcash.so
	@echo "Deployed mainnet size:"
	@solana program show 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu \
		--url mainnet-beta | grep 'Data Length'
