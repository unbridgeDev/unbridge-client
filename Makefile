.PHONY: help check test lint format clean verify

help:
	@echo "Unbridge client build targets:"
	@echo "  make check   - Type-check the client workspace"
	@echo "  make test    - Run unit tests across all client crates"
	@echo "  make lint    - Run clippy warnings-only"
	@echo "  make format  - Format all Rust source with rustfmt"
	@echo "  make clean   - Remove build artifacts"
	@echo "  make verify  - Show the on-chain program shape for the deployed pool"

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

verify:
	@echo "Deployed pool program shape:"
	@solana program show 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu \
		--url mainnet-beta
