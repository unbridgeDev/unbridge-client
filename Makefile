.PHONY: build test lint format check clean anchor-build web-build

build:
	cargo build --workspace

test:
	cargo test --workspace
	cd engine/kobe-ecdsa && go test -short ./...

lint:
	cargo clippy --workspace --all-targets

format:
	cargo fmt --all

check:
	cargo check --workspace
	cd engine/kobe-ecdsa && go vet ./...

anchor-build:
	cd engine && anchor build

web-build:
	cd web && npm run build

clean:
	cargo clean
	rm -rf web/.next web/out
