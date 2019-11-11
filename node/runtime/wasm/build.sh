#!/usr/bin/env bash
set -e

# `rustup default` is pinned to specific nightly release in `./scripts/init.sh`
CARGO_CMD="cargo"
CARGO_INCREMENTAL=0 RUSTFLAGS="-C link-arg=--export-table" $CARGO_CMD build --target=wasm32-unknown-unknown --release
for i in node_runtime
do
	wasm-gc target/wasm32-unknown-unknown/release/$i.wasm target/wasm32-unknown-unknown/release/$i.compact.wasm
done
