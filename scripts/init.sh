#!/usr/bin/env bash

set -e

echo "*** Initializing WASM build environment"

# latest nightly will break this build
#if [ -z $CI_PROJECT_NAME ] ; then
#   rustup update nightly
#   rustup update stable
#fi

rustup install stable # need stable channel for native build
rustup install nightly-2019-07-14
rustup default nightly-2019-07-14
rustup target add wasm32-unknown-unknown

# Install wasm-gc. It's useful for stripping slimming down wasm binaries.
command -v wasm-gc || \
	cargo install --git https://github.com/alexcrichton/wasm-gc --force
