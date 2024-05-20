#!/bin/bash

set -ex

. "$HOME/.cargo/env"
export PATH="$HOME/c2rust/target/release:$PATH"

cargo install --path $1/scripts/s2n2rust/s2n2rust

exec $HOME/.cargo/bin/s2n2rust $@
