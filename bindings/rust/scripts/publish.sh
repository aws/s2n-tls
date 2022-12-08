#!/usr/bin/env bash

# `cargo publish` is idempotent so its possible to run this script more than once

for dir in s2n-tls-sys s2n-tls s2n-tls-tokio
do
    pushd $dir
        echo "publishing $dir..."
        cargo publish --allow-dirty
        echo "sleep... and wait for previous publish to succeed"
        sleep 10
    popd
done

