#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

set -eu

usage() {
    echo "install_s2n_head.sh build_dir"
    exit 1
}

BUILD_DIR=$1
SRC_ROOT=${SRC_ROOT:-$(pwd)}

if [ "$#" -ne "1" ]; then
    usage
fi

clone(){
    # Path differences for internal builds mean we always need to go back to GitHub for head.
    git clone --branch main --single-branch "$CLONE_SRC" "$SRC_ROOT"/s2n_head
}

# CMake(nix) and Make are using different directory structures.
set +u
if [[ "$IN_NIX_SHELL" ]]; then
    export DEST_DIR="$SRC_ROOT"/build/bin
    export EXTRA_BUILD_FLAGS=""
    # Work around issue cloning inside a nix devshell https://github.com/NixOS/nixpkgs/issues/299949 
    export CLONE_SRC="."
else
    export DEST_DIR="$SRC_ROOT"/bin
    export EXTRA_BUILD_FLAGS="-DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT"
    # Work around different pathing issues for internal rel.
    export CLONE_SRC="https://github.com/aws/s2n-tls"
fi
set -u

# Cleanup any stale s2n_head clones.
if [[ -d "$SRC_ROOT/s2n_head" ]]; then
    now=$(date +%s)
    last_modified=$(stat -c %Y s2n_head)
    days_old=$(( (now - last_modified) / 86400))
    if ((days_old > 1 )); then
        echo "s2n_head is $days_old days old, removing and cloning again."
        rm -rf s2n_head
        clone
    else
        echo "s2n_head already exists and is $days_old days old."
    fi
else
    clone
fi
cmake "$SRC_ROOT"/s2n_head -B"$BUILD_DIR" "$EXTRA_BUILD_FLAGS" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on
cmake --build "$BUILD_DIR" -- -j "$(nproc)"
cp -f "$BUILD_DIR"/bin/s2nc "$DEST_DIR"/s2nc_head
cp -f "$BUILD_DIR"/bin/s2nd "$DEST_DIR"/s2nd_head

exit 0
