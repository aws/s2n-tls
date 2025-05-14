#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

SNAPSHOTS_DIR_DEFAULT="./tests/policy_snapshot/snapshots"
SECURITY_POLICIES_C_DEFAULT="./tls/s2n_security_policies.c"

function display_usage {
    echo "Usage: $0 <policy_path> [snapshots_dir] [s2n_security_policies]"
    echo
    echo "Arguments:"
    echo "  policy_path                 Path to the policy util binary"
    echo "  snapshots_dir               Path to the snapshots directory"
    echo "                              (default: $SNAPSHOTS_DIR_DEFAULT)"
    echo "  s2n_security_policies       Path to the s2n_security_policies.c file"
    echo "                              (default: $SECURITY_POLICIES_C_DEFAULT)"
    echo
    exit 1
}

if [ $# -lt 1 ] || [ $# -gt 3 ] || [ "$1" == "--help" ]; then
    display_usage
fi

POLICY_BINARY="$1"
SNAPSHOTS_DIR=${2:-$SNAPSHOTS_DIR_DEFAULT}
SECURITY_POLICIES_C=${3:-$SECURITY_POLICIES_C_DEFAULT}

echo "Using snapshots directory: $SNAPSHOTS_DIR"
echo "Using policy binary: $POLICY_BINARY"
echo "Using security policy file: $SECURITY_POLICIES_C"

echo "Extracting security policy names..."
POLICIES=$(grep -o '{ .version = "[^"]*"' $SECURITY_POLICIES_C \
    | sed 's/{ .version = "\(.*\)"/\1/' | grep -v "^null$")

COUNT=$(echo "$POLICIES" | wc -l)
echo "Found $COUNT policies."

rm -f $SNAPSHOTS_DIR/*

for policy in $POLICIES; do
    $POLICY_BINARY $policy > $SNAPSHOTS_DIR/$policy
    echo "Generated snapshot for $policy..."
done

echo
echo "Snapshots successfully generated."
exit 0
