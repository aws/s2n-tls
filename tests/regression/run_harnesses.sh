#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Function to run a harness
run_harness() {
    local harness=$1
    local output_file="cachegrind.out.${harness}"
    local annotated_output="perf_outputs/${harness}_annotated.txt"

    echo "Running harness: $harness"
    cargo build
    valgrind --tool=cachegrind --cachegrind-out-file=$output_file target/debug/$harness
    cg_annotate $output_file > $annotated_output

    echo "Annotated output saved to: $annotated_output"
}

# Create the perf_outputs directory if it doesn't exist
mkdir -p perf_outputs

# Check if any harness is specified
if [ $# -eq 0 ]; then
    echo "No harness specified. Running all harnesses..."
    harnesses=(config_create config_configure)
else
    # Use the specified harnesses
    harnesses=("$@")
fi

# Run each specified harness
for harness in "${harnesses[@]}"; do
    run_harness $harness
done

