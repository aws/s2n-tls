#!/bin/bash
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

set -e

# merge profiling data
llvm-profdata merge -failure-mode=all -sparse tests/unit/ut_*.profraw -o merged.profdata

# generate file-level summary
llvm-cov report build/lib/libs2n.so \
    -instr-profile=merged.profdata \
    > coverage_summary.txt

# convert llvm information to lcov format for genhtml
llvm-cov export build/lib/libs2n.so \
    -instr-profile=merged.profdata \
    -format=lcov \
    > unit_test_coverage.info

# generate html report with annotated source files
genhtml unit_test_coverage.info \
    --branch-coverage \
    -o coverage_report
