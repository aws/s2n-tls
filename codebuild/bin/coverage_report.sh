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

# useful for my debugging at the moment
find / -name '*profraw*'

# merge profiling data
# i think this is a valid relative path, but not entirely sure, test locally before pushing
llvm-profdata merge -sparse tests/unit/ut_*.profraw -o merged.profdata

llvm-cov export build/lib/libs2n.so \
    -instr-profile=merged.profdata \
    -format=lcov \
    > unit_test_coverage.info

genhtml unit_test_coverage.info -o coverage_report