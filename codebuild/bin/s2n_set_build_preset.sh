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

case "$S2N_BUILD_PRESET" in
    "awslc_gcc4-8")
        : "${S2N_LIBCRYPTO:=awslc}"
        : "${GCC_VERSION:=4.8}"
        ;;
    "awslc_gcc9")
        : "${S2N_LIBCRYPTO:=awslc}"
        : "${GCC_VERSION:=9}"
        ;;
    "awslc-fips_gcc4-8")
        : "${S2N_LIBCRYPTO:=awslc-fips}"
        : "${GCC_VERSION:=4.8}"
        ;;
    "awslc-fips_gcc9")
        : "${S2N_LIBCRYPTO:=awslc-fips}"
        : "${GCC_VERSION:=9}"
        ;;
esac

