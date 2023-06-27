#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# immediately bail if any command fails
set -e

# go to directory script is located in
pushd "$(dirname "$0")"

tags=`git tag -l | sort -rV`

IFS=$'\n'

for tag in $tags
do 
    echo $tag
done

popd