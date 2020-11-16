#!/bin/bash
#
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
#
set -eu
ERRORS=0


ensure_installed() {
    if ! command -v $1 &> /dev/null; then
        if [ -z ${2+x} ]; then
            error_exit "$1 is required to be installed"
        else
            eval $2
        fi
    fi
}

# Check for duplicate identifiers in the omnibus spec.
look_for_dups() {
	SPEC_COUNT=$( sed 's/build-graph/buildgraph/g' $1| \
                      yq '.batch.buildgraph[]|.identifier'|sort|uniq -c| gawk 'BEGIN {count=0;} $1>1{count++};END{print count}')
	if [[ ${SPEC_COUNT} -ne 0 ]]; then
		echo "Omnibus: Duplicate identifiers found in the spec"
		let "ERRORS++"
	else
		echo "Omnibus: identifiers are all uniq"
	fi
}

# For the build-graph jobs to work, the dependencies defined must exist.
check_deps() {
	DEPSLIST=$(yq -r '.batch."build-graph"[]|select(."depend-on"!=null)| ."depend-on"[0] ' $1|sort|uniq)
	echo "Checking build-graph dependencies..."
	for i in $DEPSLIST; do
		echo "looking for: $i"
		test $(yq -r '.batch."build-graph"[]|select(.identifier == "'$i'")|.identifier' $1)
	done
	echo "All dependencies found."
}

ensure_installed jq
ensure_installed yq
ensure_installed gawk
look_for_dups ./spec/buildspec_omnibus.yml
check_deps ./spec/buildspec_omnibus.yml
