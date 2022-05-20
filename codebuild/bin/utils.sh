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
#
set -e

# Utility functions
get_latest_release(){
    LATEST_RELEASE_URL=$(gh api /repos/aws/s2n-tls/releases/latest|jq -r '.tarball_url')
    LATEST_RELEASE_VER=$(echo "${LATEST_RELEASE_URL}" | sed 's|.*/||')
    export LATEST_RELEASE_URL
    export LATEST_RELEASE_VER
}

gh_login(){
    # Takes secrets manager key as an argument
    aws secretsmanager get-secret-value --secret-id "$1" --query 'SecretString' --output text |jq -r '.secret_key'| gh auth login --with-token
    #gh auth status
}

usage(){
    echo -e "Usage:\n\tget_latest_release: returns just the latest v.N.N.N version"
    echo -e "\tgh_login <Secret Name> : retrieves a GitHub PAT from secrest manager and logs into GitHub.\n"
}

if [[ "${BASH_SOURCE[0]}" == "${0}"  ]]; then
    case "${1:-}" in
        "gh_login")
            gh_login "${2:-}";;
        "get_latest_release")
            get_latest_release
            echo "$LATEST_RELEASE_VER";;
        *)  usage;
    esac
fi
