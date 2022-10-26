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
#

set -eu

apache2_config() {
    cert_dir="$1"
    command="$2"
    echo "apache2: ${command}"

    APACHE_SERVER_ROOT="$APACHE2_INSTALL_DIR" \
    APACHE_RUN_USER=www-data \
    APACHE_RUN_GROUP=www-data \
    APACHE_PID_FILE="${APACHE2_INSTALL_DIR}/run/apache2.pid" \
    APACHE_RUN_DIR="${APACHE2_INSTALL_DIR}/run" \
    APACHE_LOCK_DIR="${APACHE2_INSTALL_DIR}/lock" \
    APACHE_LOG_DIR="${APACHE2_INSTALL_DIR}/log" \
    APACHE_CERT_DIR="${cert_dir}" \
    apache2 -k "${command}" -f "${APACHE2_INSTALL_DIR}/apache2.conf"
}

apache2_stop() {
    cert_dir="$1"
    apache2_config "${cert_dir}" stop
}

apache2_start() {
    if [[ ! -f "$APACHE2_INSTALL_DIR/apache2.conf" ]]; then
        echo "apache2 not installed"
        exit 1
    fi

    cert_dir="$1"
    apache2_config "${cert_dir}" start

    # Stop the apache server after tests finish, even if an error occurs
    trap 'apache2_stop "${cert_dir}"' ERR EXIT
}
