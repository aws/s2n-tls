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
source codebuild/bin/s2n_setup_env.sh

usage() {
    echo "install_apache2.sh config_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

APACHE2_CONFIG_DIR="$1"
APACHE2_INSTALL_DIR="$2"

apache_enable() {
    item_type="$1"
    item="$2"
    required="$3"

    source_path="/etc/apache2/${item_type}-available/${item}"
    dest_path="${APACHE2_INSTALL_DIR}/${item_type}-enabled/${item}"

    if [ ! -f "${source_path}" ]; then
        if [ "$required" = true ]; then
            echo "apache item not found: ${source_path}"
            exit 1
        fi

        return
    fi

    ln -s "$source_path" "$dest_path"
}

mod_enable() {
    mod="$1"
    apache_enable "mods" "${mod}.load" true
    apache_enable "mods" "${mod}.conf" false
}

conf_enable() {
    conf="$1"
    apache_enable "conf" "${conf}.conf" true
}

cp -r "${APACHE2_CONFIG_DIR}" "${APACHE2_INSTALL_DIR}"
mkdir "${APACHE2_INSTALL_DIR}/mods-enabled"
mkdir "${APACHE2_INSTALL_DIR}/conf-enabled"
mkdir "${APACHE2_INSTALL_DIR}/run"
mkdir "${APACHE2_INSTALL_DIR}/lock"
mkdir "${APACHE2_INSTALL_DIR}/log"

# Enable default mods
DEFAULT_MODS=("access_compat" "alias" "auth_basic" "authn_core" "authn_file" "authz_core" "authz_host" "authz_user"
              "autoindex" "deflate" "dir" "env" "filter" "mime" "mpm_event" "negotiation" "reqtimeout" "setenvif"
              "socache_shmcb" "status" "ssl")
for mod in "${DEFAULT_MODS[@]}"; do
    mod_enable "$mod"
done

# Enable default configuration
DEFAULT_CONF=("charset" "localized-error-pages" "other-vhosts-access-log" "security" "serve-cgi-bin")
for conf in "${DEFAULT_CONF[@]}"; do
    conf_enable "$conf"
done
