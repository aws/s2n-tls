#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

display_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Sets up an AWS EC2 instance for CodeBuild fleets by:
  1) Installing Nix package manager on a bare EC2 instance
  2) Configuring Nix to be usable by the root user for CodeBuild compatibility
     (Note: This is not officially supported by Nix)

Options:
  -h, --help    Display this help message and exit
EOF
}

setup_nix() {
    echo "=== Setting up nix user, groups and permissions ==="
    sudo groupadd nixbld
    sudo useradd -m -g nixbld -G nixbld nix
    # Give everyone on the system read access to the nix user homedir.
    sudo chmod 755 /home/nix
    echo "Both $HOME and $USER need to be set for the nix installer to work."
    echo "=== Installing Nix ==="
    sudo -u nix bash -c "sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --no-daemon"
    echo "=== Enabling Nix flakes ==="
    sudo -u nix bash -c 'mkdir -p ~/.config/nix; echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf'
    # This sidesteps the need to update PATH for every user.
    sudo ln -s /home/nix/.nix-profile/bin/nix /usr/local/bin
    echo "=== Setting up Nix configs for the root user ==="
    sudo -u root bash -c "ln -s /home/nix/.nix-profile ~/"
    sudo -u root bash -c "ln -s /home/nix/.config ~/"
}

setup_sudo() {
    echo "Setting up sudo for the nix user, needed for installation ==="
    # The nix installer refuses to install as root, so we need to set up sudo for the nix user.
    sudo bash -c "echo 'nix ALL=NOPASSWD: ALL' > /etc/sudoers.d/nix"
}

check_gnutls_config() {
    if [[ -f "/etc/gnutls/config" ]]; then
        echo "Turning off gnuTLS overrides"
        sudo rm -f /etc/gnutls/config
    fi
}

update_ubuntu_packages() {
    sudo apt update
    sudo apt upgrade -y
}
# main
for arg in "$@"; do
    case $arg in
        -h|--help)
            display_usage
            exit 0
            ;;
    esac
done
check_gnutls_config
update_ubuntu_packages
setup_sudo
setup_nix
