#!/usr/bin/env bash

set -euo pipefail

echo "Is $HOME set? Is $USER set?"
echo "=== Setting up sudo for the nix user ==="
sudo bash -c "echo 'nix ALL=NOPASSWD: ALL' > /etc/sudoers.d/nix"
sudo groupadd nixbld
sudo useradd -m -g nixbld -G nixbld nix
sudo chmod 755 /home/nix

echo "=== Installing Nix ==="
sudo -u nix bash -c "sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --no-daemon"
echo "=== Enabling Nix flakes ==="
sudo -u nix bash -c 'mkdir -p ~/.config/nix; echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf'
# This sidesteps the need to update PATH
sudo ln -s /home/nix/.nix-profile/bin/nix /usr/local/bin

echo "=== Setting up Nix for root ==="
sudo -u root bash -c "ln -s /home/nix/.nix-profile ~/"
sudo -u root bash -c "ln -s /home/nix/.config ~/"

sudo apt update
sudo apt upgrade -y