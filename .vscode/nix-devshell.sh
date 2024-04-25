#!/bin/sh
set -eu
echo $PROJ_DIR
echo "Received $@"

nix_shell(){
    nix develop .
}
nix_command(){
    nix develop . --command bash -c "source nix/shell.sh;$@"
}

# The condition may be wrong because I'm not sure if Nix (!= NixOS) users have this file
if [ -e "/nix/var/nix/profiles/default/bin/nix" ]; then
  if [ "$#" -eq 0 ]; then
    nix_shell
  else
    shift
    nix_command "$@"
  fi
else
  echo "Could not find a nix executable."
  exit 1
fi