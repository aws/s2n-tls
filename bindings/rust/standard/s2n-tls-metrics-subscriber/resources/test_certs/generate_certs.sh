#!/usr/bin/env bash
# Generates a self-signed Ed25519 certificate for testing.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

openssl genpkey -algorithm Ed25519 -out "$DIR/ed25519_key.pem"
openssl req -new -x509 -key "$DIR/ed25519_key.pem" \
    -out "$DIR/ed25519_cert.pem" \
    -days 3650 \
    -subj "/CN=localhost"

# Also produce DER for direct loading in tests
openssl x509 -in "$DIR/ed25519_cert.pem" -outform DER -out "$DIR/ed25519_cert.der"

echo "Generated ed25519_key.pem, ed25519_cert.pem, ed25519_cert.der in $DIR"
