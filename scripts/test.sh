#!/bin/zsh
# Builds and runs the unit checks, verifying RSA output with OpenSSL.
set -euo pipefail
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc Sources/RouterClient.swift Tests/main.swift -o "$T/tests"
for bits in 512 1024; do
  openssl genrsa -out "$T/k.pem" $bits 2>/dev/null
  N=$(openssl rsa -in "$T/k.pem" -noout -modulus | cut -d= -f2)
  "$T/tests" "$N" "$T/c.bin"
  OUT=$(openssl pkeyutl -decrypt -inkey "$T/k.pem" -in "$T/c.bin" -pkeyopt rsa_padding_mode:pkcs1)
  [[ "$OUT" == "aGVsbG8xMjM=" ]] && echo "✓ OpenSSL decrypts our $bits-bit ciphertext" || { echo "✗ RSA $bits-bit mismatch"; exit 1; }
done
