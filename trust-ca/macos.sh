#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "trust-ca/macos.sh only supports macOS." >&2
  exit 1
fi

if ! command -v security >/dev/null 2>&1; then
  echo "The macOS security CLI is not available." >&2
  exit 1
fi

cert_path="${CERT_PATH:-$HOME/.express-mitm/cert/ca.crt}"

if [[ ! -f "$cert_path" ]]; then
  echo "CA certificate not found at: $cert_path" >&2
  echo "Generate it first with: go run ./cmd/gen-ca" >&2
  exit 1
fi

keychain_path="${KEYCHAIN_PATH:-$(security default-keychain -d user | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//')}"

if [[ -z "$keychain_path" ]]; then
  echo "Unable to determine the default user keychain." >&2
  exit 1
fi

# Remove any existing trust entry for the same cert so rerunning the script is idempotent.
security remove-trusted-cert "$cert_path" >/dev/null 2>&1 || true

security add-trusted-cert \
  -r trustRoot \
  -p ssl \
  -k "$keychain_path" \
  "$cert_path"

echo "Trusted CA certificate: $cert_path"
echo "Keychain: $keychain_path"
