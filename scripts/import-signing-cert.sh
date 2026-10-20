#!/bin/sh
# Imports a code-signing identity (PKCS#12) into a NEW temporary keychain and prints the
# certificate's SHA-1 (lower-case hex) on stdout. macOS only.
# Usage: P12_PASSWORD=... KEYCHAIN_PASSWORD=... sh scripts/import-signing-cert.sh P12_FILE KEYCHAIN_PATH
# Both passwords come from the environment, never from arguments of this script. `security import`
# itself takes the p12 password as an argument (it has no other way to be given one), which is
# acceptable only on a single-user, throw-away runner: do not run this on a shared machine.
# The keychain is NOT deleted here; the caller deletes it (`security delete-keychain`).
# Nothing in this script echoes a password.
set -eu

die() { printf 'import-signing-cert: %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this script needs macOS (security)"
[ "$#" -eq 2 ] || die "usage: import-signing-cert.sh P12_FILE KEYCHAIN_PATH"
p12=$1
keychain=$2
[ -f "$p12" ] || die "no such file: $p12"
[ -n "${P12_PASSWORD:-}" ] || die "P12_PASSWORD is not set"
[ -n "${KEYCHAIN_PASSWORD:-}" ] || die "KEYCHAIN_PASSWORD is not set"
[ ! -e "$keychain" ] || die "the keychain already exists: $keychain"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/import-signing-cert.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

security create-keychain -p "$KEYCHAIN_PASSWORD" "$keychain" >/dev/null
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$keychain"
security import "$p12" -k "$keychain" -P "$P12_PASSWORD" -T /usr/bin/codesign >/dev/null \
    || die "the certificate could not be imported (wrong password, or a PKCS#12 that macOS cannot read: see docs/RELEASING.md)"
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$keychain" >/dev/null 2>&1 \
    || die "the key could not be opened for codesign (set-key-partition-list)"

# Put the keychain first in the user's search list, keeping the others.
security list-keychains -d user | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//' > "$tmp/list"
set -- -d user -s "$keychain"
while IFS= read -r line; do
    [ -n "$line" ] && set -- "$@" "$line"
done < "$tmp/list"
security list-keychains "$@" >/dev/null

# A self-signed certificate is not trusted by the system. Marking it trusted for code signing
# needs an authorisation that a headless session may refuse; codesign can use the identity by
# its hash either way, so a refusal is only a note.
security find-certificate -p -a "$keychain" > "$tmp/certs.pem" 2>/dev/null || true
if ! security add-trusted-cert -r trustRoot -p codeSign -k "$keychain" "$tmp/certs.pem" >/dev/null 2>&1; then
    printf 'import-signing-cert: note: the certificate was not marked trusted (not needed to sign by hash)\n' >&2
fi

security find-identity -p codesigning "$keychain" \
    | sed -n 's/^[[:space:]]*[0-9][0-9]*) \([0-9A-Fa-f]\{40\}\) .*$/\1/p' | tr 'A-F' 'a-f' | sort -u > "$tmp/hashes"
count=$(wc -l < "$tmp/hashes" | tr -d ' ')
[ "$count" -eq 1 ] || die "expected exactly one code-signing identity in the p12, found $count"
cat "$tmp/hashes"
