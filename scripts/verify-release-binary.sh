#!/bin/sh
# Checks that a binary is what a release is supposed to contain. macOS only.
# Usage: sh scripts/verify-release-binary.sh BINARY CERT_SHA1 VERSION
#   CERT_SHA1  40 lower-case hex digits: the signing certificate the release must be signed with
#   VERSION    X.Y.Z (a -suffix is accepted for dry runs): what `wardenrun version` must print
# Prints one "verify: ..." line per problem and exits 1; prints "verify: ok" and exits 0 when
# the signature verifies, the hardened runtime flag is set, the identifier is the fixed one,
# the binary has no entitlements at all (any of them could weaken the hardened runtime), both
# architectures are present, the designated requirement is exactly the one line
# `release-info.sh requirement CERT_SHA1` prints (not a text that merely contains the hash), and
# the version matches.
here=$(cd "$(dirname "$0")" && pwd)

usage() { printf 'verify: %s\n' "$1" >&2; exit 64; }

[ "$(uname -s)" = Darwin ] || usage "this script needs macOS (codesign, lipo)"
[ "$#" -eq 3 ] || usage "usage: verify-release-binary.sh BINARY CERT_SHA1 VERSION"
binary=$1
cert=$2
version=$3
nl='
'
# valid VALUE ERE: one line only (grep alone passes when any line of a multi-line value matches)
valid() {
    case "$1" in *"$nl"*) return 1 ;; esac
    printf '%s' "$1" | grep -Eq "$2"
}
valid "$cert" '^[0-9a-f]{40}$' || usage "CERT_SHA1 must be 40 lower-case hex digits"
valid "$version" '^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?$' || usage "VERSION must be X.Y.Z (or X.Y.Z-suffix)"
identifier=$(sh "$here/release-info.sh" identifier)

problems=0
problem() { printf 'verify: %s\n' "$1"; problems=$((problems + 1)); }

if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    printf 'verify: no executable file at %s\n' "$binary"
    exit 1
fi

if ! codesign --verify --strict "$binary" >/dev/null 2>&1; then
    problem "the signature does not verify (codesign --verify --strict)"
fi

details=$(codesign -dvv "$binary" 2>&1 || true)
if ! printf '%s\n' "$details" | grep -Eq 'flags=0x[0-9a-f]+\([^)]*runtime'; then
    problem "the hardened runtime flag is not set"
fi
if ! printf '%s\n' "$details" | grep -Fxq "Identifier=$identifier"; then
    problem "the identifier is not $identifier"
fi

entitlements=$(codesign -d --entitlements - "$binary" 2>/dev/null | tr -d '[:space:]')
if [ -n "$entitlements" ]; then
    problem "the binary carries entitlements (get-task-allow would let a debugger attach; others weaken the hardened runtime)"
fi

archs=$(lipo -archs "$binary" 2>/dev/null || true)
for arch in arm64 x86_64; do
    case " $archs " in
    *" $arch "*) ;;
    *) problem "the binary has no $arch slice (found: ${archs:-none})" ;;
    esac
done

requirement=$(codesign -d -r- "$binary" 2>&1 || true)
if ! why=$(printf '%s\n' "$requirement" | sh "$here/release-info.sh" requirement-ok "$cert" 2>&1); then
    problem "the designated requirement does not name certificate $cert exactly (${why#release-info: })"
fi

printed=$("$binary" version 2>/dev/null || true)
if [ "$printed" != "wardenrun $version" ]; then
    problem "'wardenrun version' printed '$printed', expected 'wardenrun $version'"
fi

if [ "$problems" -ne 0 ]; then
    exit 1
fi
echo "verify: ok"
