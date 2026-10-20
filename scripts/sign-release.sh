#!/bin/sh
# Signs a built binary and packs the release tarball. macOS only.
# Usage: SIGN_IDENTITY=<certificate SHA-1 or name> [SIGN_KEYCHAIN=<path>] [DIST=<dir>] \
#        sh scripts/sign-release.sh BINARY VERSION
# Writes DIST/wardenrun-VERSION-macos-universal.tar.gz (wardenrun + LICENSE) and its .sha256
# (default DIST is dist/). VERSION only names the asset: that the tag equals
# WardenrunVersion.current is checked by the workflow (release-info.sh check-version), and that
# the binary reports VERSION by scripts/verify-release-binary.sh, which the caller runs on the
# binary inside the tarball: what is checked is what users get.
# This script runs no Swift and no code from the package: in the release workflow it is the
# only step that holds the signing key, so it must not execute build code.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

die() { printf 'sign-release: %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this script needs macOS (codesign)"
[ "$#" -eq 2 ] || die "usage: sign-release.sh BINARY VERSION"
binary=$1
version=$2
nl='
'
case "$version" in *"$nl"*) die "VERSION must be X.Y.Z" ;; esac
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "VERSION must be X.Y.Z"
[ -n "${SIGN_IDENTITY:-}" ] || die "SIGN_IDENTITY is not set"
[ -f "$binary" ] || die "no such binary: $binary"
[ -f "$root/LICENSE" ] || die "no LICENSE in $root"

identifier=$(sh "$here/release-info.sh" identifier)
asset=$(sh "$here/release-info.sh" name "$version")
dist=${DIST:-"$root/dist"}
[ -n "$dist" ] && [ "$dist" != / ] || die "refusing to use '$dist' as the output folder"
rm -rf "$dist"
mkdir -p "$dist"
stage=$(mktemp -d "${TMPDIR:-/tmp}/wardenrun-release.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM

cp "$binary" "$stage/wardenrun"
chmod 755 "$stage/wardenrun"
cp "$root/LICENSE" "$stage/LICENSE"

set -- --force --options runtime --identifier "$identifier" --timestamp=none --sign "$SIGN_IDENTITY"
if [ -n "${SIGN_KEYCHAIN:-}" ]; then
    set -- "$@" --keychain "$SIGN_KEYCHAIN"
fi
codesign "$@" "$stage/wardenrun"

COPYFILE_DISABLE=1 tar -C "$stage" -czf "$dist/$asset" wardenrun LICENSE
(cd "$dist" && shasum -a 256 "$asset" > "$asset.sha256")
printf 'sign-release: wrote %s\n' "$dist/$asset"
