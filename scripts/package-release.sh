#!/bin/sh
# Builds, signs and packs a release. macOS only; needs the signing certificate in a keychain.
# Usage: SIGN_IDENTITY=<certificate SHA-1 or name> [SIGN_KEYCHAIN=<path>] [DIST=<dir>] \
#        sh scripts/package-release.sh VERSION
# Writes DIST/wardenrun-VERSION-macos-universal.tar.gz (wardenrun + LICENSE) and its .sha256
# (default DIST is dist/). The tree must be clean. VERSION only names the asset: that the tag
# equals WardenrunVersion.current is checked by the workflow (release-info.sh check-version),
# and that the binary reports VERSION by scripts/verify-release-binary.sh, which the caller
# runs on the binary inside the tarball: what is checked is what users get.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

die() { printf 'package-release: %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this script needs macOS (codesign, lipo)"
[ "$#" -eq 1 ] || die "usage: package-release.sh VERSION"
version=$1
[ -n "${SIGN_IDENTITY:-}" ] || die "SIGN_IDENTITY is not set"
[ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree has uncommitted changes"

identifier=$(sh "$here/release-info.sh" identifier)
asset=$(sh "$here/release-info.sh" name "$version")
dist=${DIST:-"$root/dist"}
rm -rf "$dist"
mkdir -p "$dist"
stage=$(mktemp -d "${TMPDIR:-/tmp}/wardenrun-release.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM

cd "$root"
swift build -c release --arch arm64 --arch x86_64
built=$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/wardenrun
[ -f "$built" ] || die "the build produced no binary at $built"
cp "$built" "$stage/wardenrun"
cp LICENSE "$stage/LICENSE"

set -- --force --options runtime --identifier "$identifier" --timestamp=none --sign "$SIGN_IDENTITY"
if [ -n "${SIGN_KEYCHAIN:-}" ]; then
    set -- "$@" --keychain "$SIGN_KEYCHAIN"
fi
codesign "$@" "$stage/wardenrun"

COPYFILE_DISABLE=1 tar -C "$stage" -czf "$dist/$asset" wardenrun LICENSE
(cd "$dist" && shasum -a 256 "$asset" > "$asset.sha256")
printf 'package-release: wrote %s\n' "$dist/$asset"
