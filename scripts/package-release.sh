#!/bin/sh
# Builds, signs and packs a release in one go, for a maintainer's Mac and for the CI dry run.
# macOS only; needs the signing certificate in a keychain.
# Usage: SIGN_IDENTITY=<certificate SHA-1 or name> [SIGN_KEYCHAIN=<path>] [DIST=<dir>] \
#        sh scripts/package-release.sh VERSION
# The release workflow does the same in two jobs, so that the job that holds the signing key
# runs no build code: scripts/build-release-binary.sh (no secrets), then scripts/sign-release.sh.
# Writes DIST/wardenrun-VERSION-macos-universal.tar.gz (wardenrun + LICENSE) and its .sha256
# (default DIST is dist/). The tree must be clean. Run scripts/verify-release-binary.sh on the
# binary inside the tarball afterwards.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

die() { printf 'package-release: %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this script needs macOS (codesign, lipo)"
[ "$#" -eq 1 ] || die "usage: package-release.sh VERSION"
version=$1
[ -n "${SIGN_IDENTITY:-}" ] || die "SIGN_IDENTITY is not set"
[ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree has uncommitted changes"

stage=$(mktemp -d "${TMPDIR:-/tmp}/wardenrun-package.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
sh "$here/build-release-binary.sh" "$stage/unsigned"
sh "$here/sign-release.sh" "$stage/unsigned/wardenrun" "$version"
