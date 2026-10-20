#!/bin/sh
# Builds the universal (arm64 + x86_64) release binary, UNSIGNED. macOS only.
# Usage: sh scripts/build-release-binary.sh DEST_DIR        writes DEST_DIR/wardenrun
# This is the step that runs the Swift toolchain and the package manifest, so the release
# workflow runs it in a job that has no signing material (see scripts/sign-release.sh).
# The tree must be clean: what is built is what is committed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

die() { printf 'build-release-binary: %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this script needs macOS (lipo, a universal Swift build)"
[ "$#" -eq 1 ] || die "usage: build-release-binary.sh DEST_DIR"
dest=$1
[ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree has uncommitted changes"

cd "$root"
swift build -c release --arch arm64 --arch x86_64
built=$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)/wardenrun
[ -f "$built" ] || die "the build produced no binary at $built"
mkdir -p "$dest"
cp "$built" "$dest/wardenrun"
printf 'build-release-binary: wrote %s\n' "$dest/wardenrun"
