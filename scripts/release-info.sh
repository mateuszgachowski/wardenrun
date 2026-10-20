#!/bin/sh
# Names and checks shared by the release scripts and the workflow.
# Usage:
#   sh scripts/release-info.sh identifier               the code-signing identifier of the binary
#   sh scripts/release-info.sh name X.Y.Z               asset file name for that version
#   sh scripts/release-info.sh print-version [ROOT]     WardenrunVersion.current from Usage.swift
#   sh scripts/release-info.sh check-version TAG [ROOT] exit 0 only if TAG is "v" + that version
# ROOT is the repository root (default: the one this script lives in).
# Exit 64 for a wrong argument, 1 when a tag does not match the source.
here=$(cd "$(dirname "$0")" && pwd)

usage() { printf 'release-info: %s\n' "$1" >&2; exit 64; }

source_version() { # ROOT -> the string in Usage.swift, or nothing
    file="$1/Sources/WardenrunCore/Usage.swift"
    [ -f "$file" ] || return 0
    sed -n 's/^[[:space:]]*public static let current = "\([^"]*\)"[[:space:]]*$/\1/p' "$file" | head -n 1
}

command=${1:-}
[ -n "$command" ] || usage "usage: release-info.sh name|print-version|check-version ..."
shift

case "$command" in
identifier)
    [ "$#" -eq 0 ] || usage "usage: release-info.sh identifier"
    printf 'io.github.mateuszgachowski.wardenrun\n'
    ;;
name)
    [ "$#" -eq 1 ] || usage "usage: release-info.sh name X.Y.Z"
    printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || usage "version must be X.Y.Z"
    printf 'wardenrun-%s-macos-universal.tar.gz\n' "$1"
    ;;
print-version)
    root=${1:-"$here/.."}
    version=$(source_version "$root")
    [ -n "$version" ] || { printf 'release-info: no WardenrunVersion.current in %s\n' "$root" >&2; exit 1; }
    printf '%s\n' "$version"
    ;;
check-version)
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage "usage: release-info.sh check-version TAG [ROOT]"
    tag=$1
    root=${2:-"$here/.."}
    version=$(source_version "$root")
    if [ -z "$version" ]; then
        printf 'release-info: no WardenrunVersion.current in %s\n' "$root" >&2
        exit 1
    fi
    if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        printf 'release-info: WardenrunVersion.current (%s) is not a release version X.Y.Z\n' "$version" >&2
        exit 1
    fi
    if [ "$tag" != "v$version" ]; then
        printf 'release-info: tag %s does not match WardenrunVersion.current (%s)\n' "$tag" "$version" >&2
        exit 1
    fi
    ;;
*)
    usage "unknown command: $command"
    ;;
esac
