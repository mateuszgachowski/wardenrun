#!/bin/sh
# Names and checks shared by the release scripts and the workflow.
# Usage:
#   sh scripts/release-info.sh identifier               the code-signing identifier of the binary
#   sh scripts/release-info.sh name X.Y.Z               asset file name for that version
#   sh scripts/release-info.sh print-version [ROOT]     WardenrunVersion.current from Usage.swift
#   sh scripts/release-info.sh check-version TAG [ROOT] exit 0 only if TAG is "v" + that version
#   sh scripts/release-info.sh check-cert-pin SHA1 [ROOT]
#                                                       exit 0 only if SHA1 is the certificate hash committed in
#                                                       packaging/signing-cert.sha1 (the only identity a release may use)
#   sh scripts/release-info.sh requirement SHA1         the one designated-requirement line a release binary must have
#   sh scripts/release-info.sh requirement-ok SHA1      reads `codesign -d -r-` output on stdin; exit 0 only if every
#                                                       designated line in it is exactly that line (and there is one)
# ROOT is the repository root (default: the one this script lives in).
# Exit 64 for a wrong argument, 1 when a tag, a certificate or a requirement does not match.
here=$(cd "$(dirname "$0")" && pwd)

usage() { printf 'release-info: %s\n' "$1" >&2; exit 64; }

nl='
'
# valid VALUE ERE: one line only (grep alone passes when any line of a multi-line value matches)
valid() {
    case "$1" in *"$nl"*) return 1 ;; esac
    printf '%s' "$1" | grep -Eq "$2"
}

identifier_value=io.github.mateuszgachowski.wardenrun
expected_requirement() { printf 'designated => identifier "%s" and certificate leaf = H"%s"\n' "$identifier_value" "$1"; }

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
    printf '%s\n' "$identifier_value"
    ;;
name)
    [ "$#" -eq 1 ] || usage "usage: release-info.sh name X.Y.Z"
    valid "$1" '^[0-9]+\.[0-9]+\.[0-9]+$' || usage "version must be X.Y.Z"
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
check-cert-pin)
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage "usage: release-info.sh check-cert-pin CERT_SHA1 [ROOT]"
    imported=$1
    root=${2:-"$here/.."}
    valid "$imported" '^[0-9a-f]{40}$' || usage "CERT_SHA1 must be 40 lower-case hex digits"
    file="$root/packaging/signing-cert.sha1"
    if [ ! -f "$file" ]; then
        printf 'release-info: packaging/signing-cert.sha1 does not exist: commit the signing certificate SHA-1 there (docs/RELEASING.md, section 1)\n' >&2
        exit 1
    fi
    pinned=$(cat "$file")
    if ! valid "$pinned" '^[0-9a-f]{40}$'; then
        printf 'release-info: packaging/signing-cert.sha1 must hold exactly one line of 40 lower-case hex digits\n' >&2
        exit 1
    fi
    if [ "$imported" != "$pinned" ]; then
        printf 'release-info: the imported certificate (%s) does not match the pinned certificate (%s) in packaging/signing-cert.sha1\n' "$imported" "$pinned" >&2
        exit 1
    fi
    ;;
requirement)
    [ "$#" -eq 1 ] || usage "usage: release-info.sh requirement CERT_SHA1"
    valid "$1" '^[0-9a-f]{40}$' || usage "CERT_SHA1 must be 40 lower-case hex digits"
    expected_requirement "$1"
    ;;
requirement-ok)
    [ "$#" -eq 1 ] || usage "usage: release-info.sh requirement-ok CERT_SHA1"
    valid "$1" '^[0-9a-f]{40}$' || usage "CERT_SHA1 must be 40 lower-case hex digits"
    want=$(expected_requirement "$1")
    lines=$(sed -n -e 's/^#[[:space:]]*//' -e '/^designated => /p')
    if [ -z "$lines" ]; then
        printf 'release-info: no designated requirement in the codesign output\n' >&2
        exit 1
    fi
    other=$(printf '%s\n' "$lines" | grep -Fvx -- "$want" || true)
    if [ -n "$other" ]; then
        printf 'release-info: unexpected designated requirement: %s\n' "$(printf '%s\n' "$other" | head -n 1)" >&2
        exit 1
    fi
    ;;
*)
    usage "unknown command: $command"
    ;;
esac
