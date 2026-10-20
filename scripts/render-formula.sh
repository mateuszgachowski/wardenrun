#!/bin/sh
# Fills packaging/wardenrun.rb.in and prints the Homebrew formula on stdout.
# Usage: sh scripts/render-formula.sh VERSION SHA256 CERT_SHA1
#   VERSION    X.Y.Z (no "v", no suffix)
#   SHA256     64 lower-case hex digits: the release tarball
#   CERT_SHA1  40 lower-case hex digits: the signing certificate the formula test checks
# Exit 64 with one line on stderr when an argument is wrong.
here=$(cd "$(dirname "$0")" && pwd)
template="$here/../packaging/wardenrun.rb.in"

usage() { printf 'render-formula: %s\n' "$1" >&2; exit 64; }

nl='
'
# valid VALUE ERE: one line only (grep alone passes when any line of a multi-line value matches,
# and a newline in a value would put Ruby code into the formula)
valid() {
    case "$1" in *"$nl"*) return 1 ;; esac
    printf '%s' "$1" | grep -Eq "$2"
}

[ "$#" -eq 3 ] || usage "usage: render-formula.sh VERSION SHA256 CERT_SHA1"
version=$1
sha256=$2
cert=$3

valid "$version" '^[0-9]+\.[0-9]+\.[0-9]+$' || usage "VERSION must be X.Y.Z"
valid "$sha256" '^[0-9a-f]{64}$' || usage "SHA256 must be 64 lower-case hex digits"
valid "$cert" '^[0-9a-f]{40}$' || usage "CERT_SHA1 must be 40 lower-case hex digits"
[ -f "$template" ] || usage "template not found: $template"

asset=$(sh "$here/release-info.sh" name "$version") || usage "no asset name for $version"
sed -e "s/@VERSION@/$version/g" -e "s/@ASSET@/$asset/g" -e "s/@SHA256@/$sha256/g" -e "s/@CERT_SHA1@/$cert/g" "$template"
