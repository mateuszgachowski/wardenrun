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

[ "$#" -eq 3 ] || usage "usage: render-formula.sh VERSION SHA256 CERT_SHA1"
version=$1
sha256=$2
cert=$3

printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || usage "VERSION must be X.Y.Z"
printf '%s\n' "$sha256" | grep -Eq '^[0-9a-f]{64}$' || usage "SHA256 must be 64 lower-case hex digits"
printf '%s\n' "$cert" | grep -Eq '^[0-9a-f]{40}$' || usage "CERT_SHA1 must be 40 lower-case hex digits"
[ -f "$template" ] || usage "template not found: $template"

asset=$(sh "$here/release-info.sh" name "$version") || usage "no asset name for $version"
sed -e "s/@VERSION@/$version/g" -e "s/@ASSET@/$asset/g" -e "s/@SHA256@/$sha256/g" -e "s/@CERT_SHA1@/$cert/g" "$template"
