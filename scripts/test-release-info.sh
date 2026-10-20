#!/bin/sh
# Tests for scripts/release-info.sh. Usage: sh scripts/test-release-info.sh
here=$(cd "$(dirname "$0")" && pwd)
info="$here/release-info.sh"
render="$here/render-formula.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-release-info.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: > "$tmp/failed"

pass() { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s: %s\n' "$1" "$2"; printf x >> "$tmp/failed"; }

run() { status=0; out=$(sh "$info" "$@" 2>"$tmp/err") || status=$?; err=$(cat "$tmp/err"); }

# root VERSION -> a fixture root whose Usage.swift declares VERSION
root() {
    mkdir -p "$tmp/$1/Sources/WardenrunCore"
    cat > "$tmp/$1/Sources/WardenrunCore/Usage.swift" <<SWIFT
public enum WardenrunVersion {
    public static let current = "$2"
}
SWIFT
}

expect_status() { # name expected-status
    if [ "$status" -eq "$2" ]; then pass "$1"; else bad "$1" "expected $2, got $status (out=[$out] err=[$err])"; fi
}

run identifier
if [ "$status" -eq 0 ] && [ "$out" = "io.github.mateuszgachowski.wardenrun" ]; then pass identifierIsTheFixedSigningIdentifier; else bad identifierIsTheFixedSigningIdentifier "[$out] $status"; fi

run name 1.2.3
if [ "$status" -eq 0 ] && [ "$out" = "wardenrun-1.2.3-macos-universal.tar.gz" ]; then pass nameIsAssetNameForVersion; else bad nameIsAssetNameForVersion "[$out] $status"; fi
run name v1.2.3;       expect_status nameRejectsTagForm 64
run name 0.1.0-dev;    expect_status nameRejectsDevVersion 64
run name 1.2;          expect_status nameRejectsTwoPartVersion 64
run name;              expect_status nameNeedsAVersion 64
run frobnicate 1.2.3;  expect_status unknownCommandIs64 64

root good 1.2.3
run check-version v1.2.3 "$tmp/good";   expect_status checkVersionAcceptsMatchingTag 0
run check-version v1.2.4 "$tmp/good"
if [ "$status" -eq 1 ] && printf '%s' "$err" | grep -q 'does not match WardenrunVersion.current (1.2.3)'; then pass checkVersionRejectsMismatchAndSaysWhy; else bad checkVersionRejectsMismatchAndSaysWhy "$status [$err]"; fi
run check-version 1.2.3 "$tmp/good";    expect_status checkVersionRejectsATagWithoutV 1
run check-version v1.2.30 "$tmp/good";  expect_status checkVersionRejectsAPrefixMatch 1
run check-version v1.2 "$tmp/good";     expect_status checkVersionRejectsAShorterTag 1
run check-version "v1.2.3 " "$tmp/good"; expect_status checkVersionRejectsATrailingSpace 1

root dev 0.1.0-dev
run check-version v0.1.0-dev "$tmp/dev"; expect_status checkVersionRejectsADevVersionEvenIfTheTagMatches 1
run check-version v0.1.0 "$tmp/dev";     expect_status checkVersionRejectsATagForADevVersion 1

mkdir -p "$tmp/none/Sources/WardenrunCore"
printf 'public enum Other {}\n' > "$tmp/none/Sources/WardenrunCore/Usage.swift"
run check-version v1.2.3 "$tmp/none"
if [ "$status" -eq 1 ] && printf '%s' "$err" | grep -q 'no WardenrunVersion.current'; then pass checkVersionFailsWhenTheConstantIsMissing; else bad checkVersionFailsWhenTheConstantIsMissing "$status [$err]"; fi
run print-version "$tmp/none";             expect_status printVersionFailsWithoutTheConstant 1

mkdir -p "$tmp/nofile"
run check-version v1.2.3 "$tmp/nofile";  expect_status checkVersionFailsWhenUsageSwiftIsMissing 1

run print-version "$tmp/good"
if [ "$status" -eq 0 ] && [ "$out" = "1.2.3" ]; then pass printVersionPrintsTheConstant; else bad printVersionPrintsTheConstant "[$out] $status"; fi
run print-version
if [ "$status" -eq 0 ] && printf '%s\n' "$out" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?$'; then pass theRealUsageSwiftHasAParsableVersion; else bad theRealUsageSwiftHasAParsableVersion "[$out] $status [$err]"; fi

# The formula's download URL ends in the asset name this script prints.
sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
cert=fedcba9876543210fedcba9876543210fedcba98
url=$(sh "$render" 4.5.6 "$sha" "$cert" | sed -n 's/^  url "\(.*\)"$/\1/p')
expected=$(sh "$info" name 4.5.6)
if [ -n "$url" ] && [ "${url##*/}" = "$expected" ] && printf '%s' "$url" | grep -q '/download/v4.5.6/'; then pass theAssetNameMatchesTheFormulaUrl; else bad theAssetNameMatchesTheFormulaUrl "url=[$url] expected=[$expected]"; fi

[ ! -s "$tmp/failed" ]
