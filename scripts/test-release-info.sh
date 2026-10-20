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

expect_failure_saying() { # name needle  (exit 1 and the message names the real reason)
    if [ "$status" -eq 1 ] && printf '%s' "$err" | grep -q "$2"; then pass "$1"; else bad "$1" "status $status, wanted a message with [$2], got [$err]"; fi
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

# The pinned certificate: the hash committed in packaging/signing-cert.sha1 is the only identity a release may be signed with.
pinned=0123456789abcdef0123456789abcdef01234567
other=fedcba9876543210fedcba9876543210fedcba98
pinroot() { mkdir -p "$tmp/$1/packaging"; cat > "$tmp/$1/packaging/signing-cert.sha1"; } # name, file content on stdin
printf '%s\n' "$pinned" | pinroot pin
run check-cert-pin "$pinned" "$tmp/pin";  expect_status checkCertPinAcceptsTheCommittedHash 0
run check-cert-pin "$other" "$tmp/pin"
if [ "$status" -eq 1 ] && printf '%s' "$err" | grep -q 'does not match the pinned certificate'; then pass checkCertPinRejectsAnotherCertificateAndSaysWhy; else bad checkCertPinRejectsAnotherCertificateAndSaysWhy "$status [$err]"; fi
mkdir -p "$tmp/nopin"
run check-cert-pin "$pinned" "$tmp/nopin"
expect_failure_saying checkCertPinFailsWithoutTheFileAndNamesIt 'packaging/signing-cert.sha1 does not exist'
printf '%s' "$pinned" | pinroot pinnl
run check-cert-pin "$pinned" "$tmp/pinnl"; expect_status checkCertPinAcceptsAFileWithoutATrailingNewline 0
printf '%s\n%s\n' "$pinned" "$other" | pinroot pin2
run check-cert-pin "$pinned" "$tmp/pin2"; expect_failure_saying checkCertPinRejectsAFileWithTwoLines 'exactly one line'
printf '%s\n' "$pinned" | tr 'a-f' 'A-F' | pinroot pinup
run check-cert-pin "$pinned" "$tmp/pinup"; expect_failure_saying checkCertPinRejectsAnUppercaseFile 'exactly one line'
printf '%s \n' "$pinned" | pinroot pinsp
run check-cert-pin "$pinned" "$tmp/pinsp"; expect_failure_saying checkCertPinRejectsATrailingSpace 'exactly one line'
: | pinroot pinempty
run check-cert-pin "$pinned" "$tmp/pinempty"; expect_failure_saying checkCertPinRejectsAnEmptyFile 'exactly one line'
printf '# the certificate\n%s\n' "$pinned" | pinroot pincomment
run check-cert-pin "$pinned" "$tmp/pincomment"; expect_failure_saying checkCertPinRejectsAFileWithAComment 'exactly one line'
run check-cert-pin abc "$tmp/pin";        expect_status checkCertPinRejectsAMalformedImportedHash 64
nl='
'
run check-cert-pin "$pinned${nl}$other" "$tmp/pin"; expect_status checkCertPinRejectsAHashWithANewline 64
run check-cert-pin;                       expect_status checkCertPinNeedsTheImportedHash 64

# The requirement a release binary must have, as one exact line.
want="designated => identifier \"io.github.mateuszgachowski.wardenrun\" and certificate leaf = H\"$pinned\""
run requirement "$pinned"
if [ "$status" -eq 0 ] && [ "$out" = "$want" ]; then pass requirementPrintsTheWholeLine; else bad requirementPrintsTheWholeLine "[$out] $status"; fi
run requirement 0123;                     expect_status requirementRejectsAShortHash 64
run requirement "$pinned${nl}$other";     expect_status requirementRejectsAHashWithANewline 64

reqok() { # name expected-status  (codesign output on stdin)
    reqname=$1; reqwant=$2
    status=0
    sh "$info" requirement-ok "$pinned" >/dev/null 2>"$tmp/err" || status=$?
    if [ "$status" -eq "$reqwant" ]; then pass "$reqname"; else bad "$reqname" "expected $reqwant, got $status ($(cat "$tmp/err"))"; fi
}
printf 'Executable=/x/wardenrun\n%s\n' "$want" | reqok requirementOkAcceptsTheExactLine 0
printf 'Executable=/x/wardenrun\n# %s\n' "$want" | reqok requirementOkAcceptsTheOlderCommentedForm 0
printf '%s\n%s\n' "$want" "$want" | reqok requirementOkAcceptsTheSameLineForEverySlice 0
printf '%s or certificate leaf = H"%s"\n' "$want" "$other" | reqok requirementOkRejectsAnExtendedRequirement 1
printf '%s\n%s\n' "$want" "designated => identifier \"io.github.mateuszgachowski.wardenrun\" and certificate leaf = H\"$other\"" | reqok requirementOkRejectsAnyOtherDesignatedLine 1
printf 'designated => identifier "other.id" and certificate leaf = H"%s"\n' "$pinned" | reqok requirementOkRejectsAnotherIdentifier 1
printf 'designated => identifier "io.github.mateuszgachowski.wardenrun" and certificate leaf = H"%s"\n' "$other" | reqok requirementOkRejectsAnotherCertificate 1
printf 'Executable=/x/wardenrun\n' | reqok requirementOkRejectsOutputWithoutARequirement 1
printf '' | reqok requirementOkRejectsEmptyOutput 1
printf 'designated => anchor apple\n' | reqok requirementOkRejectsAnAppleAnchoredRequirement 1

run name "1.2.3${nl}9.9.9";               expect_status nameRejectsAVersionWithANewline 64

# The formula's download URL ends in the asset name this script prints.
sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
cert=fedcba9876543210fedcba9876543210fedcba98
url=$(sh "$render" 4.5.6 "$sha" "$cert" | sed -n 's/^  url "\(.*\)"$/\1/p')
expected=$(sh "$info" name 4.5.6)
if [ -n "$url" ] && [ "${url##*/}" = "$expected" ] && printf '%s' "$url" | grep -q '/download/v4.5.6/'; then pass theAssetNameMatchesTheFormulaUrl; else bad theAssetNameMatchesTheFormulaUrl "url=[$url] expected=[$expected]"; fi

[ ! -s "$tmp/failed" ]
