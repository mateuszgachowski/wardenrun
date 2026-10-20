#!/bin/sh
# Tests for scripts/render-formula.sh. Usage: sh scripts/test-render-formula.sh
here=$(cd "$(dirname "$0")" && pwd)
render="$here/render-formula.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-render-formula.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: > "$tmp/failed"

pass() { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s: %s\n' "$1" "$2"; printf x >> "$tmp/failed"; }

sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
cert=fedcba9876543210fedcba9876543210fedcba98

run() { # args... -> $out, $status (stdout and stderr kept apart)
    status=0
    out=$(sh "$render" "$@" 2>"$tmp/err") || status=$?
    err=$(cat "$tmp/err")
}

contains() { # name needle
    if printf '%s\n' "$out" | grep -Fq -- "$2"; then pass "$1"; else bad "$1" "missing: $2"; fi
}
lacks() { # name needle
    if printf '%s\n' "$out" | grep -Fq -- "$2"; then bad "$1" "unexpected: $2"; else pass "$1"; fi
}
refuses() { # name args...
    name=$1; shift
    run "$@"
    if [ "$status" -eq 64 ] && [ -n "$err" ] && [ -z "$out" ]; then pass "$name"; else bad "$name" "status $status out=[$out] err=[$err]"; fi
}

run 1.2.3 "$sha" "$cert"
[ "$status" -eq 0 ] || bad rendersWithValidInput "status $status: $err"

if printf '%s\n' "$out" | grep -q '@[A-Z0-9_]*@'; then bad rendersEveryPlaceholder "left: $(printf '%s\n' "$out" | grep '@[A-Z0-9_]*@')"; else pass rendersEveryPlaceholder; fi
contains theUrlNamesTheTagAndTheAsset 'url "https://github.com/mateuszgachowski/wardenrun/releases/download/v1.2.3/wardenrun-1.2.3-macos-universal.tar.gz"'
contains theSha256IsInTheFormula "sha256 \"$sha\""
contains theCertificateHashIsInTheTestBlock "H\\\"$cert\\\""
contains theTestBlockChecksTheVersion 'wardenrun 1.2.3'
contains theTestBlockChecksTheSignature '--verify'
contains theTestBlockReadsTheRequirement 'codesign -d -r-'
lacks formulaDoesNotDependOnBitwardenCli 'depends_on "bitwarden-cli"'
lacks formulaDoesNotDependOnAnyFormula 'depends_on "'
lacks formulaHasNoBitwardenDependencyInAnyForm 'depends_on "bitwarden'
contains formulaIsMacosOnly 'depends_on :macos'
contains formulaHasTheMitLicense 'license "MIT"'
contains theBinaryIsNotStrippedBecauseThatWouldBreakTheSignature 'skip_clean "bin/wardenrun"'
contains caveatsPointToTheOfficialBw "Bitwarden's GitHub releases"
contains caveatsPointToSetup 'wardenrun setup'

if command -v ruby >/dev/null 2>&1; then
    printf '%s\n' "$out" > "$tmp/wardenrun.rb"
    if ruby -c "$tmp/wardenrun.rb" >/dev/null 2>&1; then pass rubySyntaxIsValid; else bad rubySyntaxIsValid "ruby -c failed"; fi
fi

refuses rejectsAVPrefixedVersion v1.2.3 "$sha" "$cert"
refuses rejectsADevVersion 0.1.0-dev "$sha" "$cert"
refuses rejectsAVersionWithTwoParts 1.2 "$sha" "$cert"
refuses rejectsAVersionWithAShellMetacharacter '1.2.3;x' "$sha" "$cert"
refuses rejectsAShortSha256 1.2.3 0123abcd "$cert"
refuses rejectsAnUppercaseSha256 1.2.3 "$(printf '%s' "$sha" | tr 'a-f' 'A-F')" "$cert"
refuses rejectsASha256ThatIsTooLong 1.2.3 "${sha}0" "$cert"
refuses rejectsAShortCertificateHash 1.2.3 "$sha" fedcba98
refuses rejectsACertificateHashThatIsASha256 1.2.3 "$sha" "$sha"
refuses rejectsMissingArguments 1.2.3 "$sha"
refuses rejectsExtraArguments 1.2.3 "$sha" "$cert" extra

[ ! -s "$tmp/failed" ]
