#!/bin/sh
# Tests for the argument handling of scripts/verify-release-binary.sh and
# scripts/package-release.sh. Only paths that never call codesign run here; the signing paths
# are exercised by scripts/ci-release-dry-run.sh on a macOS runner.
# Usage: sh scripts/test-verify-release-binary.sh        (macOS only; elsewhere it skips)
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(uname -s)" != Darwin ]; then echo "skip: needs macOS"; exit 0; fi
verify="$here/verify-release-binary.sh"
package="$here/package-release.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-verify.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: > "$tmp/failed"

pass() { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s: %s\n' "$1" "$2"; printf x >> "$tmp/failed"; }

cert=0123456789abcdef0123456789abcdef01234567

check() { # name expected-status script args...
    name=$1; want=$2; script=$3; shift 3
    status=0
    out=$(sh "$script" "$@" 2>&1) || status=$?
    if [ "$status" -eq "$want" ]; then pass "$name"; else bad "$name" "expected $want, got $status: $out"; fi
}

check verifyNeedsThreeArguments 64 "$verify" /bin/ls "$cert"
check verifyRejectsAShortCertificateHash 64 "$verify" /bin/ls 0123 1.2.3
check verifyRejectsAnUppercaseCertificateHash 64 "$verify" /bin/ls "$(printf '%s' "$cert" | tr 'a-f' 'A-F')" 1.2.3
check verifyRejectsAVersionWithAV 64 "$verify" /bin/ls "$cert" v1.2.3
check verifyRejectsAVersionWithAShellMetacharacter 64 "$verify" /bin/ls "$cert" '1.2.3;x'
check verifyReportsAMissingBinary 1 "$verify" "$tmp/nothing" "$cert" 1.2.3
status=0
out=$(sh "$verify" "$tmp/nothing" "$cert" 1.2.3 2>&1) || status=$?
if printf '%s' "$out" | grep -q "no executable file at $tmp/nothing"; then pass verifyNamesTheMissingFile; else bad verifyNamesTheMissingFile "$out"; fi
printf 'not executable\n' > "$tmp/plain"
check verifyRejectsAFileThatIsNotExecutable 1 "$verify" "$tmp/plain" "$cert" 1.2.3

check packageNeedsAVersion 1 "$package"
check packageNeedsASigningIdentity 1 "$package" 1.2.3
status=0
out=$(env -u SIGN_IDENTITY sh "$package" 1.2.3 2>&1) || status=$?
if printf '%s' "$out" | grep -q 'SIGN_IDENTITY is not set'; then pass packageSaysWhyItStopped; else bad packageSaysWhyItStopped "$out"; fi

[ ! -s "$tmp/failed" ]
