#!/bin/sh
# CI check for the macOS binary: build it in release mode, sign it ad hoc with the hardened
# runtime (the release will use a real certificate; the flags are the same), and read what the
# program itself reports. The exit code of `doctor` is NOT asserted: a runner has no Touch ID
# and no stored item, which doctor reports as FAIL or info. Only named lines are checked.
set -eu

swift build -c release
binary=.build/release/wardenrun

codesign --force --sign - --options runtime "$binary"
codesign --verify --strict "$binary"
codesign -d --verbose=2 "$binary" 2>&1 | grep -q 'flags=0x10002(adhoc,runtime)'

# The release verifier must reject this binary: it is ad hoc, not signed by the release certificate.
status=0
verdict="$(sh scripts/verify-release-binary.sh "$binary" 0000000000000000000000000000000000000000 0.0.0 2>&1)" || status=$?
[ "$status" -eq 1 ] || { echo "ci: the release verifier accepted an ad-hoc binary ($status)" >&2; exit 1; }
printf '%s\n' "$verdict" | grep -q 'does not name certificate' || { echo "ci: unexpected verifier output: $verdict" >&2; exit 1; }

output="$("$binary" doctor || true)"
printf '%s\n' "$output"

expect() {
    printf '%s\n' "$output" | grep -Eq "$1" || { echo "ci: doctor did not print: $1" >&2; exit 1; }
}
expect '^ok +hardened-runtime '
expect '^ok +deny-attach '
expect '^ok +core-dumps '
expect '^ok +dyld-environment '
expect '^info +certificate .*ad-hoc'
if printf '%s\n' "$output" | grep -Eq '^FAIL +(hardened-runtime|deny-attach|core-dumps|dyld-environment) '; then
    echo "ci: a hardening check failed" >&2
    exit 1
fi

# The signed binary has the hardened runtime, so dyld drops DYLD_ variables before wardenrun
# starts; wardenrun's own refusal (78) is the second line. Either way the variable must not get
# through: the command stops at the missing terminal (64) or at the refusal (78), never further.
status=0
DYLD_FRAMEWORK_PATH=/nonexistent "$binary" setup </dev/null >/dev/null 2>&1 || status=$?
case "$status" in
    64|78) ;;
    *) echo "ci: with DYLD_ set the signed binary exited $status, expected 64 or 78" >&2; exit 1 ;;
esac
dyld_output="$(DYLD_FRAMEWORK_PATH=/nonexistent "$binary" doctor || true)"
if printf '%s\n' "$dyld_output" | grep -Eq '^ok +dyld-environment '; then
    echo "ci: dyld dropped DYLD_FRAMEWORK_PATH before wardenrun started"
else
    printf '%s\n' "$dyld_output" | grep -Eq '^FAIL +dyld-environment ' || { echo "ci: doctor says nothing about dyld-environment" >&2; exit 1; }
    echo "ci: wardenrun saw DYLD_FRAMEWORK_PATH and refuses (second line of defence)"
fi

# Without a terminal, setup refuses with 64 and reads nothing; on a runner without a
# window-server session it refuses with 78 first, which doctor reports as graphic-session.
status=0
"$binary" setup </dev/null >/dev/null 2>&1 || status=$?
if printf '%s\n' "$output" | grep -Eq '^ok +graphic-session '; then
    [ "$status" -eq 64 ] || { echo "ci: expected exit 64 without a terminal, got $status" >&2; exit 1; }
else
    [ "$status" -eq 78 ] || { echo "ci: expected exit 78 without a graphic session, got $status" >&2; exit 1; }
fi

# A debug build is not hardened and sees the variable: wardenrun refuses it with 78 itself.
swift build
status=0
DYLD_FRAMEWORK_PATH=/nonexistent .build/debug/wardenrun setup </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 78 ] || { echo "ci: expected exit 78 from a debug build with DYLD_ set, got $status" >&2; exit 1; }

# A release build that is NOT signed with the hardened runtime refuses setup and run (78).
unsigned_dir="$(mktemp -d)"
cp "$binary" "$unsigned_dir/wardenrun"
codesign --force --sign - "$unsigned_dir/wardenrun"
status=0
"$unsigned_dir/wardenrun" setup </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 78 ] || { echo "ci: unhardened release build: setup exited $status, expected 78" >&2; exit 1; }
status=0
"$unsigned_dir/wardenrun" run item -- true </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 78 ] || { echo "ci: unhardened release build: run exited $status, expected 78" >&2; exit 1; }
rm -rf "$unsigned_dir"

# Nothing is set up on a runner: run and new say so and ask nothing (1); without a window-server
# session they stop earlier (78).
for words in "run item -- true" "new item"; do
    status=0
    message="$("$binary" $words </dev/null 2>&1)" || status=$?
    if printf '%s\n' "$output" | grep -Eq '^ok +graphic-session '; then
        [ "$status" -eq 1 ] || { echo "ci: '$words' exited $status, expected 1 (not set up)" >&2; exit 1; }
        printf '%s\n' "$message" | grep -q 'not set up' || { echo "ci: '$words' did not say it is not set up: $message" >&2; exit 1; }
    else
        [ "$status" -eq 78 ] || { echo "ci: '$words' exited $status, expected 78 without a graphic session" >&2; exit 1; }
    fi
done

# A usage error is 64, help and version work.
status=0
"$binary" run </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 64 ] || { echo "ci: expected exit 64 for a bad command line, got $status" >&2; exit 1; }
status=0
"$binary" new item --length 3 </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 64 ] || { echo "ci: expected exit 64 for new with a length of 3, got $status" >&2; exit 1; }
"$binary" version | grep -q '^wardenrun '
"$binary" help | grep -q '^usage:'
echo "ci: signed binary checks passed"
