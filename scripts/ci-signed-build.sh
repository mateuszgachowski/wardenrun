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

# A DYLD_ variable is refused with 78 before anything is asked or stored.
status=0
DYLD_FRAMEWORK_PATH=/nonexistent "$binary" setup </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 78 ] || { echo "ci: expected exit 78 with DYLD_ set, got $status" >&2; exit 1; }

# Without a terminal, setup refuses with 64 and reads nothing.
status=0
"$binary" setup </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 64 ] || { echo "ci: expected exit 64 without a terminal, got $status" >&2; exit 1; }

# A usage error is 64, help and version work.
status=0
"$binary" run </dev/null >/dev/null 2>&1 || status=$?
[ "$status" -eq 64 ] || { echo "ci: expected exit 64 for a bad command line, got $status" >&2; exit 1; }
"$binary" version | grep -q '^wardenrun '
"$binary" help | grep -q '^usage:'
echo "ci: signed binary checks passed"
