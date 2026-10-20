#!/bin/sh
# Workflow lint: the rules that keep the release pipeline from leaking its signing key.
# Usage: sh scripts/check-workflows.sh [ROOT]     (default ROOT is the current directory)
# Prints one "FAIL: W<n>: <file>: <where>: <detail>" line per violation and exits 1; prints
# "workflow lint: ok" and exits 0 when clean. The rules are in scripts/check-workflows.rb; they
# work on the parsed YAML, so Ruby is needed (it is on macOS and on the Ubuntu runners).
here=$(cd "$(dirname "$0")" && pwd)
if ! command -v ruby >/dev/null 2>&1; then
    echo "FAIL: W5: ruby is needed to parse the workflows and was not found"
    exit 1
fi
exec ruby "$here/check-workflows.rb" "$@"
