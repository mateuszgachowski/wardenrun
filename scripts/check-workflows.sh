#!/bin/sh
# Workflow lint: the rules that keep the release pipeline from leaking its signing key.
# Usage: sh scripts/check-workflows.sh [ROOT]     (default ROOT is the current directory)
# Prints one "FAIL: W<n>: <file>:<line>: <detail>" line per violation and exits 1; prints
# "workflow lint: ok" and exits 0 when clean. POSIX sh + grep/awk/sed, so it runs the same on
# macOS and Ubuntu. It is a lint with heuristics, not a YAML parser; W5 parses for real when
# ruby is installed.
#
#   W1 every `uses:` (except ./local actions) is owner/repo[/path]@<40 hex commit>
#   W2 every workflow has a top-level `permissions:` (the default token must be narrowed)
#   W3 a workflow that reads a secret other than GITHUB_TOKEN has no pull_request,
#      pull_request_target, workflow_dispatch, issue_comment or workflow_run trigger
#   W4 no `${{ github.event.` or `${{ github.head_ref` outside an `if:` line (script injection)
#   W5 the file parses as YAML (checked when ruby is available)
root=${1:-.}
dir="$root/.github/workflows"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-workflows.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: > "$tmp/failed"

fail() { # rule file line detail
    printf 'FAIL: %s: %s:%s: %s\n' "$1" "$2" "$3" "$4"
    printf x >> "$tmp/failed"
}

files=$(ls "$dir"/*.yml "$dir"/*.yaml 2>/dev/null)
if [ -z "$files" ]; then
    printf 'FAIL: W0: %s: no workflow files found\n' "$dir"
    exit 1
fi

for file in $files; do
    name=${file#"$root"/}
    # The text without comments, keeping line numbers: "NNN:text".
    sed 's/[[:space:]]#.*$//' "$file" | grep -n '' | grep -v '^[0-9]*:[[:space:]]*#' > "$tmp/body"

    # W1
    grep -E '^[0-9]+:[[:space:]-]*uses:' "$tmp/body" | while IFS= read -r entry; do
        line=${entry%%:*}
        value=$(printf '%s\n' "${entry#*:}" | sed -e 's/^[[:space:]-]*uses:[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^[\"']//" -e "s/[\"']\$//")
        case "$value" in ./*) continue ;; esac
        if ! printf '%s\n' "$value" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$'; then
            fail W1 "$name" "$line" "uses: $value is not pinned to a 40-hex commit"
        fi
    done

    # W2
    if ! grep -Eq '^[0-9]+:permissions:' "$tmp/body"; then
        fail W2 "$name" 1 "no top-level permissions:"
    fi

    # W3
    if grep -E 'secrets\.[A-Za-z_]' "$tmp/body" | grep -Evq 'secrets\.GITHUB_TOKEN'; then
        triggers=$(grep -Ev '^[0-9]+:[[:space:]-]*if:' "$tmp/body" \
            | grep -E '(^|[^A-Za-z_])(pull_request_target|pull_request|workflow_dispatch|issue_comment|workflow_run)([^A-Za-z_]|$)' | head -n 1)
        if [ -n "$triggers" ]; then
            fail W3 "$name" "${triggers%%:*}" "reads secrets and can be triggered by ${triggers#*:}"
        fi
    fi

    # W4
    grep -Ev '^[0-9]+:[[:space:]-]*if:' "$tmp/body" \
        | grep -E '\$\{\{[[:space:]]*github\.(event\.|head_ref)' | while IFS= read -r entry; do
        fail W4 "$name" "${entry%%:*}" "untrusted value interpolated: pass it through env: instead"
    done

    # W5
    if command -v ruby >/dev/null 2>&1; then
        if ! ruby -ryaml -e 'YAML.load_file(ARGV[0])' "$file" >/dev/null 2>&1; then
            fail W5 "$name" 1 "does not parse as YAML"
        fi
    fi
done

if [ -s "$tmp/failed" ]; then
    exit 1
fi
echo "workflow lint: ok"
