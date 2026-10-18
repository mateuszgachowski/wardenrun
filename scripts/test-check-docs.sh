#!/bin/sh
# Tests for scripts/check-docs.sh: a clean fixture must pass, and each rule
# R1..R7 must fail on its own mutation of that fixture.
here=$(cd "$(dirname "$0")" && pwd)
check="$here/check-docs.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/check-docs-test.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT HUP INT TERM
failures=0

make_fixture() {
    mkdir -p "$1/docs"
    cat > "$1/README.md" <<'EOF'
# wardenrun

Fixture README.

## Status

This project is pre-release.

> Not available yet.
>
> ```sh
> brew install example/tap/wardenrun
> ```

## What it does

Runs a command with a secret. See [the threat model](docs/THREAT_MODEL.md).

## How the data flows

```text
agent -> wardenrun -> bw
```

The command line (argv) goes to wardenrun. The secret reaches the child through its
environment or through stdin. Another process of the same user can run `ps eww`.
Versions such as 2026.9.0 and addresses such as 1.10.20.30 are not private.

## What wardenrun can reach, and what it cannot

Fixture.

## Where your data lives

The keychain item and the audit log.

## How secure is it, honestly

Fixture.

## Compared to what exists

Fixture.

## Verify, don't trust

Fixture.

## Use with Claude Code and other AI agents

Fixture.

## Requirements

Fixture.

## Not affiliated with Bitwarden

Fixture.
EOF
    printf '# Threat model\n\nFixture.\n' > "$1/docs/THREAT_MODEL.md"
}

# expect_pass NAME DIR
expect_pass() {
    out=$(sh "$check" "$2" 2>&1); rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "ok: $1"
    else
        echo "NOT OK: $1 (exit $rc)"; echo "$out"; failures=$((failures + 1))
    fi
}

# expect_fail NAME RULE DIR
expect_fail() {
    out=$(sh "$check" "$3" 2>&1); rc=$?
    case "$out" in
        *"FAIL: $2:"*) [ "$rc" -eq 1 ] && { echo "ok: $1"; return; } ;;
    esac
    echo "NOT OK: $1 (exit $rc, wanted exit 1 with FAIL: $2)"; echo "$out"
    failures=$((failures + 1))
}

# mutated DIR -> prints a fresh copy of the fixture in DIR
fresh() { rm -rf "$1"; make_fixture "$1"; }

fresh "$work/clean"
expect_pass "clean fixture passes" "$work/clean"

fresh "$work/r1"
grep -v -x '## Status' "$work/r1/README.md" > "$work/r1/tmp" && mv "$work/r1/tmp" "$work/r1/README.md"
expect_fail "R1 missing heading" R1 "$work/r1"

fresh "$work/r1b"; rm "$work/r1b/README.md"
expect_fail "R1 missing README" R1 "$work/r1b"

fresh "$work/r2"; printf '\n```\n' >> "$work/r2/docs/THREAT_MODEL.md"
expect_fail "R2 unbalanced fence" R2 "$work/r2"

fresh "$work/r3"; printf '\nSee [x](docs/missing.md).\n' >> "$work/r3/README.md"
expect_fail "R3 broken relative link" R3 "$work/r3"

fresh "$work/r3b"; printf '\nSee [x](https://example.com/a) and [y](#how-the-data-flows).\n' >> "$work/r3b/README.md"
expect_pass "R3 ignores URLs and anchors" "$work/r3b"

fresh "$work/r4"; printf '\nA Touch ID protected keychain.\n' >> "$work/r4/docs/THREAT_MODEL.md"
expect_fail "R4 overclaim phrase" R4 "$work/r4"

fresh "$work/r4b"; printf '\nNever write "Touch ID protected" here.\n' > "$work/r4b/docs/DESIGN.md"
expect_pass "R4 exempts docs/DESIGN.md" "$work/r4b"

fresh "$work/r5"; printf '\nbrew install example/tap/wardenrun\n' >> "$work/r5/README.md"
expect_fail "R5 brew install outside the quote" R5 "$work/r5"

fresh "$work/r5b"
grep -v -i 'pre-release' "$work/r5b/README.md" > "$work/r5b/tmp" && mv "$work/r5b/tmp" "$work/r5b/README.md"
expect_fail "R5 status without pre-release" R5 "$work/r5b"

fresh "$work/r6"; printf '\nServer at 10.0.0.5.\n' >> "$work/r6/README.md"
expect_fail "R6 private IPv4" R6 "$work/r6"

fresh "$work/r6b"; printf '\nServer at nas.local.\n' >> "$work/r6b/README.md"
expect_fail "R6 .local hostname" R6 "$work/r6b"

fresh "$work/r7"; sed 's/argv/args/' "$work/r7/README.md" > "$work/r7/tmp" && mv "$work/r7/tmp" "$work/r7/README.md"
expect_fail "R7 missing term" R7 "$work/r7"

fresh "$work/r7b"; sed 's/`ps eww`/`steps eww`/' "$work/r7b/README.md" > "$work/r7b/tmp" && mv "$work/r7b/tmp" "$work/r7b/README.md"
expect_fail "R7 'ps' is a whole word, not a substring of 'steps'" R7 "$work/r7b"

fresh "$work/r3c"; printf '\nSee [x](#no-such-heading).\n' >> "$work/r3c/README.md"
expect_fail "R3 broken same-page anchor" R3 "$work/r3c"

fresh "$work/r3d"; printf '\nSee [x](#verify-dont-trust) and [y](docs/THREAT_MODEL.md#threat-model).\n' >> "$work/r3d/README.md"
expect_pass "R3 accepts GitHub heading slugs (punctuation dropped)" "$work/r3d"

fresh "$work/r3e"; printf '\nSee [y](docs/THREAT_MODEL.md#nope).\n' >> "$work/r3e/README.md"
expect_fail "R3 broken anchor in another file" R3 "$work/r3e"

fresh "$work/r4c"; printf '\nUse secrets without ever seeing them.\n' >> "$work/r4c/README.md"
expect_fail "R4 'without ever seeing'" R4 "$work/r4c"

fresh "$work/r6c"; printf '\nTailnet host 100.100.1.1.\n' >> "$work/r6c/README.md"
expect_fail "R6 CGNAT/Tailscale range" R6 "$work/r6c"

fresh "$work/r6d"; printf '\nPublic host 100.128.1.1.\n' >> "$work/r6d/README.md"
expect_pass "R6 100.128.x.x is public, not flagged" "$work/r6d"

fresh "$work/r6e"; printf '\nCopy it to /%s/someone/project.\n' Users >> "$work/r6e/README.md"
expect_fail "R6 absolute home path" R6 "$work/r6e"

# Inside a git repository only tracked and not-ignored files are linted.
if command -v git >/dev/null 2>&1; then
    fresh "$work/g1"
    printf 'Server at 10.0.0.5.\n' > "$work/g1/docs/private.md"
    printf 'docs/private.md\n' > "$work/g1/ignore-list"
    ( cd "$work/g1" && git init -q && mkdir -p .git/info && cp ignore-list .git/info/exclude && rm ignore-list && git add -A )
    expect_pass "git: ignored files are not linted" "$work/g1"

    fresh "$work/g2"
    ( cd "$work/g2" && git init -q && git add -A ) && printf 'Server at 10.0.0.5.\n' > "$work/g2/docs/new.md"
    expect_fail "git: untracked but not ignored files are linted" R6 "$work/g2"
fi

[ "$failures" -eq 0 ] && { echo "all rule tests passed"; exit 0; }
echo "$failures test(s) failed"; exit 1
