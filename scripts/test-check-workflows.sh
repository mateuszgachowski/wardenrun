#!/bin/sh
# Tests for scripts/check-workflows.sh. Usage: sh scripts/test-check-workflows.sh
# Each case writes a workflow into a temporary root and runs the lint on it.
here=$(cd "$(dirname "$0")" && pwd)
lint="$here/check-workflows.sh"
repo=$(cd "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/test-check-workflows.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: > "$tmp/failed"

pass() { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s: %s\n' "$1" "$2"; printf x >> "$tmp/failed"; }

# workflow NAME  (workflow text on stdin) -> $tmp/NAME as a lint root
workflow() {
    mkdir -p "$tmp/$1/.github/workflows"
    cat > "$tmp/$1/.github/workflows/w.yml"
}

# lint NAME -> sets $out and $status
lint() {
    status=0
    out=$(sh "$lint" "$tmp/$1" 2>&1) || status=$?
}

expect_ok() {
    lint "$1"
    if [ "$status" -eq 0 ] && printf '%s\n' "$out" | grep -q '^workflow lint: ok$'; then pass "$1"; else bad "$1" "expected ok, got $status: $out"; fi
}

expect_fail() { # name rule
    lint "$1"
    if [ "$status" -eq 1 ] && printf '%s\n' "$out" | grep -q "^FAIL: $2: "; then pass "$1"; else bad "$1" "expected $2 and exit 1, got $status: $out"; fi
}

sha=11bd71901bbe5b1630ceea73d27597364c9af683

workflow aPinnedWorkflowWithPermissionsPasses <<EOF
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$sha # v4.2.2
      - uses: ./.github/actions/local
      - run: echo hi
EOF
expect_ok aPinnedWorkflowWithPermissionsPasses

workflow aTagInsteadOfShaFails <<EOF
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
EOF
expect_fail aTagInsteadOfShaFails W1

workflow aShortShaFails <<EOF
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd719
EOF
expect_fail aShortShaFails W1

workflow aUsesWithoutAnyRefFails <<EOF
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout
EOF
expect_fail aUsesWithoutAnyRefFails W1

workflow aMissingPermissionsFails <<EOF
name: x
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$sha # v4.2.2
EOF
expect_fail aMissingPermissionsFails W2

workflow permissionsOnlyInsideAJobStillFailsW2 <<EOF
name: x
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi
EOF
expect_fail permissionsOnlyInsideAJobStillFailsW2 W2

workflow secretsWithPullRequestFail <<EOF
name: x
on:
  pull_request:
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          KEY: \${{ secrets.SIGNING_CERT_PASSWORD }}
EOF
expect_fail secretsWithPullRequestFail W3

workflow secretsWithPullRequestTargetFail <<EOF
name: x
on: pull_request_target
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          KEY: \${{ secrets.TAP_TOKEN }}
EOF
expect_fail secretsWithPullRequestTargetFail W3

workflow secretsWithWorkflowDispatchFail <<EOF
name: x
on:
  workflow_dispatch:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          KEY: \${{ secrets.TAP_TOKEN }}
EOF
expect_fail secretsWithWorkflowDispatchFail W3

workflow githubTokenWithPullRequestPasses <<EOF
name: x
on:
  pull_request:
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
EOF
expect_ok githubTokenWithPullRequestPasses

workflow aCommentMentioningPullRequestDoesNotCount <<EOF
name: x
# never on pull_request: this one holds secrets
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          KEY: \${{ secrets.TAP_TOKEN }}
EOF
expect_ok aCommentMentioningPullRequestDoesNotCount

workflow eventInterpolationInRunFails <<EOF
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.head_commit.message }}"
EOF
expect_fail eventInterpolationInRunFails W4

workflow headRefInterpolationFails <<EOF
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: git checkout "\${{ github.head_ref }}"
EOF
expect_fail headRefInterpolationFails W4

workflow eventNameInAnIfIsFine <<EOF
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - if: \${{ github.event_name == 'push' }}
        run: echo hi
EOF
expect_ok eventNameInAnIfIsFine

if command -v ruby >/dev/null 2>&1; then
    workflow brokenYamlFailsWhenRubyExists <<EOF
name: x
on: [push
permissions:
  contents: read
EOF
    expect_fail brokenYamlFailsWhenRubyExists W5
fi

# --- Ways around the first, line-based lint (found by review) ---
workflow toJsonSecretsFail <<'EOF'
name: x
on: [push, workflow_call, pull_request_target]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    env: {ALL: "${{ toJSON(secrets) }}"}
    steps:
      - run: echo hi
EOF
expect_fail toJsonSecretsFail W3

workflow bracketSecretsWithWorkflowRunFail <<'EOF'
name: x
on: workflow_run
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: ${{ secrets['TAP_TOKEN'] }}
EOF
expect_fail bracketSecretsWithWorkflowRunFail W3

mkdir -p "$tmp/inheritPullRequestTargetFail/.github/workflows"
workflow inheritPullRequestTargetFail <<'EOF'
name: x
on: pull_request_target
permissions:
  contents: read
jobs:
  call:
    uses: ./.github/workflows/other.yml
    secrets: inherit
EOF
expect_fail inheritPullRequestTargetFail W3

workflow pullRequestReviewWithSecretFails <<'EOF'
name: x
on: pull_request_review
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: ${{ secrets.TAP_TOKEN }}
EOF
expect_fail pullRequestReviewWithSecretFails W3

workflow branchPushWithSecretFails <<'EOF'
name: x
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: ${{ secrets.TAP_TOKEN }}
EOF
expect_fail branchPushWithSecretFails W3

workflow tagAndBranchPushWithSecretFails <<'EOF'
name: x
on:
  push:
    branches: [main]
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: ${{ secrets.TAP_TOKEN }}
EOF
expect_fail tagAndBranchPushWithSecretFails W3

workflow aCommentCharacterInAStringDoesNotHideATrigger <<'EOF'
name: x
on: {push: {tags: ["v #1"]}, pull_request_target: {}}
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: ${{ secrets.TAP_TOKEN }}
EOF
expect_fail aCommentCharacterInAStringDoesNotHideATrigger W3

workflow writeAllPermissionsFail <<'EOF'
name: x
on: [push]
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
expect_fail writeAllPermissionsFail W2

workflow aTopLevelWriteGrantFails <<'EOF'
name: x
on: [push]
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
expect_fail aTopLevelWriteGrantFails W2

workflow aJobWithWriteAllFails <<'EOF'
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
EOF
expect_fail aJobWithWriteAllFails W2

workflow flowStyleUsesFails <<'EOF'
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - {uses: actions/checkout@v4}
EOF
expect_fail flowStyleUsesFails W1

workflow quotedKeyUsesFails <<'EOF'
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - "uses": actions/setup-node@v4
EOF
expect_fail quotedKeyUsesFails W1

workflow dockerUsesFails <<'EOF'
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.19
EOF
expect_fail dockerUsesFails W1

workflow secretInsideARunScriptFails <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.TAP_TOKEN }}"
EOF
expect_fail secretInsideARunScriptFails W6

workflow secretInAJobLevelEnvFails <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      K: ${{ secrets.TAP_TOKEN }}
    steps:
      - run: echo hi
EOF
expect_fail secretInAJobLevelEnvFails W6

workflow secretsInheritInATagWorkflowFails <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  call:
    uses: ./.github/workflows/other.yml
    secrets: inherit
EOF
expect_fail secretsInheritInATagWorkflowFails W6

workflow secretMixedWithTextInAnEnvValueFails <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: "prefix-${{ secrets.TAP_TOKEN }}"
EOF
expect_fail secretMixedWithTextInAnEnvValueFails W6

workflow aHashInsideAStringDoesNotHideAnInterpolation <<'EOF'
name: x
on: [push]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo " #"; echo "${{ github.event.pull_request.title }}"
EOF
expect_fail aHashInsideAStringDoesNotHideAnInterpolation W4

workflow aSecretInAStepEnvOfATagWorkflowPasses <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          K: ${{ secrets.TAP_TOKEN }}
EOF
expect_ok aSecretInAStepEnvOfATagWorkflowPasses

workflow aSecretInTheWithOfAStepPasses <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          token: ${{ secrets.TAP_TOKEN }}
EOF
expect_ok aSecretInTheWithOfAStepPasses

workflow theWordSecretsInProseDoesNotCount <<'EOF'
name: no secrets are read here
on: [pull_request]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "this job has no secrets"
EOF
expect_ok theWordSecretsInProseDoesNotCount

workflow theGithubTokenInARunScriptIsNotASecretOfOurs <<'EOF'
name: x
on: [pull_request]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr list
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
EOF
expect_ok theGithubTokenInARunScriptIsNotASecretOfOurs

workflow aWorkflowWithoutSecretsMayUseAnyTrigger <<'EOF'
name: x
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
expect_ok aWorkflowWithoutSecretsMayUseAnyTrigger

workflow aJobMayRaiseItsOwnPermissions <<'EOF'
name: x
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - run: echo hi
EOF
expect_ok aJobMayRaiseItsOwnPermissions

workflow anEventConditionInAnIfIsFine <<'EOF'
name: x
on: [pull_request]
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ github.event.pull_request.draft == false }}
        run: echo hi
EOF
expect_ok anEventConditionInAnIfIsFine

workflow readAllIsAnAcceptableDefault <<'EOF'
name: x
on: [push]
permissions: read-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
expect_ok readAllIsAnAcceptableDefault

workflow anUnknownPermissionsStringFails <<'EOF'
name: x
on: [push]
permissions: contents
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
expect_fail anUnknownPermissionsStringFails W2

# The repository's own workflows must pass.
status=0
out=$(sh "$lint" "$repo" 2>&1) || status=$?
if [ "$status" -eq 0 ]; then pass theRealWorkflowsPass; else bad theRealWorkflowsPass "$out"; fi

# A root without workflows is an error, not a pass.
mkdir -p "$tmp/empty"
lint empty
if [ "$status" -ne 0 ]; then pass aRootWithoutWorkflowsIsAnError; else bad aRootWithoutWorkflowsIsAnError "exit $status: $out"; fi

[ ! -s "$tmp/failed" ]
