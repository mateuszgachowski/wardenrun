#!/bin/sh
# Docs lint: keeps the public documents honest (see docs/DESIGN.md section 12).
# Usage: sh scripts/check-docs.sh [ROOT]     (default ROOT is the current directory)
# Prints one "FAIL: R<n>: <file>: <detail>" line per violation and exits 1; exits 0 when clean.
# Inside a git work tree only tracked or not-ignored files are checked, as in CI.
# POSIX sh + grep/awk/sed only, so it runs the same on macOS (BSD grep) and Ubuntu (GNU grep).
#
#   R1 README.md has the required headings, in this exact spelling
#   R2 every Markdown file has balanced ``` code fences
#   R3 every relative Markdown link points at a file that exists, and every #anchor at a heading
#   R4 no overclaim phrases (docs/DESIGN.md is exempt: it quotes them as things never to write)
#   R5 README says "pre-release" under Status; "brew install" appears only inside a
#      "> Not available yet" quote (docs/DESIGN.md is exempt: it describes the planned flow)
#   R6 no private or CGNAT IPv4 addresses, no .local / .lan hostnames, no absolute home paths
#   R7 README mentions every data channel: argv, environment, stdin, keychain, audit log, ps
root=${1:-.}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-docs.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() { # rule file detail; also marks the run failed (loops below may run in subshells)
    printf 'FAIL: %s: %s: %s\n' "$1" "$2" "$3"
    : > "$tmp/failed"
}
rel() { printf '%s' "${1#"$root"/}"; }

# Inside a git work tree, lint what git would publish (tracked or untracked-but-not-ignored),
# so a local scratch file cannot make the result differ from CI. Elsewhere, walk the tree.
if [ -e "$root/.git" ]; then
    git -C "$root" ls-files --cached --others --exclude-standard -- '*.md' '*.yml' \
        | awk -v r="$root" '{ print r "/" $0 }' | sort > "$tmp/listed"
    while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done < "$tmp/listed" > "$tmp/all"
else
    find "$root" -type f \( -name '*.md' -o -name '*.yml' \) ! -path '*/.git/*' ! -path '*/.build/*' \
        | sort > "$tmp/all"
fi
grep '\.md$' "$tmp/all" > "$tmp/md"
grep -v '/docs/DESIGN\.md$' "$tmp/all" > "$tmp/all_but_design"
grep '\.md$' "$tmp/all_but_design" > "$tmp/md_but_design"

readme="$root/README.md"

# R1: required headings
if [ ! -f "$readme" ]; then
    fail R1 README.md "file is missing"
else
    while IFS= read -r heading; do
        grep -q -x -F -- "$heading" "$readme" || fail R1 README.md "missing heading: $heading"
    done <<'EOF'
# wardenrun
## Status
## What it does
## How the data flows
## What wardenrun can reach, and what it cannot
## Where your data lives
## How secure is it, honestly
## Compared to what exists
## Verify, don't trust
## Use with Claude Code and other AI agents
## Requirements
## Not affiliated with Bitwarden
EOF
fi

# R2: balanced code fences
while IFS= read -r f; do
    n=$(grep -c '^```' "$f")
    [ $((n % 2)) -eq 0 ] || fail R2 "$(rel "$f")" "unbalanced code fences ($n fence lines)"
done < "$tmp/md"

# R3: relative links resolve (relative to the linking file; a leading / means ROOT), and so do #anchors
slugs_of() { # GitHub heading anchors of a Markdown file, one per line
    grep -E '^#{1,6} ' "$1" | sed -E 's/^#{1,6} +//; s/ +#* *$//' | tr 'A-Z' 'a-z' \
        | sed -E 's/[^a-z0-9 _-]//g; s/ /-/g'
}
while IFS= read -r f; do
    grep -o '\]([^)]*)' "$f" | sed 's/^\](//; s/)$//' | while IFS= read -r target; do
        target=${target%% *}                 # drop an optional "title"
        target=${target#<}; target=${target%>}
        case "$target" in
            ''|*:*) continue ;;              # empty, or has a scheme (http:, mailto:)
        esac
        anchor=
        case "$target" in *'#'*) anchor=$(printf '%s' "${target#*#}" | tr 'A-Z' 'a-z') ;; esac
        target=${target%%#*}; target=${target%%\?*}
        if [ -z "$target" ]; then
            path=$f                          # same-page anchor
        else
            case "$target" in
                /*) path="$root$target" ;;
                *)  path="$(dirname "$f")/$target" ;;
            esac
            [ -e "$path" ] || { fail R3 "$(rel "$f")" "broken link: $target"; continue; }
        fi
        case "$path" in
            *.md) [ -z "$anchor" ] || [ -f "$path" ] || continue
                  [ -z "$anchor" ] || slugs_of "$path" | grep -q -x -F -- "$anchor" \
                      || fail R3 "$(rel "$f")" "broken anchor: #$anchor in $(rel "$path")" ;;
        esac
    done
done < "$tmp/md"

# R4: overclaim phrases
while IFS= read -r f; do
    for phrase in 'touch id protected' 'unhackable' 'military-grade' '100% secure' 'unbreakable' 'without ever seeing'; do
        grep -i -q -F -- "$phrase" "$f" && fail R4 "$(rel "$f")" "overclaim phrase: $phrase"
    done
done < "$tmp/md_but_design"

# R5: honest status, install command only inside a "Not available yet" quote
if [ -f "$readme" ]; then
    awk '/^## /{s=($0=="## Status")} s' "$readme" | grep -i -q 'pre-release' \
        || fail R5 README.md 'the "## Status" section must say "pre-release"'
    awk '
        /^> Not available yet/ { q = 1 }
        !/^>/                  { q = 0 }
        /brew install/ && !q   { print NR }
    ' "$readme" | while IFS= read -r line; do
        fail R5 README.md "line $line: brew install outside a \"> Not available yet\" quote"
    done
fi

# R6: private addresses, hostnames and paths
ipv4='(^|[^0-9.])(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+)'
host='[A-Za-z0-9-]+\.(local|lan)([^A-Za-z0-9_-]|$)'
homepath='(^|[^A-Za-z0-9_.])/(Users|home)/[A-Za-z]'
while IFS= read -r f; do
    grep -q -E -- "$ipv4" "$f" && fail R6 "$(rel "$f")" "private or CGNAT IPv4 address"
    grep -q -E -- "$host" "$f" && fail R6 "$(rel "$f")" "private .local/.lan hostname"
    grep -q -E -- "$homepath" "$f" && fail R6 "$(rel "$f")" "absolute home-directory path"
done < "$tmp/all"

# R7: every data channel is mentioned in the README
if [ -f "$readme" ]; then
    for term in argv environment stdin keychain 'audit log' ps; do
        grep -i -q -E -- "(^|[^A-Za-z0-9_])$term([^A-Za-z0-9_]|\$)" "$readme" \
            || fail R7 README.md "never mentions: $term"
    done
fi

[ -e "$tmp/failed" ] && exit 1
echo "docs lint: ok"
exit 0
