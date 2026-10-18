# Security policy

wardenrun is a security tool, so reports are welcome and taken seriously.

## Status and supported versions

wardenrun is **pre-release**: there is no released version yet, so there is nothing to
patch and no version is "supported" in the usual sense. Design-level reports are just as
useful as bug reports right now. The approved design and its known gaps are in
[`docs/DESIGN.md`](docs/DESIGN.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md);
please read the "Not protected" rows before reporting something that is already listed there.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's private reporting:

<https://github.com/mateuszgachowski/wardenrun/security/advisories/new>

Include what you did, what you expected and what happened. Reports are acknowledged on a
best-effort basis: this is a free project maintained by one person.

## The signing certificate

Releases are signed with a self-signed code-signing certificate, so that the keychain item
wardenrun creates keeps working across upgrades. The certificate hash will be published here
and in the README **together with the first release**. A different hash means the binary was
not signed by this project.

If the signing key is ever leaked, or a malicious release is published, the rotation is:

1. A security advisory is published and the old certificate hash is marked revoked here.
2. A new certificate is generated and a new release is signed with it.
3. Everyone re-runs `wardenrun setup` (the old keychain item cannot be read by the new
   binary, by design).

## What is in scope

Anything that lets a process running as the same user obtain a secret **without** the
approval described in the threat model, or that puts a secret where the design says it must
never be (command line, logs, the agent's output). Gaps already listed under "Not protected"
in the threat model are known; a way to make them worse, or to close them, is still welcome.
