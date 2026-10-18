## What and why

<!-- One or two sentences. -->

## Checklist

- [ ] Tests pass (`sh scripts/test-check-docs.sh`, `sh scripts/check-docs.sh`, plus the code tests once they exist).
- [ ] If this PR changes a data path (what is passed to `bw`, where a secret is written, what is logged, what the child process receives), the data-flow section and the tables in `README.md` are updated in this PR. Otherwise: N/A.
- [ ] If this PR changes a protection or an assumption, `docs/THREAT_MODEL.md` is updated. Otherwise: N/A.
- [ ] No private names, hostnames or addresses anywhere in the diff (examples use `vault.example.com`, `example-api`, `staging-db-admin`).
