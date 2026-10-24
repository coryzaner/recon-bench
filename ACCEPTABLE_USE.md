# Acceptable Use / Code of Conduct

**Required.** Before any active-tier tool may run, the operator must explicitly
accept this short code of conduct. Acceptance is recorded with a timestamp
(and a hash of this statement) by the companion bench:

```
recon-guard --accept-use
```

## Statement you accept

> **I will only test systems I own or have written permission to test.**

## Rules

1. **Authorization first.** Active testing happens only under a written
   authorization and a matching `scope.yaml` for a single engagement. No
   signed authorization → no active tools.
2. **One scope at a time.** Load one engagement's `scope.yaml`. There is no
   mass-scan or internet-wide target mode. Every target on the command line
   must fall inside the loaded scope.
3. **Passive-first.** Prefer OSINT / passive recon. Escalate to active tools
   only when the engagement calls for it and the gate is loaded.
4. **No destructive or DoS-like activity** unless a per-engagement exception
   is explicitly authorized in writing.
5. **Attribution, not anonymity.** Every successful active run is written to a
   local audit log (operator, tool, target, timestamp). Do not attempt to
   disable or evade that log.
6. **You are responsible for legal compliance.** This tooling is for
   authorized testing and education only. Misuse is your responsibility.

## Recording acceptance

On the bench:

```bash
recon-guard --accept-use
# writes /etc/testbench/acceptable_use_accepted  (0600)
# containing accepted_at=<ISO UTC>, statement=<text>, statement_sha256=<hash>
```

Active tools refuse until that file exists. Re-accepting overwrites the prior
record with a fresh timestamp.
