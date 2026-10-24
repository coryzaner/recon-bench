# Ethical Recon / Test Bench

> **Legal disclaimer.** This software is provided for lawful, authorized
> security testing only. You may use it only against systems you own or have
> **written permission** to test. Unauthorized scanning or testing may violate
> computer-misuse laws (e.g. the US CFAA, UK Computer Misuse Act) and
> contracts. The authors accept no liability for misuse; the safety gate is a
> guardrail, not a legal authorization. See `ACCEPTABLE_USE.md` and `LICENSE`.

A shareable, **one-command** security test bench for a lab you own.
Two tiers of tooling with a hard **scope + signed-authorization safety gate** in
front of everything active. **Lab-only** — nothing here is meant to touch
public or third-party systems.

> ⚠️ Active scanning without authorization is illegal and unethical. The gate
> below is a guardrail, not a license. Only test assets you own or are
> explicitly authorized to test.

## Quickstart

```bash
git clone <BENCH_REPO_URL> recon-bench && cd recon-bench
ansible-galaxy collection install -r requirements.yml
make test                                 # gate unit tests, no VM needed
cp inventory.example.yml inventory.yml    # set your private lab VM IP/user/key
make check && make deploy                 # dry-run, then deploy
# on the VM: accept the AUP, write scope.yaml, sign authorization.yml
recon-guard --accept-use && recon-guard --check
```

Passive tools run freely; anything active must go through `recon-guard`.

## What's installed

### PASSIVE tier (safe, runs freely — no authorization required)
Informational / recon only; no intrusive traffic.

| Tool | Purpose |
|------|---------|
| **amass** | subdomain enumeration / attack-surface mapping |
| **dnsx** | fast DNS resolver/toolkit |
| **httpx** | HTTP probing / fingerprinting |
| **dnsrecon** | DNS reconnaissance |
| **crtsh** (helper) | certificate-transparency subdomain discovery (crt.sh) |
| **testssl.sh** | TLS/SSL configuration tester |
| **sslscan** | TLS cipher/protocol scanner |
| **whois / dig** | OSINT helpers |

### ACTIVE tier (GATED — refuses to run without scope + signed auth)
Intrusive scanning, exploitation-adjacent, cloud/AD assessment, and code/secret
scanning. Every active CLI is meant to be invoked **through `recon-guard`**.

| Tool | Purpose |
|------|---------|
| **nmap**, **masscan** | port/host scanning |
| **nuclei**, **nikto** | vuln/template & web-server scanning |
| **OpenVAS/Greenbone** | full vulnerability scanner (Docker; heavy feeds) |
| **OWASP ZAP** | web app DAST (Docker, daemon on loopback) |
| **droopescan**, **wpscan** | CMS (Drupal/WordPress) scanners |
| **ScoutSuite**, **Prowler** | cloud security posture (AWS/Azure/GCP) |
| **ROADrecon**, **AADInternals**, **MicroBurst** | Entra/Azure AD assessment |
| **trufflehog**, **gitleaks** | secret scanning |
| **semgrep**, **PHPStan**, **Psalm**, **composer audit** | SAST / dependency audit |

> Install toggles live in `roles/testbench/defaults/main.yml`
> (`testbench_install_openvas` is **off** by default — see feed caveats below).
> Some active tools (WPScan/Droopescan/AADInternals/MicroBurst/PHPStan/Psalm)
> ship via their native package managers (gem/pwsh/composer); the role installs
> the core set and the compose stack covers the heavy containerized ones.

## The safety gate

The gate is two pieces, installed by the `guard` tasks:

- **`scope_check.py`** — validator (authorization + scope-membership logic).
- **`recon-guard`** — the wrapper every active tool is invoked through.

`recon-guard <tool> [args...]` will **refuse with a non-zero exit** unless **all**
of the following hold:

1. **`scope.yaml` exists and is well-formed** and defines at least one in-scope
   domain, CIDR, or host (`/etc/testbench/scope.yaml`).
2. **An authorization file exists** (`/etc/testbench/authorization.yml`), and:
   - carries a **valid GPG detached signature** (`authorization.yml.sig`) from a
     key in the trusted keyring (`/etc/testbench/operators.gpg`),
   - is **not expired** (and past any `not_before`),
   - **names an operator**,
   - is **not the example template** (`example: true` is rejected),
   - its **`scope_sha256` matches the live `scope.yaml`** (so changing scope
     after signing invalidates the authorization).
3. **Every target on the command line is inside scope** — IPs/CIDRs must fall
   within an in-scope network (CIDRs must be fully contained), hostnames must
   match an in-scope domain suffix or explicit host.
4. **Acceptable-use has been accepted** — the operator must have recorded a
   first-run acceptance (`recon-guard --accept-use`) writing
   `/etc/testbench/acceptable_use_accepted` with a timestamp + statement hash.
   One engagement / one loaded `scope.yaml` at a time; there is no
   mass/internet-wide target mode.

On a successful gate pass, `recon-guard` appends one attribution line to
`/etc/testbench/audit.log` (mode 0600): ISO timestamp, operator, tool, and
target(s). No secrets are printed. Otherwise it prints a clear reason and
exits `2`.

### Setting up a real authorization

```bash
cd /etc/testbench
cp scope.example.yaml scope.yaml && $EDITOR scope.yaml        # your targets
cp authorization.example.yml authorization.yml && $EDITOR authorization.yml
#  -> delete the `example: true` line, set operator/expires,
#     set scope_sha256 to:  sha256sum scope.yaml
gpg --armor --detach-sign -o authorization.yml.sig authorization.yml
gpg --no-default-keyring --keyring operators.gpg --import operator-pub.asc
recon-guard --check     # verifies gate without running anything
recon-guard --accept-use  # first-run: record acceptable-use acceptance
```

Then run active tools through the gate:

```bash
recon-guard nmap -sV 192.0.2.10
recon-guard nuclei -u https://web01.lab.example.com
```

Sample files shipped for reference: `scope.example.yaml`,
`authorization.example.yml` (unsigned, intentionally **non-valid**).
**A real signed authorization is never baked into this repo.**

## One-command run

Deploy the whole bench to a fresh lab VM:

```bash
cp inventory.example.yml inventory.yml   # edit host/IP/jump
make deploy
# equivalently:
./deploy.sh
# or directly:
ansible-playbook -i inventory.yml site.yml --limit testbench
```

Other targets: `make check` (dry-run), `make lint`, `make test` (gate unit
tests, no VM needed), `make syntax`.

### Docker Compose alternative
Heavy active tools (ZAP, Greenbone) also ship as a standalone stack:

```bash
cd compose && cp .env.example .env
docker compose --profile zap up -d          # ZAP only
docker compose --profile all up -d          # ZAP + OpenVAS (heavy)
```

## OpenVAS / Greenbone feed caveats

- The Greenbone Community container **pulls multi-GB vulnerability feeds
  (NVTs, SCAP/CPE, CERT, Notus) on first start**. This needs solid internet
  connectivity and can take **tens of minutes to hours**; the scanner is not
  fully usable until the sync finishes.
- Feeds update regularly — expect periodic re-sync and growing disk use
  (budget several GB of volume storage: `gvmd_data`, `notus_data`, `psql_data`).
- Because of this, OpenVAS is **opt-in** (`testbench_install_openvas: false`)
  and the compose stack does **not** auto-pull/start it during provisioning.
  Start it explicitly and let the first feed sync complete before scanning.
- Feed sync is a background process; check `docker compose logs -f greenbone`
  for sync progress before relying on scan results.

## Real-VM deploy

This repo is validated locally (lint, syntax, `--check`, gate unit tests).
Deploying needs:

- A lab VM you own on a private network (Debian 12 / Ubuntu), reachable by SSH
  (add a ProxyJump/bastion in `inventory.yml` if needed).
- `golang` present on the target for the Go-based tools (amass/dnsx/httpx/nuclei),
  or swap to release-binary installs.

## Layout

```
recon-bench/
├── site.yml                 # playbook (one-command entry)
├── deploy.sh / Makefile     # one-command wrappers
├── inventory.example.yml
├── roles/testbench/         # the Ansible role (passive + active + gate)
│   ├── defaults/main.yml    # toggles & tool lists
│   ├── tasks/               # main, passive, active, guard, docker_active, ...
│   ├── templates/           # env, profile.d, docker-compose
│   └── files/               # recon-guard.sh, scope_check.py, examples, crtsh
├── compose/                 # standalone heavy-tool stack (ZAP/OpenVAS)
├── guard/                   # standalone copies of the gate (for sharing/testing)
└── tests/gate_test.sh       # VM-free safety-gate unit tests
```
