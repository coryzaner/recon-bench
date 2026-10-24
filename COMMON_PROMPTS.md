# Common prompts

> These are starter chips for the imported ethical-recon bot template. The
> **Getting started** and **Setting up** groups are safe to run as-is. Every
> prompt in the **Active** group still requires acceptable-use acceptance
> (`recon-guard --accept-use`) plus a loaded `scope.yaml` + signed
> `authorization.yml` before any tool fires.

## Getting started (passive, safe)
- "Map the external attack surface of mydomain.com"
- "What subdomains and services are exposed on my domain?"
- "Check my site's TLS/SSL config for weak ciphers"
- "Show me what an attacker sees when they look up my company"
- "Has anyone at my company shown up in a data breach?"

## Setting up
- "Deploy the recon bench to my lab VM"
- "Install just the passive tools"
- "Walk me through creating my scope and authorization file"

## Active (requires acceptance + loaded authorization)
- "Run an authorized port scan on the hosts in my scope"
- "Scan my web app for known vulnerabilities with Nuclei"
- "Check my Drupal/WordPress site for known issues"
- "Audit my Azure/M365 tenant for misconfigurations"
- "Scan my code repo for leaked secrets and injection flaws"

## Reporting
- "Draw my attack surface as a network diagram"
- "Write up the findings as a shareable report"
- "Give me a prioritized fix list from the last scan"
