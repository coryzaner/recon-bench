#!/usr/bin/env bash
# crtsh.sh — passive certificate-transparency subdomain helper (crt.sh).
# Usage: crtsh.sh <domain>    Passive OSINT only; queries public CT logs.
set -euo pipefail
dom="${1:?usage: crtsh.sh <domain>}"
url="https://crt.sh/?q=%25.${dom}&output=json"
if command -v jq >/dev/null 2>&1; then
  curl -fsSL "$url" | jq -r '.[].name_value' | tr '\n' '\n' | sed 's/\*\.//g' | sort -u
else
  curl -fsSL "$url" | grep -oE '"name_value":"[^"]+"' | cut -d'"' -f4 | \
    sed 's/\\n/\n/g; s/\*\.//g' | sort -u
fi
