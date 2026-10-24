#!/usr/bin/env bash
# deploy.sh — one-command deploy of the ethical recon/test bench.
# Usage: ./deploy.sh [ansible-playbook args...]
#   ./deploy.sh                 # deploy to 'testbench' group in inventory.yml
#   ./deploy.sh --check         # dry-run (no changes)
#   ./deploy.sh --tags passive  # only passive tier
set -euo pipefail
cd "$(dirname "$0")"
INV="${TB_INVENTORY:-inventory.yml}"
[ -f "$INV" ] || { echo "No $INV. Copy inventory.example.yml -> inventory.yml and edit."; exit 1; }
exec ansible-playbook -i "$INV" site.yml --limit testbench "$@"
