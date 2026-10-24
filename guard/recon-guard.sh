#!/usr/bin/env bash
#
# recon-guard.sh — safety gate for the ethical recon/test bench.
#
# Every ACTIVE-tier tool is invoked through this wrapper. It refuses to run
# until ALL of the following hold:
#   * the operator has accepted the acceptable-use / code-of-conduct,
#   * a well-formed scope.yaml AND a valid, signed, unexpired authorization
#     file exist, and
#   * the requested target(s) fall inside the single loaded scope.
# On a successful gate pass it appends an attribution line to an audit log.
#
# Usage:
#   recon-guard <tool> [args...]          # run an active tool through the gate
#   recon-guard --accept-use              # record acceptable-use acceptance
#   recon-guard --list                    # list known active/passive tools
#   recon-guard --check                   # verify scope+auth only, run nothing
#
# Config (env, with defaults; set in /etc/testbench/testbench.env):
#   TB_ETC=/etc/testbench
#   TB_SCOPE=$TB_ETC/scope.yaml
#   TB_AUTH=$TB_ETC/authorization.yml
#   TB_AUTH_SIG=$TB_AUTH.sig
#   TB_KEYRING=$TB_ETC/operators.gpg      # trusted operator public keys
#   TB_BIN=/opt/testbench/bin             # real tool binaries live here
#   TB_ALLOW_NO_SIG=0                     # 1 only for lab dry-runs (noisy warn)
#   TB_AU_ACCEPT=$TB_ETC/acceptable_use_accepted  # acceptance record
#   TB_AUDIT=$TB_ETC/audit.log            # per-run attribution log (0600)
#
# Exit codes: 0 ok · 2 refused (gate) · 3 misconfig · 127 tool not found.
# No secrets are ever printed.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${TB_ETC:=/etc/testbench}"
: "${TB_SCOPE:=$TB_ETC/scope.yaml}"
: "${TB_AUTH:=$TB_ETC/authorization.yml}"
: "${TB_AUTH_SIG:=${TB_AUTH}.sig}"
: "${TB_KEYRING:=$TB_ETC/operators.gpg}"
: "${TB_BIN:=/opt/testbench/bin}"
: "${TB_ALLOW_NO_SIG:=0}"
: "${TB_AU_ACCEPT:=$TB_ETC/acceptable_use_accepted}"
: "${TB_AUDIT:=$TB_ETC/audit.log}"
SCOPE_CHECK="${TB_SCOPE_CHECK:-$SELF_DIR/scope_check.py}"

# Acceptable-use statement the operator must accept before any active tool runs.
AU_STATEMENT="I will only test systems I own or have written permission to test."

# Tier definitions ------------------------------------------------------------
# ACTIVE tools touch a target and are gated. PASSIVE tools are informational
# and run freely (listed for --list / documentation; not gated here).
ACTIVE_TOOLS=(nmap masscan nuclei nikto gvm-cli openvas zap.sh zaproxy droopescan \
  wpscan scout prowler roadrecon aadinternals microburst trufflehog gitleaks \
  semgrep phpstan psalm composer-audit)
PASSIVE_TOOLS=(amass dnsx httpx dnsrecon crtsh testssl.sh sslscan whois dig)

err() { printf '[recon-guard] %s\n' "$*" >&2; }

is_active() { local t; for t in "${ACTIVE_TOOLS[@]}"; do [[ "$1" == "$t" ]] && return 0; done; return 1; }

# Record acceptable-use acceptance (operator must have confirmed first).
accept_use() {
  local ts hash
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  hash="$(printf '%s' "$AU_STATEMENT" | sha256sum | awk '{print $1}')"
  mkdir -p "$(dirname "$TB_AU_ACCEPT")" 2>/dev/null || true
  ( umask 077; printf 'accepted_at=%s\nstatement=%s\nstatement_sha256=%s\n' \
      "$ts" "$AU_STATEMENT" "$hash" > "$TB_AU_ACCEPT" )
  chmod 0600 "$TB_AU_ACCEPT" 2>/dev/null || true
  err "acceptable-use accepted and recorded at $ts -> $TB_AU_ACCEPT"
}

# Refuse active tools until acceptable-use has been accepted.
require_acceptance() {
  if [[ ! -f "$TB_AU_ACCEPT" ]]; then
    err "acceptable-use NOT accepted; active tools are blocked."
    err "You must accept: \"$AU_STATEMENT\""
    err "Record acceptance with:  recon-guard --accept-use"
    exit 2
  fi
}

# Best-effort operator name from the (already validated) authorization file.
auth_operator() {
  local op
  op="$(sed -nE 's/^operator:[[:space:]]*["'"'"']?([^"'"'"']+)["'"'"']?[[:space:]]*$/\1/p' \
        "$TB_AUTH" 2>/dev/null | head -n1)"
  [[ -n "$op" ]] && printf '%s' "$op" || printf 'unknown'
}

# Append one attribution line for a successful active run.
audit_log() {
  local op="$1" tool="$2"; shift 2
  local ts targets
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  targets="$*"
  mkdir -p "$(dirname "$TB_AUDIT")" 2>/dev/null || true
  if [[ ! -f "$TB_AUDIT" ]]; then ( umask 077; : > "$TB_AUDIT" ); chmod 0600 "$TB_AUDIT" 2>/dev/null || true; fi
  printf '%s operator=%s tool=%s targets=%s\n' "$ts" "$op" "$tool" "${targets:-none}" >> "$TB_AUDIT"
}

# Pull candidate targets out of an arbitrary tool command line.
# Heuristic but conservative: anything that looks like a host/ip/cidr/url and
# is NOT an option flag or a flag's obvious value.
extract_targets() {
  local out=() a
  for a in "$@"; do
    [[ "$a" == -* ]] && continue
    # url
    if [[ "$a" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then out+=("$a"); continue; fi
    # cidr / ip
    if [[ "$a" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then out+=("$a"); continue; fi
    # ip range a.b.c.d-e (masscan/nmap) -> take base
    if [[ "$a" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})-[0-9]+$ ]]; then out+=("${BASH_REMATCH[1]}"); continue; fi
    # hostname with a dot, not a filename-looking arg
    if [[ "$a" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && "$a" == *.* \
          && ! "$a" =~ \.(yaml|yml|txt|json|xml|html|conf|cfg|log|csv|pem|key|crt|sh|py)$ ]]; then
      out+=("$a"); continue
    fi
  done
  printf '%s\n' "${out[@]:-}"
}

validate_gate() {
  if [[ ! -f "$TB_SCOPE" ]]; then err "scope.yaml not found: $TB_SCOPE"; exit 2; fi
  if [[ ! -f "$TB_AUTH" ]]; then err "authorization file not found: $TB_AUTH"; exit 2; fi
  local args=(verify-auth --scope "$TB_SCOPE" --auth "$TB_AUTH" --sig "$TB_AUTH_SIG")
  [[ -f "$TB_KEYRING" ]] && args+=(--keyring "$TB_KEYRING")
  [[ "$TB_ALLOW_NO_SIG" == "1" ]] && args+=(--no-sig)
  python3 "$SCOPE_CHECK" "${args[@]}"
}

validate_targets() {
  local targets; mapfile -t targets < <(extract_targets "$@")
  # filter empties
  local clean=(); local t
  for t in "${targets[@]}"; do [[ -n "$t" ]] && clean+=("$t"); done
  if [[ ${#clean[@]} -eq 0 ]]; then
    err "no target found on command line; refusing (active tools must name an in-scope target)."
    err "if the target is inside a file, pre-validate it with: recon-guard --check and scope_check.py check-target"
    exit 2
  fi
  python3 "$SCOPE_CHECK" check-target --scope "$TB_SCOPE" --target "${clean[@]}"
}

resolve_bin() {
  local tool="$1"
  if [[ -x "$TB_BIN/$tool" ]]; then echo "$TB_BIN/$tool"; return; fi
  local p; p="$(command -v "$tool" 2>/dev/null || true)"
  # never recurse into the guard itself
  if [[ -n "$p" && "$(readlink -f "$p")" != "$(readlink -f "${BASH_SOURCE[0]}")" ]]; then
    echo "$p"; return
  fi
  return 1
}

# Entry -----------------------------------------------------------------------
case "${1:-}" in
  --accept-use)
    accept_use
    exit 0 ;;
  --list)
    echo "ACTIVE (gated):  ${ACTIVE_TOOLS[*]}"
    echo "PASSIVE (free):  ${PASSIVE_TOOLS[*]}"
    exit 0 ;;
  --check)
    validate_gate
    err "gate OK: scope + authorization valid."
    exit 0 ;;
  ""|-h|--help)
    sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0 ;;
esac

TOOL="$1"; shift

if ! is_active "$TOOL"; then
  err "'$TOOL' is not a registered ACTIVE tool; passive/unknown tools are not gated here."
  err "run passive tools directly, or see 'recon-guard --list'."
  exit 3
fi

# One authorized scope at a time: a single loaded scope.yaml + authorization.
# There is no mass / internet-wide target mode; every target must fall inside
# the one loaded scope, and acceptable-use must be accepted first.
validate_gate
validate_targets "$@"
require_acceptance

if ! BIN="$(resolve_bin "$TOOL")"; then
  err "tool binary not found for '$TOOL' (looked in $TB_BIN and PATH)."
  exit 127
fi

# Attribution: record who ran what against which target(s), then execute.
OPERATOR="$(auth_operator)"
RUN_TARGETS="$(extract_targets "$@" | tr '\n' ' ')"
audit_log "$OPERATOR" "$TOOL" "$RUN_TARGETS"

err "gate passed; executing: $TOOL $*"
exec "$BIN" "$@"
