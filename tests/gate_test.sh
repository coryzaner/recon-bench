#!/usr/bin/env bash
# gate_test.sh — local, VM-free validation of the safety gate.
# Creates a throwaway GPG key + scope + signed auth in a tmp dir and asserts the
# guard refuses/permits correctly. No network, no real targets, no secrets kept.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$HERE/roles/testbench/files/recon-guard.sh"
CHECK="$HERE/roles/testbench/files/scope_check.py"
TMP="$(mktemp -d)"
export GNUPGHOME="$TMP/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }

# fake tool so the guard has something to exec on success
mkdir -p "$TMP/bin"
printf '#!/bin/sh\necho "[nmap-stub] scanning $*"\n' > "$TMP/bin/nmap"
chmod +x "$TMP/bin/nmap"

# scope
cat > "$TMP/scope.yaml" <<YML
meta: {engagement: test, owner: op@example.internal}
in_scope:
  domains: [lab.example.internal]
  cidrs: [192.0.2.0/24]
  hosts: [web01.lab.example.com]
YML

export TB_ETC="$TMP" TB_SCOPE="$TMP/scope.yaml" TB_AUTH="$TMP/authorization.yml" \
  TB_AUTH_SIG="$TMP/authorization.yml.sig" TB_KEYRING="$TMP/operators.gpg" \
  TB_BIN="$TMP/bin" TB_SCOPE_CHECK="$CHECK" TB_ALLOW_NO_SIG=0 \
  TB_AU_ACCEPT="$TMP/acceptable_use_accepted" TB_AUDIT="$TMP/audit.log"

run(){ bash "$GUARD" "$@" >/dev/null 2>&1; echo $?; }

# 1. No auth file yet -> refuse (exit 2)
[ "$(run nmap 192.0.2.10)" = "2" ] && ok "refuse: no authorization" || no "should refuse without auth"

# 2. Example (unsigned, example:true) auth -> refuse
cp "$HERE/roles/testbench/files/authorization.example.yml" "$TMP/authorization.yml"
[ "$(run nmap 192.0.2.10)" = "2" ] && ok "refuse: example template" || no "should refuse example template"

# Build a real, signed auth bound to scope
KEY="op@example.internal"
cat > "$TMP/keyparams" <<KP
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: Test Operator
Name-Email: $KEY
Expire-Date: 0
%commit
KP
gpg --batch --gen-key "$TMP/keyparams" >/dev/null 2>&1
gpg --no-default-keyring --keyring "$TB_KEYRING" --import \
    <(gpg --export "$KEY") >/dev/null 2>&1
SHA="$(sha256sum "$TMP/scope.yaml" | awk '{print $1}')"
cat > "$TMP/authorization.yml" <<YML
operator: $KEY
issued: "2026-10-23"
not_before: "2026-10-01"
expires: "2099-01-01"
scope_ref: scope.yaml
scope_sha256: "$SHA"
YML
gpg --batch --yes --detach-sign -o "$TMP/authorization.yml.sig" "$TMP/authorization.yml" >/dev/null 2>&1

# 3. Valid auth + in-scope BUT acceptable-use NOT accepted -> refuse
rm -f "$TB_AU_ACCEPT"
[ "$(run nmap 192.0.2.10)" = "2" ] && ok "refuse: acceptable-use missing" || no "should refuse without acceptance"

# 4. Record acceptable-use acceptance
bash "$GUARD" --accept-use >/dev/null 2>&1
[ -f "$TB_AU_ACCEPT" ] && ok "accept-use: recorded acceptance file" || no "accept-use should write acceptance file"

# 5. Valid auth + acceptance + in-scope target -> allow (exit 0)
: > "$TB_AUDIT"   # clear for a clean audit assertion
[ "$(run nmap 192.0.2.10)" = "0" ] && ok "allow: valid auth + acceptance + in-scope" || no "should allow in-scope"

# 6. Successful allow appends an audit line (operator, tool, target, timestamp)
if [ -f "$TB_AUDIT" ] && grep -q "operator=$KEY" "$TB_AUDIT" \
   && grep -q "tool=nmap" "$TB_AUDIT" \
   && grep -q "192.0.2.10" "$TB_AUDIT"; then
  ok "audit: line written on successful allow"
else
  no "audit.log should gain an attribution line"
fi

# 7. Valid auth + OUT-of-scope target -> refuse (exit 2)
[ "$(run nmap 203.0.113.5)" = "2" ] && ok "refuse: out-of-scope target" || no "should refuse out-of-scope"

# 8. In-scope hostname under domain -> allow
[ "$(run nmap host1.lab.example.internal)" = "0" ] && ok "allow: subdomain in scope" || no "should allow subdomain"

# 9. Tampered scope (sha mismatch) -> refuse
echo "# tamper" >> "$TMP/scope.yaml"
[ "$(run nmap 192.0.2.10)" = "2" ] && ok "refuse: scope changed after signing" || no "should refuse tampered scope"
# restore scope + re-sign for remaining tests
sed -i '/# tamper/d' "$TMP/scope.yaml"

# 10. Expired auth -> refuse
cat > "$TMP/authorization.yml" <<YML
operator: $KEY
expires: "2000-01-01"
scope_sha256: "$SHA"
YML
gpg --batch --yes --detach-sign -o "$TMP/authorization.yml.sig" "$TMP/authorization.yml" >/dev/null 2>&1
[ "$(run nmap 192.0.2.10)" = "2" ] && ok "refuse: expired authorization" || no "should refuse expired"

# 11. Bad signature (unsigned by trusted key) -> refuse
cat > "$TMP/authorization.yml" <<YML
operator: $KEY
expires: "2099-01-01"
scope_sha256: "$SHA"
YML
echo "not a real signature" > "$TMP/authorization.yml.sig"
[ "$(run nmap 192.0.2.10)" = "2" ] && ok "refuse: bad signature" || no "should refuse bad signature"

# 12. Passive tool not gated here -> exit 3 (handled directly, not via guard)
[ "$(run amass -d example.com)" = "3" ] && ok "passive tool not gated by guard" || no "passive handling"

# 13. Optional: absurdly broad target (0.0.0.0/0) refused by scope_check
# Restore a valid signed auth + keep acceptance so only the target check bites.
cat > "$TMP/authorization.yml" <<YML
operator: $KEY
expires: "2099-01-01"
scope_sha256: "$SHA"
YML
gpg --batch --yes --detach-sign -o "$TMP/authorization.yml.sig" "$TMP/authorization.yml" >/dev/null 2>&1
[ "$(run nmap 0.0.0.0/0)" = "2" ] && ok "refuse: absurdly broad target 0.0.0.0/0" || no "should refuse 0.0.0.0/0"

echo "----"; echo "PASS=$pass FAIL=$fail"
rm -rf "$TMP"
[ "$fail" -eq 0 ]
