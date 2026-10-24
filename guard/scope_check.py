#!/usr/bin/env python3
"""
scope_check.py — authorization + scope validator for the ethical recon/test bench.

Used by recon-guard.sh. Can also be run standalone:

  scope_check.py verify-auth  --scope scope.yaml --auth authorization.yml \
                              [--keyring pubkey.gpg] [--now 2026-10-23]
  scope_check.py check-target --scope scope.yaml --target <host|ip|cidr|url> [...]

Exit codes:
  0  = OK
  2  = validation failure (refuse to run)
  3  = malformed / missing inputs

No secrets are printed. Lab-only tooling.
"""
import argparse
import datetime
import ipaddress
import os
import re
import subprocess
import sys

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def die(code, msg):
    sys.stderr.write("[scope_check] " + msg + "\n")
    sys.exit(code)


def load_yaml(path):
    if not os.path.isfile(path):
        die(3, f"file not found: {path}")
    if yaml is None:
        die(3, "PyYAML not available; install python3-yaml")
    with open(path, "r") as fh:
        try:
            return yaml.safe_load(fh) or {}
        except Exception as exc:
            die(3, f"malformed YAML in {path}: {exc}")


def parse_date(val, field):
    if isinstance(val, datetime.datetime):
        return val.date()
    if isinstance(val, datetime.date):
        return val
    try:
        return datetime.date.fromisoformat(str(val))
    except Exception:
        die(3, f"bad date in '{field}': {val!r} (want YYYY-MM-DD)")


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- scope parsing
def scope_entries(scope):
    """Return (domains, networks, hosts) from a parsed scope.yaml."""
    if not isinstance(scope, dict):
        die(3, "scope.yaml top-level must be a mapping")
    in_scope = scope.get("in_scope") or {}
    if not isinstance(in_scope, dict):
        die(3, "scope.yaml 'in_scope' must be a mapping")
    domains = [str(d).lower().lstrip(".") for d in (in_scope.get("domains") or [])]
    hosts = [str(h).lower() for h in (in_scope.get("hosts") or [])]
    networks = []
    for c in (in_scope.get("cidrs") or []):
        try:
            networks.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            die(3, f"bad CIDR in scope: {c}")
    return domains, networks, hosts


def normalize_target(raw):
    """Strip scheme/port/path, return a bare host/ip/cidr string."""
    t = raw.strip()
    # URL -> host
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/]+)", t)
    if m:
        t = m.group(1)
    # strip userinfo
    if "@" in t:
        t = t.split("@", 1)[1]
    # bracketed IPv6
    if t.startswith("["):
        t = t[1:].split("]", 1)[0]
    else:
        # strip :port only if it looks like host:port (single colon, numeric port)
        if t.count(":") == 1:
            host, _, port = t.partition(":")
            if port.isdigit():
                t = host
    # drop any trailing path remnants
    t = t.split("/")[0] if "/" not in t or not _is_cidrish(t) else t
    return t.lower().rstrip(".")


def _is_cidrish(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return "/" in s
    except ValueError:
        return False


def target_in_scope(raw, domains, networks, hosts):
    t = normalize_target(raw)
    if not t:
        return False, "empty target"
    # CIDR target: must be fully contained in an in-scope network
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return False, f"unparseable target {raw!r}"
        for n in networks:
            if net.version == n.version and net.subnet_of(n):
                return True, f"{t} within {n}"
        return False, f"CIDR {t} not within any in-scope network"
    # bare IP
    try:
        ip = ipaddress.ip_address(t)
        for n in networks:
            if ip.version == n.version and ip in n:
                return True, f"{t} in {n}"
        if t in hosts:
            return True, f"{t} explicit host"
        return False, f"IP {t} not in any in-scope network/host"
    except ValueError:
        pass
    # hostname
    if t in hosts:
        return True, f"{t} explicit host"
    for d in domains:
        if t == d or t.endswith("." + d):
            return True, f"{t} under domain {d}"
    return False, f"host {t} not in scope"


# ----------------------------------------------------------------- subcommands
def cmd_check_target(args):
    scope = load_yaml(args.scope)
    domains, networks, hosts = scope_entries(scope)
    if not (domains or networks or hosts):
        die(2, "scope.yaml has no in-scope domains, cidrs, or hosts")
    bad = []
    for raw in args.target:
        ok, why = target_in_scope(raw, domains, networks, hosts)
        if ok:
            sys.stderr.write(f"[scope_check] in-scope: {raw} ({why})\n")
        else:
            bad.append((raw, why))
    if bad:
        for raw, why in bad:
            sys.stderr.write(f"[scope_check] OUT OF SCOPE: {raw} ({why})\n")
        sys.exit(2)
    sys.exit(0)


def cmd_verify_auth(args):
    # 1. scope must be well-formed with real entries
    scope = load_yaml(args.scope)
    domains, networks, hosts = scope_entries(scope)
    if not (domains or networks or hosts):
        die(2, "scope.yaml defines no in-scope targets")

    # 2. authorization file must exist & parse
    auth = load_yaml(args.auth)
    for field in ("operator", "expires"):
        if not auth.get(field):
            die(2, f"authorization missing required field: {field}")
    if str(auth.get("example", "")).lower() in ("true", "yes", "1"):
        die(2, "authorization file is the EXAMPLE template; refusing. "
               "Create a real, signed authorization.")

    # 3. expiry / not-before
    now = parse_date(args.now, "--now") if args.now else datetime.date.today()
    exp = parse_date(auth["expires"], "expires")
    if exp < now:
        die(2, f"authorization expired on {exp} (today {now})")
    if auth.get("not_before"):
        nb = parse_date(auth["not_before"], "not_before")
        if now < nb:
            die(2, f"authorization not valid until {nb} (today {now})")

    # 4. bind auth to this scope via sha256 (optional but enforced if present)
    if auth.get("scope_sha256"):
        actual = sha256_file(args.scope)
        if actual.lower() != str(auth["scope_sha256"]).lower():
            die(2, "scope_sha256 in authorization does not match scope.yaml "
                   "(scope changed after signing)")

    # 5. signature verification (GPG detached sig)
    sig = args.sig or (args.auth + ".sig")
    if args.no_sig:
        sys.stderr.write("[scope_check] WARNING: signature check skipped (--no-sig)\n")
    else:
        if not os.path.isfile(sig):
            die(2, f"detached signature not found: {sig}")
        cmd = ["gpg", "--batch", "--status-fd", "1"]
        if args.keyring:
            cmd += ["--no-default-keyring", "--keyring", os.path.abspath(args.keyring)]
        cmd += ["--verify", sig, args.auth]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            die(3, "gpg not installed; cannot verify signature")
        if out.returncode != 0 or "VALIDSIG" not in out.stdout:
            die(2, "GPG signature verification FAILED for authorization file")
        sys.stderr.write("[scope_check] signature OK\n")

    sys.stderr.write(
        f"[scope_check] authorization valid for operator "
        f"{auth['operator']} until {exp}\n")
    sys.exit(0)


def main():
    p = argparse.ArgumentParser(description="recon test-bench scope/auth validator")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("verify-auth")
    a.add_argument("--scope", required=True)
    a.add_argument("--auth", required=True)
    a.add_argument("--sig")
    a.add_argument("--keyring")
    a.add_argument("--now")
    a.add_argument("--no-sig", action="store_true")
    a.set_defaults(func=cmd_verify_auth)

    c = sub.add_parser("check-target")
    c.add_argument("--scope", required=True)
    c.add_argument("--target", required=True, nargs="+")
    c.set_defaults(func=cmd_check_target)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
