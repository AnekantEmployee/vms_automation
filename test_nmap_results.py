"""
test_nmap_results.py — Validates nmap cached results for correctness.

Checks:
  1. Schema integrity  — required keys present, correct types
  2. Port consistency  — open_ports list matches service_details entries
  3. open_ports_count  — matches len(open_ports)
  4. Service name sanity — no blank/None service names in service_details
  5. Port range validity — all ports in 1–65535
  6. State field        — all service_details entries have state == "open"
  7. Known-role spot checks — AD/DC IPs have expected ports, etc.
"""

import json
from pathlib import Path

CACHE_FILE = Path(__file__).parent / "backend" / "core" / "cache" / "nmap.json"

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def fail(msg): print(f"  {RED}✗{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")

# ── known-role expectations (spot-check a few IPs from the cache) ─────────────
# Format: ip -> {"must_have": [...], "must_not_have": [...], "label": "..."}
KNOWN_EXPECTATIONS = {
    # Active Directory / Domain Controllers — must have Kerberos, LDAP, DNS
    "10.4.32.150": {
        "label": "AD/DC (INIDRSCADC01)",
        "must_have": [53, 88, 389, 445, 636, 3268, 3269, 3389],
        "must_not_have": [],
    },
    "10.17.1.105": {
        "label": "AD/DC (INIDRBTCADC02)",
        "must_have": [53, 88, 389, 445, 636, 3268, 3269, 3389],
        "must_not_have": [],
    },
    "10.15.1.105": {
        "label": "AD/DC (INBLRADC05)",
        "must_have": [53, 88, 389, 445, 636, 3268, 3269, 3389],
        "must_not_have": [],
    },
    # Exchange / Mail server
    "10.10.2.101": {
        "label": "Exchange (ITS0101021)",
        "must_have": [25, 443, 445, 587, 3389],
        "must_not_have": [],
    },
    # Web-only (Cloudflare)
    "104.17.135.180": {
        "label": "Cloudflare CDN",
        "must_have": [80, 443],
        "must_not_have": [22, 3389],
    },
    # EC2 app server
    "3.6.159.186": {
        "label": "EC2 app server",
        "must_have": [22, 80, 443],
        "must_not_have": [],
    },
    # F5 load balancer
    "10.10.2.112": {
        "label": "F5 BIG-IP",
        "must_have": [80, 443],
        "must_not_have": [],
    },
}

# ── helpers ───────────────────────────────────────────────────────────────────

def validate_schema(ip: str, entry: dict) -> list[str]:
    """Return list of error strings (empty = pass)."""
    errors = []
    required_keys = ["open_ports", "open_ports_count", "services", "service_details", "os", "hostname"]
    for k in required_keys:
        if k not in entry:
            errors.append(f"Missing key '{k}'")

    if not isinstance(entry.get("open_ports"), list):
        errors.append("'open_ports' is not a list")
    if not isinstance(entry.get("open_ports_count"), int):
        errors.append("'open_ports_count' is not an int")
    if not isinstance(entry.get("services"), list):
        errors.append("'services' is not a list")
    if not isinstance(entry.get("service_details"), list):
        errors.append("'service_details' is not a list")
    return errors


def validate_consistency(ip: str, entry: dict) -> list[str]:
    errors = []

    open_ports = entry.get("open_ports", [])
    service_details = entry.get("service_details", [])
    count = entry.get("open_ports_count", -1)

    # Count matches list length
    if count != len(open_ports):
        errors.append(
            f"open_ports_count={count} but len(open_ports)={len(open_ports)}"
        )

    # Ports in service_details match open_ports
    detail_ports = sorted([s["port"] for s in service_details])
    sorted_open  = sorted(open_ports)
    if detail_ports != sorted_open:
        extra_in_details = set(detail_ports) - set(sorted_open)
        missing_in_details = set(sorted_open) - set(detail_ports)
        if extra_in_details:
            errors.append(f"service_details has extra ports not in open_ports: {sorted(extra_in_details)}")
        if missing_in_details:
            errors.append(f"open_ports has ports missing from service_details: {sorted(missing_in_details)}")

    # Port range
    for p in open_ports:
        if not (1 <= p <= 65535):
            errors.append(f"Port {p} is out of valid range 1-65535")

    # State field
    for s in service_details:
        if s.get("state") != "open":
            errors.append(
                f"Port {s.get('port')} has state='{s.get('state')}' (expected 'open')"
            )

    # Service name not None/empty
    for s in service_details:
        if not s.get("name"):
            errors.append(f"Port {s.get('port')} has empty/None service name")

    return errors


def validate_known_expectations(ip: str, entry: dict) -> list[str]:
    if ip not in KNOWN_EXPECTATIONS:
        return []

    exp = KNOWN_EXPECTATIONS[ip]
    open_ports = set(entry.get("open_ports", []))
    errors = []

    for p in exp.get("must_have", []):
        if p not in open_ports:
            errors.append(
                f"Expected port {p} to be open on {exp['label']} but it's missing"
            )

    for p in exp.get("must_not_have", []):
        if p in open_ports:
            errors.append(
                f"Port {p} should NOT be open on {exp['label']} but it is"
            )

    return errors


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    if not CACHE_FILE.exists():
        print(f"{RED}Cache file not found: {CACHE_FILE}{RESET}")
        return

    raw = json.loads(CACHE_FILE.read_text())
    total = len(raw)
    passed = 0
    failed_ips = []

    print(f"\n{'='*60}")
    print(f"  Nmap Results Validation  ({total} IPs in cache)")
    print(f"{'='*60}\n")

    for ip, record in raw.items():
        entry = record.get("value", {})
        ip_errors = []

        ip_errors += validate_schema(ip, entry)
        ip_errors += validate_consistency(ip, entry)
        ip_errors += validate_known_expectations(ip, entry)

        label = KNOWN_EXPECTATIONS.get(ip, {}).get("label", "")
        display = f"{ip}" + (f"  [{label}]" if label else "")

        if ip_errors:
            print(f"  {RED}FAIL{RESET}  {display}")
            for e in ip_errors:
                fail(e)
            failed_ips.append(ip)
        else:
            ports = entry.get("open_ports", [])
            services = entry.get("services", [])
            print(f"  {GREEN}PASS{RESET}  {display}")
            print(f"         ports={ports}  services={services}")
            passed += 1

    # ── summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Results: {GREEN}{passed} passed{RESET} / {RED}{len(failed_ips)} failed{RESET}  (total {total})")
    if failed_ips:
        print(f"\n  Failed IPs:")
        for ip in failed_ips:
            print(f"    - {ip}")
    print(f"{'='*60}\n")

    # ── extra: flag IPs with 0 open ports (may indicate scan issues) ──────────
    zero_port_ips = [
        ip for ip, rec in raw.items()
        if rec.get("value", {}).get("open_ports_count", -1) == 0
    ]
    if zero_port_ips:
        print(f"  {YELLOW}Note:{RESET} {len(zero_port_ips)} IP(s) returned 0 open ports "
              f"(host may be down, firewalled, or scan failed):")
        for ip in zero_port_ips:
            print(f"    - {ip}")
        print()


if __name__ == "__main__":
    main()
