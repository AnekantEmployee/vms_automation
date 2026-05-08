"""
nmap_scan.py — Port scanning & service fingerprinting via python-nmap.

Returns a normalised dict that the rest of the pipeline consumes:
{
    "open_ports":       [22, 80, 443, ...],
    "open_ports_count": 3,
    "services":         ["ssh", "http", "https"],
    "service_details":  [{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9"}, ...],
    "os":               "Ubuntu Linux 22.04",
    "hostname":         "dc01.corp.example.com" | "",
}
"""

import socket
import nmap
from backend.core.asset_criticality.cache import cache_get, cache_set


# ---------------------------------------------------------------------------
# Port validation
# ---------------------------------------------------------------------------

def validate_nmap_result(ip: str, result: dict) -> list[str]:
    """
    Validate a nmap result dict for correctness and internal consistency.

    Returns a list of warning/error strings.  An empty list means the result
    is clean.  Warnings are printed automatically; callers can inspect the
    list for further action.

    Checks performed
    ----------------
    1. Required keys present with correct types
    2. open_ports_count matches len(open_ports)
    3. Every port in open_ports has a matching entry in service_details
    4. No duplicate ports in open_ports
    5. All port numbers are in the valid range 1–65535
    6. Every service_details entry has state == "open"
    7. No blank / None service name in service_details
    8. services list is consistent with names found in service_details
    """
    issues: list[str] = []

    # 1. Required keys & types
    expected = {
        "open_ports":       list,
        "open_ports_count": int,
        "services":         list,
        "service_details":  list,
        "os":               str,
        "hostname":         str,
    }
    for key, expected_type in expected.items():
        if key not in result:
            issues.append(f"Missing key '{key}'")
        elif not isinstance(result[key], expected_type):
            issues.append(
                f"Key '{key}' has type {type(result[key]).__name__}, "
                f"expected {expected_type.__name__}"
            )

    # Bail early if structure is broken — remaining checks would crash
    if issues:
        for w in issues:
            print(f"[nmap][WARN] {ip} → {w}")
        return issues

    open_ports     = result["open_ports"]
    open_ports_set = set(open_ports)
    service_details = result["service_details"]

    # 2. Count consistency
    if result["open_ports_count"] != len(open_ports):
        issues.append(
            f"open_ports_count={result['open_ports_count']} "
            f"but len(open_ports)={len(open_ports)}"
        )

    # 3. service_details ↔ open_ports alignment
    detail_ports = [s.get("port") for s in service_details]
    detail_ports_set = set(detail_ports)

    missing_in_details = open_ports_set - detail_ports_set
    extra_in_details   = detail_ports_set - open_ports_set
    if missing_in_details:
        issues.append(
            f"Ports in open_ports but missing from service_details: "
            f"{sorted(missing_in_details)}"
        )
    if extra_in_details:
        issues.append(
            f"Ports in service_details but not in open_ports: "
            f"{sorted(extra_in_details)}"
        )

    # 4. Duplicate ports
    if len(open_ports) != len(open_ports_set):
        from collections import Counter
        dupes = [p for p, c in Counter(open_ports).items() if c > 1]
        issues.append(f"Duplicate ports in open_ports: {sorted(dupes)}")

    # 5. Port range validity
    bad_range = [p for p in open_ports if not isinstance(p, int) or not (1 <= p <= 65535)]
    if bad_range:
        issues.append(f"Ports out of valid range 1-65535: {bad_range}")

    # 6. State must be "open"
    wrong_state = [
        s["port"] for s in service_details
        if s.get("state") != "open"
    ]
    if wrong_state:
        issues.append(
            f"service_details entries with state != 'open': {wrong_state}"
        )

    # 7. Blank service names
    blank_name_ports = [
        s["port"] for s in service_details
        if not s.get("name")
    ]
    if blank_name_ports:
        issues.append(
            f"service_details entries with empty/None name: {blank_name_ports}"
        )

    # 8. services list consistency
    names_in_details = {
        s["name"] for s in service_details
        if s.get("name") and s["name"] != "unknown"
    }
    services_set = set(result["services"])
    phantom = services_set - names_in_details          # in services but no detail
    if phantom:
        issues.append(
            f"services list contains names not found in service_details: {phantom}"
        )

    # Print all issues
    if issues:
        for w in issues:
            print(f"[nmap][WARN] {ip} → {w}")
    else:
        print(f"[nmap][OK]   {ip} → result validated ({len(open_ports)} ports, all checks passed)")

    return issues


def run_nmap(ip: str) -> dict:
    cached = cache_get("nmap", ip)
    if cached:
        age_note = " (from cache)"
        print(f"[nmap] Cache hit for {ip}{age_note}")
        return cached

    print(f"[nmap] Scanning {ip}  (this may take ~30s) ...")
    nm = nmap.PortScanner()
    # -sV  : service/version detection
    # --open: only show open ports
    # -T4  : aggressive timing (faster on LAN/cloud)
    # -Pn  : skip host-discovery ping (works even if ICMP is blocked)
    # -O   : OS detection (needs root; gracefully degrades if unavailable)
    nm.scan(ip, arguments="-sV --open -T4 -Pn")

    host_data = nm[ip] if ip in nm.all_hosts() else {}
    tcp        = host_data.get("tcp", {})

    # --- ports & services ---
    service_details = []
    for port, info in sorted(tcp.items()):
        service_details.append({
            "port":    port,
            "name":    info.get("name", "unknown"),
            "product": info.get("product", ""),
            "version": info.get("version", ""),
            "state":   info.get("state", ""),
        })

    services = list({s["name"] for s in service_details if s["name"] != "unknown"})

    # --- OS ---
    os_matches = host_data.get("osmatch", [])
    os_name = "unknown"
    if os_matches:
        os_name = os_matches[0].get("name", "unknown")

    # --- hostname via reverse DNS (best-effort) ---
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    result = {
        "open_ports":       list(tcp.keys()),
        "open_ports_count": len(tcp),
        "services":         services,
        "service_details":  service_details,
        "os":               os_name,
        "hostname":         hostname,
    }

    # Validate before caching — logs any inconsistencies found in the raw scan
    validate_nmap_result(ip, result)

    cache_set("nmap", ip, result)
    print(
        f"[nmap] Done → {result['open_ports_count']} open ports, "
        f"services: {result['services']}, os: {result['os']}, hostname: {result['hostname']}"
    )
    return result