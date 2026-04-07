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
from asset_criticality.cache import cache_get, cache_set


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
    nm.scan(ip, arguments="-sV --open -T4 -Pn -O --osscan-guess")

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

    cache_set("nmap", ip, result)
    print(
        f"[nmap] Done → {result['open_ports_count']} open ports, "
        f"services: {result['services']}, os: {result['os']}, hostname: {result['hostname']}"
    )
    return result