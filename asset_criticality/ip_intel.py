"""
ip_intel.py — Free-tier threat intelligence enrichment for an IP.

Sources used (all free, no paid key required for basic use):
  1. ipinfo.io      → ASN, org, country, hosting provider
  2. AbuseIPDB      → abuse confidence score, report count          (needs free API key)
  3. GreyNoise      → is it a scanner / known noise on the internet  (community API, no key)
  4. Shodan         → internet-facing banner grab                    (optional paid key)

Every source is wrapped in try/except so a failure never breaks the pipeline.
Missing env vars just disable that source gracefully.

Returns:
{
    "internet_facing":      bool,
    "asn":                  "AS16509",
    "org":                  "Amazon.com Inc.",
    "country":              "US",
    "hosting_provider":     "AWS",
    "abuse_confidence":     42,        # 0-100; -1 if unavailable
    "abuse_reports":        7,
    "is_known_scanner":     False,
    "greynoise_classification": "malicious" | "benign" | "unknown",
    "shodan_ports":         [22, 80],  # [] if unavailable
    "shodan_vulns":         ["CVE-2021-44228"],  # [] if unavailable
    "threat_intel_summary": "string",
}
"""

import os
import requests
from dotenv import load_dotenv
from asset_criticality.cache import cache_get, cache_set

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_KEY    = os.getenv("SHODAN_API_KEY", "")

_HEADERS = {"User-Agent": "AssetCriticalityAgent/1.0"}
_TIMEOUT = 8  # seconds per request


def _ipinfo(ip: str) -> dict:
    """ASN, org, country, hosting info from ipinfo.io (free, no key needed)."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers=_HEADERS, timeout=_TIMEOUT)
        d = r.json()
        return {
            "asn":              d.get("org", "").split(" ")[0],          # e.g. AS16509
            "org":              " ".join(d.get("org", "").split(" ")[1:]),# e.g. Amazon.com Inc.
            "country":          d.get("country", ""),
            "hosting_provider": d.get("org", ""),
        }
    except Exception as e:
        print(f"[ipinfo] Failed: {e}")
        return {"asn": "", "org": "", "country": "", "hosting_provider": ""}


def _abuseipdb(ip: str) -> dict:
    """Abuse confidence + report count from AbuseIPDB (free 1 000 req/day key)."""
    if not ABUSEIPDB_KEY:
        print("[abuseipdb] No API key set (ABUSEIPDB_API_KEY) — skipping")
        return {"abuse_confidence": -1, "abuse_reports": -1}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={**_HEADERS, "Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_TIMEOUT,
        )
        d = r.json().get("data", {})
        return {
            "abuse_confidence": d.get("abuseConfidenceScore", -1),
            "abuse_reports":    d.get("totalReports", -1),
        }
    except Exception as e:
        print(f"[abuseipdb] Failed: {e}")
        return {"abuse_confidence": -1, "abuse_reports": -1}


def _greynoise(ip: str) -> dict:
    """GreyNoise community API — no key required, 10 000 req/month free."""
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={**_HEADERS, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            # Not in GreyNoise → not a known internet scanner
            return {"is_known_scanner": False, "greynoise_classification": "unknown"}
        d = r.json()
        return {
            "is_known_scanner":          d.get("noise", False),
            "greynoise_classification":  d.get("classification", "unknown"),
        }
    except Exception as e:
        print(f"[greynoise] Failed: {e}")
        return {"is_known_scanner": False, "greynoise_classification": "unknown"}


def _shodan(ip: str) -> dict:
    """Shodan host lookup — banners, open ports, known vulns."""
    if not SHODAN_KEY:
        print("[shodan] No API key set (SHODAN_API_KEY) — skipping")
        return {"shodan_ports": [], "shodan_vulns": [], "internet_facing": False}
    try:
        import shodan as shodan_lib
        host = shodan_lib.Shodan(SHODAN_KEY).host(ip)
        return {
            "shodan_ports":   host.get("ports", []),
            "shodan_vulns":   list(host.get("vulns", {}).keys()),
            "internet_facing": True,
        }
    except Exception:
        print("[shodan] Unable to connect — skipping")
        return {"shodan_ports": [], "shodan_vulns": [], "internet_facing": False}


def _internet_facing_heuristic(ipinfo_data: dict, shodan_data: dict) -> bool:
    """
    Even without Shodan, if ipinfo says the IP belongs to a cloud/hosting ASN
    it is almost certainly internet-facing (a public cloud IP).
    """
    if shodan_data.get("internet_facing"):
        return True
    cloud_keywords = ["amazon", "aws", "azure", "google", "digitalocean",
                      "linode", "vultr", "hetzner", "cloudflare", "ovh"]
    org_lower = ipinfo_data.get("hosting_provider", "").lower()
    return any(kw in org_lower for kw in cloud_keywords)


def run_ip_intel(ip: str) -> dict:
    cached = cache_get("ip_intel", ip)
    if cached:
        print(f"[ip_intel] Cache hit for {ip}")
        return cached

    print(f"[ip_intel] Enriching {ip} ...")

    ipinfo  = _ipinfo(ip)
    abuse   = _abuseipdb(ip)
    gnoise  = _greynoise(ip)
    shodan  = _shodan(ip)

    internet_facing = _internet_facing_heuristic(ipinfo, shodan)

    # Build a short human-readable threat intel summary for the LLM
    parts = []
    if internet_facing:
        parts.append("The IP is publicly reachable on the internet.")
    if abuse["abuse_confidence"] >= 0:
        parts.append(
            f"AbuseIPDB confidence score: {abuse['abuse_confidence']}% "
            f"({abuse['abuse_reports']} reports)."
        )
    if gnoise["is_known_scanner"]:
        parts.append("GreyNoise flags this IP as an active internet scanner.")
    if gnoise["greynoise_classification"] == "malicious":
        parts.append("GreyNoise classifies this IP as malicious.")
    if shodan["shodan_vulns"]:
        parts.append(f"Shodan reports known CVEs: {', '.join(shodan['shodan_vulns'][:5])}.")

    threat_summary = " ".join(parts) if parts else "No significant threat signals detected."

    result = {
        "internet_facing":           internet_facing,
        "asn":                       ipinfo["asn"],
        "org":                       ipinfo["org"],
        "country":                   ipinfo["country"],
        "hosting_provider":          ipinfo["hosting_provider"],
        "abuse_confidence":          abuse["abuse_confidence"],
        "abuse_reports":             abuse["abuse_reports"],
        "is_known_scanner":          gnoise["is_known_scanner"],
        "greynoise_classification":  gnoise["greynoise_classification"],
        "shodan_ports":              shodan["shodan_ports"],
        "shodan_vulns":              shodan["shodan_vulns"],
        "threat_intel_summary":      threat_summary,
    }

    cache_set("ip_intel", ip, result)
    print(f"[ip_intel] Done → internet_facing={result['internet_facing']}, "
          f"abuse={result['abuse_confidence']}%, scanner={result['is_known_scanner']}")
    return result