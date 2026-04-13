#!/usr/bin/env python3
"""
IP Asset Discovery Tool - Passive Recon
Discovers all IPs associated with a domain and enriches them with:
  - asset_role        : Role of the IP in the organization
  - data_classification: public / internal / confidential / restricted / Unknown
  - environment       : production / staging / dev / dr / Unknown

Usage:
    python3 ip_asset_discovery.py -d example.com
    python3 ip_asset_discovery.py -d example.com -o assets.json

Requirements:
    pip install requests dnspython colorama
"""

import argparse
import json
import re
import socket
import time
from datetime import datetime

import requests
import dns.resolver
from colorama import Fore, Style, init

init(autoreset=True)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PassiveRecon/1.0)"}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def banner():
    print(Fore.CYAN + r"""
  ___  ____     __    ____  ____  ____  ____    ____  ___  ___  ____  _  _ 
 |_ _||  _ \   / \   / ___||  _ \|  __||_  _|  |  _ \|_ _|/ __||  _ \| \/ |
  | | | |_) | / _ \  \___ \| |_) |  _|   | |   | | | || |( (__ | | | |    |
 |___||____/ /_/ \_\ |____/|____/|____|  |_|   |_|_|_/|___|\___||_|_|_||_|_|

    IP Asset Discovery | Passive | Free Sources Only
    """)

def section(title):
    print(f"\n{Fore.YELLOW}{'─'*65}")
    print(f"{Fore.YELLOW}  {title}")
    print(f"{Fore.YELLOW}{'─'*65}{Style.RESET_ALL}")

def ok(msg):   print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")
def info(msg): print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def safe_get(url, timeout=15, **kwargs):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        warn(f"Request failed → {url} | {e}")
        return None

# ─── Step 1: Collect all hostnames ────────────────────────────────────────────

def collect_hostnames(domain):
    """Gather subdomains from crt.sh, HackerTarget, and Wayback CDX."""
    hostnames = set()
    hostnames.add(domain)

    # crt.sh
    info("crt.sh — Certificate Transparency logs...")
    r = safe_get(f"https://crt.sh/?q=%.{domain}&output=json")
    if r:
        try:
            for entry in r.json():
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub:
                        hostnames.add(sub.lower())
        except Exception as e:
            warn(f"crt.sh parse error: {e}")

    # HackerTarget
    info("HackerTarget — host search...")
    r = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if r and "error" not in r.text.lower():
        for line in r.text.strip().split("\n"):
            parts = line.split(",")
            if parts and domain in parts[0]:
                hostnames.add(parts[0].strip().lower())

    # Wayback CDX
    info("Wayback Machine CDX — URL extraction...")
    r = safe_get(
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
    )
    if r:
        try:
            for entry in r.json()[1:]:
                match = re.search(r"https?://([^/]+)", entry[0])
                if match:
                    host = match.group(1).lower().strip()
                    if domain in host:
                        hostnames.add(host)
        except Exception as e:
            warn(f"Wayback parse error: {e}")

    hostnames.discard(domain + ".")
    return sorted(hostnames)

# ─── Step 2: Resolve hostnames → IPs ──────────────────────────────────────────

def resolve_ips(hostnames):
    """Resolve each hostname to an IP. Returns dict: ip → [hostnames]"""
    ip_map = {}
    for host in hostnames:
        try:
            ip = socket.gethostbyname(host)
            ip_map.setdefault(ip, []).append(host)
        except Exception:
            pass
    return ip_map

# ─── Step 3: Enrich IPs via ipinfo.io ─────────────────────────────────────────

def enrich_ip(ip):
    """Get org, ASN, country, city from ipinfo.io free tier."""
    r = safe_get(f"https://ipinfo.io/{ip}/json", timeout=10)
    if r:
        try:
            d = r.json()
            return {
                "org": d.get("org", "Unknown"),
                "asn": d.get("org", "").split()[0] if d.get("org") else "Unknown",
                "country": d.get("country", "Unknown"),
                "region": d.get("region", "Unknown"),
                "city": d.get("city", "Unknown"),
                "hostname": d.get("hostname", ""),
                "anycast": d.get("anycast", False),
            }
        except Exception:
            pass
    return {
        "org": "Unknown", "asn": "Unknown", "country": "Unknown",
        "region": "Unknown", "city": "Unknown", "hostname": "", "anycast": False
    }

# ─── Step 4: DNS record type for a hostname ────────────────────────────────────

def dns_record_type(hostname):
    """Check which DNS record type resolves for this hostname."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    for rtype in ["A", "CNAME", "AAAA"]:
        try:
            resolver.resolve(hostname, rtype)
            return rtype
        except Exception:
            pass
    return "Unknown"

# ─── Step 5: Infer asset_role ─────────────────────────────────────────────────

ROLE_PATTERNS = [
    # (regex on hostname,            role label)
    (r"^(www|web)\.",               "Web Server (Primary)"),
    (r"\bmail\b|\bsmtp\b|\bmx\b",   "Mail Server"),
    (r"\bapi\b|\brest\b|\bgraphql\b","API Gateway / Endpoint"),
    (r"\bcdn\b|\bstatic\b|\bassets\b|\bmedia\b", "CDN / Static Assets"),
    (r"\bvpn\b|\bremote\b|\bgateway\b",          "VPN / Remote Access Gateway"),
    (r"\bauth\b|\bsso\b|\blogin\b|\biam\b",       "Authentication / SSO Server"),
    (r"\badmin\b|\bpanel\b|\bcpanel\b|\bdashboard\b", "Admin Panel"),
    (r"\bdb\b|\bdatabase\b|\bmysql\b|\bpgsql\b|\bmongo\b|\bsql\b", "Database Server"),
    (r"\bns\d*\b|\bdns\b|\bnamed\b",              "DNS / Nameserver"),
    (r"\bftp\b|\bfiles\b|\bsftp\b",               "File Transfer / FTP Server"),
    (r"\bmonitor\b|\bmetrics\b|\bgrafana\b|\bkibana\b|\belastic\b", "Monitoring / Observability"),
    (r"\bci\b|\bcd\b|\bjenkins\b|\bgitlab\b|\bgithub\b|\bbuild\b", "CI/CD Server"),
    (r"\bstage\b|\bstaging\b|\buat\b|\btest\b",   "Staging / Test Server"),
    (r"\bdev\b|\blocal\b|\bsandbox\b",             "Development Server"),
    (r"\bdr\b|\bbackup\b|\bfailover\b|\bstandby\b","Disaster Recovery / Backup"),
    (r"\blb\b|\bbalancer\b|\bhaproxy\b|\bnginx\b", "Load Balancer"),
    (r"\bstore\b|\bshop\b|\bcart\b|\bcommerce\b",  "E-Commerce / Store"),
    (r"\bsupport\b|\bhelp\b|\bdesk\b|\bticket\b",  "Support / Helpdesk"),
    (r"\bblog\b|\bnews\b|\bcms\b|\bwp\b|\bwordpress\b", "CMS / Blog"),
    (r"\bapp\b|\bportal\b|\bplatform\b",           "Application Server / Portal"),
]

def infer_role(hostnames, org_info):
    """Infer the asset role from hostname patterns + org info."""
    for host in hostnames:
        host_lower = host.lower()
        for pattern, role in ROLE_PATTERNS:
            if re.search(pattern, host_lower):
                return role

    # Fallback: use org info
    org = org_info.get("org", "").lower()
    if "cloudflare" in org:   return "CDN / Proxy (Cloudflare)"
    if "amazon" in org or "aws" in org: return "Cloud Infrastructure (AWS)"
    if "google" in org:       return "Cloud Infrastructure (GCP)"
    if "microsoft" in org or "azure" in org: return "Cloud Infrastructure (Azure)"
    if "fastly" in org:       return "CDN (Fastly)"
    if "akamai" in org:       return "CDN (Akamai)"

    return "Unknown"

# ─── Step 6: Infer data_classification ────────────────────────────────────────

def infer_classification(hostnames, role):
    """
    Heuristic classification based on role + hostname keywords.
    public / internal / confidential / restricted / Unknown
    """
    role_lower = role.lower()
    hostnames_str = " ".join(hostnames).lower()

    # Restricted: auth, VPN, DB, admin, CI/CD
    if any(k in role_lower for k in ["auth", "database", "admin", "vpn", "ci/cd", "iam"]):
        return "restricted"

    # Confidential: internal apps, monitoring, backup, file transfer
    if any(k in role_lower for k in ["monitoring", "file transfer", "backup", "disaster"]):
        return "confidential"

    # Internal: staging, dev, support backend
    if any(k in role_lower for k in ["staging", "development", "helpdesk"]):
        return "internal"

    # Public: web, cdn, api, store, blog, app portal
    if any(k in role_lower for k in ["web server", "cdn", "api", "e-commerce", "cms", "blog",
                                      "application server", "mail server", "load balancer"]):
        return "public"

    # Keyword fallback on hostnames
    if re.search(r"\binternal\b|\bintra\b|\bprivate\b", hostnames_str):
        return "internal"
    if re.search(r"\bpublic\b|\bwww\b|\bweb\b|\bcdn\b", hostnames_str):
        return "public"

    return "Unknown"

# ─── Step 7: Infer environment ────────────────────────────────────────────────

def infer_environment(hostnames, role):
    """
    Heuristic: production / staging / dev / dr / Unknown
    """
    hostnames_str = " ".join(hostnames).lower()
    role_lower = role.lower()

    if re.search(r"\bdr\b|\bfailover\b|\bstandby\b|\bbackup\b", hostnames_str) or "disaster" in role_lower:
        return "dr"
    if re.search(r"\bdev\b|\bsandbox\b|\blocal\b|\bdevelop\b", hostnames_str) or "development" in role_lower:
        return "dev"
    if re.search(r"\bstag\b|\buat\b|\btest\b|\bqa\b|\bpre-?prod\b", hostnames_str) or "staging" in role_lower:
        return "staging"
    if re.search(r"\bprod\b|\bwww\b|\bweb\b|\bapi\b|\bapp\b|\bmail\b|\bcdn\b", hostnames_str):
        return "production"

    # If we have a clear public-facing role, assume production
    if any(k in role_lower for k in ["web server", "cdn", "api", "mail", "load balancer",
                                      "e-commerce", "cms", "application server"]):
        return "production"

    return "Unknown"

# ─── Step 8: MX record IPs ────────────────────────────────────────────────────

def mx_ips(domain):
    """Resolve MX records and return their IPs."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    mx_hosts = {}
    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            mx_host = str(rdata.exchange).rstrip(".")
            try:
                ip = socket.gethostbyname(mx_host)
                mx_hosts[ip] = mx_host
            except Exception:
                pass
    except Exception:
        pass
    return mx_hosts

# ─── Step 9: NS record IPs ────────────────────────────────────────────────────

def ns_ips(domain):
    """Resolve NS records and return their IPs."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    ns_hosts = {}
    try:
        answers = resolver.resolve(domain, "NS")
        for rdata in answers:
            ns_host = str(rdata).rstrip(".")
            try:
                ip = socket.gethostbyname(ns_host)
                ns_hosts[ip] = ns_host
            except Exception:
                pass
    except Exception:
        pass
    return ns_hosts

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IP Asset Discovery — Passive Recon")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    domain = args.domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]

    banner()
    print(f"{Fore.CYAN}  Target : {Fore.WHITE}{domain}")
    print(f"{Fore.CYAN}  Time   : {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    assets = []

    # ── Collect hostnames
    section("STEP 1 — Collecting Hostnames")
    hostnames = collect_hostnames(domain)
    ok(f"Total hostnames collected: {len(hostnames)}")

    # ── Resolve IPs
    section("STEP 2 — Resolving IPs")
    ip_map = resolve_ips(hostnames)  # ip → [hostnames]

    # ── Add MX & NS IPs
    info("Resolving MX record IPs...")
    for ip, host in mx_ips(domain).items():
        ip_map.setdefault(ip, []).append(f"MX:{host}")

    info("Resolving NS record IPs...")
    for ip, host in ns_ips(domain).items():
        ip_map.setdefault(ip, []).append(f"NS:{host}")

    ok(f"Total unique IPs found: {len(ip_map)}")

    # ── Enrich each IP
    section("STEP 3 — Enriching IPs")
    col_w = [18, 35, 22, 18, 14]
    header = (
        f"  {'IP':<{col_w[0]}} {'Hostnames':<{col_w[1]}} "
        f"{'Asset Role':<{col_w[2]}} {'Classification':<{col_w[3]}} {'Environment':<{col_w[4]}}"
    )
    print(Fore.CYAN + header)
    print(Fore.CYAN + "  " + "─" * (sum(col_w) + 4))

    for ip, hosts in ip_map.items():
        org_info = enrich_ip(ip)
        time.sleep(0.4)  # be polite to ipinfo.io

        # Deduplicate and clean hostnames
        hosts = sorted(set(h for h in hosts if h))

        role           = infer_role(hosts, org_info)
        classification = infer_classification(hosts, role)
        environment    = infer_environment(hosts, role)

        asset = {
            "ip": ip,
            "hostnames": hosts,
            "asn": org_info["asn"],
            "org": org_info["org"],
            "country": org_info["country"],
            "region": org_info["region"],
            "city": org_info["city"],
            "anycast": org_info["anycast"],
            "asset_role": role,
            "data_classification": classification,
            "environment": environment,
        }
        assets.append(asset)

        # Color-code classification
        cls_color = {
            "public": Fore.GREEN,
            "internal": Fore.YELLOW,
            "confidential": Fore.MAGENTA,
            "restricted": Fore.RED,
            "Unknown": Fore.WHITE,
        }.get(classification, Fore.WHITE)

        env_color = {
            "production": Fore.RED,
            "staging": Fore.YELLOW,
            "dev": Fore.BLUE,
            "dr": Fore.MAGENTA,
            "Unknown": Fore.WHITE,
        }.get(environment, Fore.WHITE)

        hosts_display = ", ".join(hosts[:2]) + ("…" if len(hosts) > 2 else "")
        print(
            f"  {Fore.GREEN}{ip:<{col_w[0]}}{Style.RESET_ALL}"
            f" {hosts_display:<{col_w[1]}}"
            f" {role:<{col_w[2]}}"
            f" {cls_color}{classification:<{col_w[3]}}{Style.RESET_ALL}"
            f" {env_color}{environment:<{col_w[4]}}{Style.RESET_ALL}"
        )

    # ── Summary
    section("SUMMARY")
    ok(f"Total unique IPs        : {len(assets)}")
    ok(f"Production assets       : {sum(1 for a in assets if a['environment'] == 'production')}")
    ok(f"Staging assets          : {sum(1 for a in assets if a['environment'] == 'staging')}")
    ok(f"Dev assets              : {sum(1 for a in assets if a['environment'] == 'dev')}")
    ok(f"DR assets               : {sum(1 for a in assets if a['environment'] == 'dr')}")
    ok(f"Public classification   : {sum(1 for a in assets if a['data_classification'] == 'public')}")
    ok(f"Internal classification : {sum(1 for a in assets if a['data_classification'] == 'internal')}")
    ok(f"Confidential            : {sum(1 for a in assets if a['data_classification'] == 'confidential')}")
    ok(f"Restricted              : {sum(1 for a in assets if a['data_classification'] == 'restricted')}")
    ok(f"Unknown                 : {sum(1 for a in assets if a['data_classification'] == 'Unknown')}")

    # ── Save
    output = {"domain": domain, "timestamp": str(datetime.now()), "assets": assets}
    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        ok(f"\nResults saved → {args.output}")
    else:
        print(f"\n{Fore.CYAN}Tip: Run with -o assets.json to save full results.{Style.RESET_ALL}")

    return output

if __name__ == "__main__":
    main()