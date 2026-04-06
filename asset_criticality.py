import os
from dotenv import load_dotenv
import nmap, nvdlib, shodan, json
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from main_config.llm_manager import get_master_llm

load_dotenv()

SHODAN_KEY  = os.getenv("SHODAN_API_KEY")
NMAP_CACHE  = Path("cache/nmap_cache.json")
CACHE_TTL_H = 24  # hours

def _load_nmap_cache():
    if NMAP_CACHE.exists():
        return json.loads(NMAP_CACHE.read_text())
    return {}

def _save_nmap_cache(cache):
    NMAP_CACHE.parent.mkdir(exist_ok=True)
    NMAP_CACHE.write_text(json.dumps(cache, indent=2))

def run_agent(ip, business_criticality, data_classification, owner):

    asset = {
        "ip": ip,
        "business_criticality": business_criticality,
        "data_classification": data_classification,
        "owner": owner,
    }

    def _nmap_scan():
        cache = _load_nmap_cache()
        entry = cache.get(ip)
        if entry:
            age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(entry["cached_at"])).total_seconds() / 3600
            if age_h < CACHE_TTL_H:
                print(f"[nmap] Cache hit for {ip} ({age_h:.1f}h old), skipping scan")
                return entry["data"]
        print(f"[nmap] Scanning {ip}...")
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV --open -T4 -Pn")
        h = nm[ip] if ip in nm.all_hosts() else {}
        result = {
            "hostname":         nm.command_line(),
            "os":               h.get("osmatch", [{}])[0].get("name", "unknown") if h else "unknown",
            "open_ports_count": len(h.get("tcp", {})),
            "services":         [h["tcp"][p]["name"] for p in h.get("tcp", {})],
        }
        cache[ip] = {"cached_at": datetime.now(timezone.utc).isoformat(), "data": result}
        _save_nmap_cache(cache)
        print(f"[nmap] Done -> {result['open_ports_count']} open ports, services: {result['services']}")
        return result

    def _shodan_lookup():
        print(f"[shodan] Checking {ip}...")
        try:
            shodan.Shodan(SHODAN_KEY).host(ip)
            print("[shodan] Done -> Internet-facing: True")
            return True
        except Exception as e:
            print(f"[shodan] Done -> Internet-facing: False ({type(e).__name__})")
            return False

    # Step 2+3+4 — Run nmap and Shodan in parallel; CVE lookup after nmap (needs services)
    print("[1/3] Running nmap + Shodan in parallel...")
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_nmap   = ex.submit(_nmap_scan)
        f_shodan = ex.submit(_shodan_lookup)
        asset.update(f_nmap.result())
        asset["internet_facing"] = f_shodan.result()

    print(f"[2/3] Looking up CVEs for services: {asset['services']}...")
    one_year_ago = (datetime.now() - timedelta(days=365)).replace(microsecond=0)
    def _fetch_cves(svc):
        print(f"[cve] Searching '{svc}'...")
        try:
            return nvdlib.searchCVE(keywordSearch=svc, pubStartDate=one_year_ago, limit=10)
        except Exception as e:
            print(f"[cve] Skipping '{svc}': {e}")
            return []

    cves = []
    with ThreadPoolExecutor(max_workers=min(len(asset["services"]) or 1, 5)) as ex:
        for result in as_completed([ex.submit(_fetch_cves, svc) for svc in set(asset["services"])]):
            cves += result.result()

    scores = [c.score[1] for c in cves if c.score]
    asset["max_cvss"]           = max(scores, default=0)
    asset["critical_cve_count"] = sum(1 for c in cves if c.score and c.score[1] >= 9.0)
    print(f"[cve] Done -> {len(cves)} CVEs, max CVSS: {asset['max_cvss']}, critical: {asset['critical_cve_count']}")

    # Step 5+6 — LLM scoring + reasoning
    print(f"[3/3] LLM scoring + reasoning...")
    llm, _ = get_master_llm(probe=False)
    prompt = (
        f"You are a security analyst. Score this asset and assign a criticality tier.\n\n"
        f"Asset data:\n"
        f"  IP: {ip}\n"
        f"  OS: {asset['os']}\n"
        f"  Internet-facing: {asset['internet_facing']}\n"
        f"  Open ports: {asset['open_ports_count']}\n"
        f"  Services: {asset['services']}\n"
        f"  Max CVSS: {asset['max_cvss']}\n"
        f"  Critical CVEs (>=9.0): {asset['critical_cve_count']}\n"
        f"  Business criticality: {business_criticality}\n"
        f"  Data classification: {data_classification}\n\n"
        f"Rules:\n"
        f"  - Score out of 10 based on all factors above\n"
        f"  - Tier 1 = score >= 8, Tier 2 = score >= 5, Tier 3 = score < 5\n"
        f"  - tier_reason: 2 factual sentences citing the top factors\n\n"
        f"Respond ONLY with valid JSON, no markdown, no explanation:\n"
        f'{{"score": <int>, "tier": "<1|2|3>", "tier_reason": "<string>"}}'
    )
    raw = llm.call(prompt)
    try:
        llm_result = json.loads(raw)
        asset["score"]       = llm_result["score"]
        asset["tier"]        = str(llm_result["tier"])
        asset["tier_reason"] = llm_result["tier_reason"]
    except (json.JSONDecodeError, KeyError):
        asset["score"]       = 0
        asset["tier"]        = "unknown"
        asset["tier_reason"] = raw  # fallback: store raw response
    asset["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    print(f"      -> Score: {asset['score']}/10, Tier: {asset['tier']}")
    print("Done.\n")
    return asset

# Run it
result = run_agent("3.6.159.186", "medium", "public", "itadmin@acme.com")
print(json.dumps(result, indent=2))
