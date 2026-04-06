import os
from dotenv import load_dotenv
import nmap, nvdlib, shodan, json
from datetime import datetime, timedelta
from main_config.llm_manager import get_master_llm

load_dotenv()

SHODAN_KEY = os.getenv("SHODAN_API_KEY")  # from shodan.io

def run_agent(ip, business_criticality, data_classification, owner):

    asset = {
        "ip": ip,
        "business_criticality": business_criticality,
        "data_classification": data_classification,
        "owner": owner,
    }

    # Step 2 — Nmap
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-sV -O --open -T4")
    h = nm[ip]
    asset["hostname"]        = nm.command_line()
    asset["os"]              = h["osmatch"][0]["name"] if h.get("osmatch") else "unknown"
    asset["open_ports_count"] = len(h.get("tcp", {}))
    asset["services"]        = [h["tcp"][p]["name"] for p in h.get("tcp", {})]

    # Step 3 — NVD CVE lookup
    one_year_ago = datetime.now() - timedelta(days=365)
    cves = []
    for svc in asset["services"]:
        cves += nvdlib.searchCVE(keywordSearch=svc, pubStartDate=one_year_ago, limit=10)
    scores = [c.score[1] for c in cves if c.score]
    asset["max_cvss"]          = max(scores, default=0)
    asset["critical_cve_count"] = sum(1 for c in cves if c.score and c.score[1] >= 9.0)

    # Step 4 — Shodan
    try:
        s = shodan.Shodan(SHODAN_KEY).host(ip)
        asset["internet_facing"] = True
    except:
        asset["internet_facing"] = False

    # Step 5 — Score
    score = 0
    if asset["max_cvss"] >= 9.0:  score += 3
    elif asset["max_cvss"] >= 7.0: score += 2
    elif asset["max_cvss"] >= 4.0: score += 1
    if asset["internet_facing"]:   score += 2
    if business_criticality == "high":   score += 2
    elif business_criticality == "medium": score += 1
    if data_classification in ["pii","financial"]: score += 2
    elif data_classification == "internal":        score += 1
    if asset["open_ports_count"] > 10: score += 1
    asset["score"] = score
    asset["tier"]  = "1" if score >= 8 else "2" if score >= 5 else "3"

    # Step 6 — LLM reason
    llm, _ = get_master_llm(probe=False)
    prompt = (
        f"Asset {ip}, OS: {asset['os']}, internet-facing: {asset['internet_facing']}, "
        f"services: {asset['services']}, max CVSS: {asset['max_cvss']}, "
        f"critical CVEs: {asset['critical_cve_count']}, business: {business_criticality}, "
        f"data: {data_classification}, score: {score}/10, tier: {asset['tier']}. "
        f"Write 2 sentences explaining why this tier. Cite top factors. Be factual."
    )
    asset["tier_reason"] = llm.call(prompt)
    asset["scanned_at"]   = datetime.utcnow().isoformat() + "Z"

    return asset

# Run it
result = run_agent("192.168.1.45", "high", "pii", "payments@acme.com")
print(json.dumps(result, indent=2))