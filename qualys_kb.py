import requests
import xml.etree.ElementTree as ET
import os
from dotenv import load_dotenv

load_dotenv()

QUALYS_BASE_URL = os.getenv("QUALYS_BASE_URL", "qualysguard.qg1.apps.qualys.in")
USERNAME        = os.getenv("QUALYS_USERNAME")
PASSWORD        = os.getenv("QUALYS_PASSWORD")

BASE_URL = f"https://{QUALYS_BASE_URL}/api/2.0/fo/knowledge_base/vuln/"
HEADERS  = {
    "X-Requested-With": "Python-Demo",
    "Content-Type": "application/x-www-form-urlencoded",
}
AUTH = (USERNAME, PASSWORD)


def kb_request(params: dict) -> ET.Element:
    params["action"] = "list"
    try:
        response = requests.post(BASE_URL, headers=HEADERS, auth=AUTH, data=params, stream=True, timeout=300)
    except requests.exceptions.ConnectionError:
        raise SystemExit(f"[ERROR] Could not connect to '{QUALYS_BASE_URL}'.")
    except requests.exceptions.Timeout:
        raise SystemExit("[ERROR] Request timed out.")

    if not response.ok:
        try:
            root = ET.fromstring(response.content)
            code = root.findtext(".//CODE") or str(response.status_code)
            text = root.findtext(".//TEXT") or "No details returned."
            raise SystemExit(f"[Qualys API Error {code}] {text}\n  HTTP status: {response.status_code} {response.reason}")
        except ET.ParseError:
            raise SystemExit(f"[HTTP {response.status_code} {response.reason}] {response.text[:500]}")

    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as e:
        raise SystemExit(f"[ERROR] Could not parse XML: {e}")

    api_error = root.find(".//API_ERROR") or root.find(".//SIMPLE_RETURN/RESPONSE")
    if api_error is not None:
        code = api_error.findtext("CODE") or "?"
        text = api_error.findtext("TEXT") or "Unknown API error"
        raise SystemExit(f"[Qualys API Error {code}] {text}")

    return root


def parse_vulns(root: ET.Element) -> list[dict]:
    vulns = []
    for vuln in root.findall(".//VULN"):
        def get(tag):
            el = vuln.find(tag)
            return el.text.strip() if el is not None and el.text else ""

        record = {
            "qid":           get("QID"),
            "vuln_type":     get("VULN_TYPE"),
            "severity":      get("SEVERITY_LEVEL"),
            "title":         get("TITLE"),
            "category":      get("CATEGORY"),
            "patchable":     get("PATCHABLE"),
            "published":     get("PUBLISHED_DATETIME"),
            "last_modified": get("LAST_SERVICE_MODIFICATION_DATETIME"),
            "cvss_base":     get("CVSS/BASE"),
            "cvss3_base":    get("CVSS_V3/BASE"),
            "cve_id":        ", ".join([c.text for c in vuln.findall(".//CVE_ID") if c.text]),
        }
        rtis = [ti.find("LABEL").text for ti in vuln.findall(".//THREAT_INTELLIGENCE/THREAT_INTEL")
                if ti.find("LABEL") is not None]
        record["threat_intel"] = ", ".join(rtis)
        vulns.append(record)
    return vulns


def query_by_qids(qids: list[int]) -> list[dict]:
    print(f"Fetching details for QIDs: {qids}")
    root = kb_request({"ids": ",".join(str(q) for q in qids), "details": "All"})
    vulns = parse_vulns(root)
    for v in vulns:
        print(f"  QID {v['qid']} | Sev {v['severity']} | {v['title'][:70]}")
        if v["cve_id"]:
            print(f"         CVEs: {v['cve_id']}")
        if v["threat_intel"]:
            print(f"         RTI:  {v['threat_intel']}")
    return vulns


if __name__ == "__main__":
    raw = input("Enter QIDs (comma-separated): ")
    qids = [int(q.strip()) for q in raw.split(",") if q.strip()]
    query_by_qids(qids)
