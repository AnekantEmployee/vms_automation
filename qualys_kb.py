import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))

from backend.services.qualys_service import query_by_qids


if __name__ == "__main__":
    raw = input("Enter QIDs (comma-separated): ")
    qids = [int(q.strip()) for q in raw.split(",") if q.strip()]
    vulns = query_by_qids(qids)
    for v in vulns:
        print(f"  QID {v['qid']} | Sev {v['severity']} | {v['title'][:70]}")
        if v["cve_id"]:
            print(f"         CVEs: {v['cve_id']}")
        if v["threat_intel"]:
            print(f"         RTI:  {v['threat_intel']}")
