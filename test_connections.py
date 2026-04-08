"""
Test all exploit_search components against a known CVE.
Run: python test_connections.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from exploit_search.github_search      import search as github_search
from exploit_search.exploitdb_search   import search as exploitdb_search
from exploit_search.vulners_search     import search as circl_search      # now CIRCL
from exploit_search.packetstorm_search import search as osv_search, nvd_enrich  # now OSV

TEST_CVE = "CVE-2021-44228"
SEP = "=" * 60


def run(label, fn, *args):
    print(f"\n{SEP}\n  {label}\n{SEP}")
    try:
        result = fn(*args)
        if isinstance(result, list):
            print(f"  Results : {len(result)}")
            for i, r in enumerate(result[:3], 1):
                print(f"  [{i}] {str(r.get('name', ''))[:60]}  |  stars={r.get('stars', 0)}")
        elif isinstance(result, dict):
            print(f"  CVSS    : {result.get('cvss_v3_score')}  severity={result.get('severity')}")
            print(f"  Desc    : {str(result.get('description', ''))[:100]}")
        return result
    except Exception as e:
        print(f"  ERROR   : {e}")
        return None


if __name__ == "__main__":
    print(f"\nTesting exploit_search components for {TEST_CVE}")

    run("NVD Enrich",       nvd_enrich,    TEST_CVE)
    run("GitHub Search",    github_search, TEST_CVE)
    run("ExploitDB Search", exploitdb_search, TEST_CVE)
    run("CIRCL Search",     circl_search,  TEST_CVE)
    run("OSV Search",       osv_search,    TEST_CVE)

    print(f"\n{SEP}\n  DONE\n{SEP}")
