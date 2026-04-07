"""
cve_lookup.py — Fetch recent CVEs for discovered services via NIST NVD (nvdlib).

Strategy:
  - For each unique service name found by nmap, search NVD for CVEs in the last 12 months.
  - Also search using OS name if available.
  - Deduplicate by CVE ID.
  - Return aggregated stats + top CVEs by CVSS score.

Returns:
{
    "total_cves":         42,
    "critical_cves":      3,     # CVSS >= 9.0
    "high_cves":          8,     # CVSS 7.0-8.9
    "medium_cves":        18,
    "max_cvss":           9.8,
    "top_cves": [
        {"id": "CVE-2024-XXXX", "cvss": 9.8, "description": "..."},
        ...
    ],
}
"""

import nvdlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed


_LOOKBACK_DAYS  = 365
_CHUNK_DAYS     = 110   # NVD rejects date ranges > 120 days
_MAX_PER_QUERY  = 10
_MAX_WORKERS    = 5
_MAX_TOP_CVES   = 5


def _search(keyword: str) -> list:
    results, now = [], datetime.now().replace(microsecond=0)
    end = now
    start = now - timedelta(days=_LOOKBACK_DAYS)
    while start < end:
        chunk_end   = min(start + timedelta(days=_CHUNK_DAYS), end)
        try:
            results += nvdlib.searchCVE(
                keywordSearch=keyword,
                pubStartDate=start,
                pubEndDate=chunk_end,
                limit=_MAX_PER_QUERY,
            )
        except Exception as e:
            print(f"[cve] Skipping '{keyword}' chunk {start.date()}–{chunk_end.date()}: {e}")
        start = chunk_end
    return results


def run_cve_lookup(services: list[str], os_name: str = "") -> dict:
    # Build unique keyword set: services + OS (skip generic/useless terms)
    skip = {"unknown", "", "tcpwrapped"}
    keywords = {s for s in services if s.lower() not in skip}
    if os_name and os_name.lower() not in skip:
        # Take just the OS family to avoid overly specific queries
        os_family = os_name.split()[0] if os_name else ""
        if os_family:
            keywords.add(os_family)

    if not keywords:
        print("[cve] No searchable keywords — skipping CVE lookup")
        return _empty()

    print(f"[cve] Searching CVEs for: {sorted(keywords)} ...")

    raw_cves: dict[str, object] = {}  # CVE-ID → cve object (dedup)
    with ThreadPoolExecutor(max_workers=min(len(keywords), _MAX_WORKERS)) as ex:
        futures = {ex.submit(_search, kw): kw for kw in keywords}
        for future in as_completed(futures):
            for cve in future.result():
                raw_cves[cve.id] = cve

    # --- aggregate ---
    critical = high = medium = low = 0
    max_cvss = 0.0
    top: list[dict] = []

    for cve in raw_cves.values():
        score = cve.score[1] if cve.score else None
        if score is None:
            continue
        max_cvss = max(max_cvss, score)
        if score >= 9.0:
            critical += 1
        elif score >= 7.0:
            high += 1
        elif score >= 4.0:
            medium += 1
        else:
            low += 1

        desc = ""
        try:
            desc = cve.descriptions[0].value[:200] if cve.descriptions else ""
        except Exception:
            pass

        top.append({"id": cve.id, "cvss": score, "description": desc})

    top.sort(key=lambda x: x["cvss"], reverse=True)

    result = {
        "total_cves":   len(raw_cves),
        "critical_cves": critical,
        "high_cves":    high,
        "medium_cves":  medium,
        "low_cves":     low,
        "max_cvss":     round(max_cvss, 1),
        "top_cves":     top[:_MAX_TOP_CVES],
    }
    print(
        f"[cve] Done → {result['total_cves']} CVEs  "
        f"(critical={critical}, high={high}, max_cvss={max_cvss})"
    )
    return result


def _empty() -> dict:
    return {
        "total_cves": 0, "critical_cves": 0, "high_cves": 0,
        "medium_cves": 0, "low_cves": 0, "max_cvss": 0.0, "top_cves": [],
    }