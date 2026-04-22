import io
import json
import asyncio
import logging
import threading
import traceback
import pandas as pd
from datetime import datetime, timezone
from crewai import Agent, Task, Crew, Process
from backend.db.client import get_db
from backend.services.qualys_service import query_by_qids
from backend.services.exploit_service import run_exploit_agent
from backend.db.queries import upsert_cve_exploitability, get_cve_exploitability, get_asset_criticality_by_ip
from main_config.llm_manager import get_master_llm, get_next_llm, _is_rate_limit_error, GROQ_API_KEYS, GEMINI_API_KEYS, GROQ_MODELS, GEMINI_MODELS, USE_GROQ, USE_GEMINI

logger = logging.getLogger(__name__)


# ── Column map: Excel header → internal key ────────────────────────────────────

_COL_MAP = {
    "cve":                   "cve",
    "cve-description":       "cve_description",
    "cvssv2_base_(nvd)":     "cvss_v2",
    "cvssv3.1_base_(nvd)":   "cvss_v3",
    "qid":                   "qid",
    "title":                 "title",
    "severity":              "severity",
    "kb_severity":           "kb_severity",
    "type_detected":         "type_detected",
    "last_detected":         "last_detected",
    "first_detected":        "first_detected",
    "protocol":              "protocol",
    "port":                  "port",
    "status":                "vuln_status",
    "asset_id":              "asset_id",
    "asset_name":            "asset_name",
    "asset_ipv4":            "asset_ipv4",
    "asset_ipv6":            "asset_ipv6",
    "solution":              "solution",
    "asset_tags":            "asset_tags",
    "disabled":              "disabled",
    "ignored":               "ignored",
    "qvs_score":             "qvs_score",
    "detection_age":         "detection_age",
    "published_date":        "published_date",
    "patch_released":        "patch_released",
    "category":              "category",
    "cvss_rating_labels":    "cvss_rating_label",
    "rti":                   "rti",
    "operating_system":      "operating_system",
    "last_fixed":            "last_fixed",
    "last_reopened":         "last_reopened",
    "times_detected":        "times_detected",
    "threat":                "threat",
    "vuln_patchable":        "vuln_patchable",
    "asset_critical_score":  "asset_critical_score",
    "trurisk_score":         "trurisk_score",
    "vulnerability_tags":    "vulnerability_tags",
    "results":               "results",
}


def _clean(val, default=""):
    if val is None:
        return default
    s = str(val).strip()
    return default if s in ("", "'-", "nan", "None") else s


def _read_df(file_bytes: bytes, filename: str) -> pd.DataFrame:
    ext = filename.rsplit(".", 1)[-1].lower() if filename else ""
    if ext == "csv":
        df = pd.read_csv(io.BytesIO(file_bytes))
    elif ext == "xls":
        df = pd.read_excel(io.BytesIO(file_bytes), engine="xlrd")
    else:
        try:
            df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")
        except Exception:
            df = pd.read_csv(io.BytesIO(file_bytes))

    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    df = df.rename(columns=_COL_MAP)
    return df


def _row_to_dict(row: pd.Series) -> dict:
    return {key: _clean(row.get(key)) for key in _COL_MAP.values()}


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _create_qualys_session(filename: str, total_rows: int, scan_name: str) -> dict:
    db = get_db()
    res = db.table("qualys_scans").insert({
        "filename":   filename,
        "scan_name":  scan_name or filename,
        "total_rows": total_rows,
        "status":     "processing",
    }).execute()
    return res.data[0]


def _create_qualys_rows(scan_id: str, rows: list[dict]) -> list[dict]:
    db = get_db()
    payload = [
        {
            "scan_id":    scan_id,
            "row_index":  r["row_index"],
            "status":     "pending",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        for r in rows
    ]
    res = db.table("qualys_scan_rows").insert(payload).execute()
    return res.data


def _update_qualys_row_result(row_id: str, result: dict) -> None:
    db = get_db()
    db.table("qualys_scan_rows").update({
        "status":     "done",
        "result":     result,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row_id).execute()


def _update_qualys_row_error(row_id: str, error: str) -> None:
    db = get_db()
    db.table("qualys_scan_rows").update({
        "status":     "error",
        "result":     {"error": error},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", row_id).execute()


def _update_qualys_session_status(scan_id: str, status: str) -> None:
    db = get_db()
    update: dict = {"status": status}
    if status == "done":
        update["completed_at"] = datetime.now(timezone.utc).isoformat()
    db.table("qualys_scans").update(update).eq("id", scan_id).execute()


# ── Main processor ─────────────────────────────────────────────────────────────

async def process_qualys_excel(job_id: str, file_bytes: bytes, filename: str = "", scan_name: str = "") -> str:
    df = _read_df(file_bytes, filename)
    total = len(df)

    session = _create_qualys_session(filename, total, scan_name)
    scan_id = session["id"]

    rows_payload = [{"row_index": int(idx), "data": _row_to_dict(row)} for idx, row in df.iterrows()]

    db_rows = _create_qualys_rows(scan_id, rows_payload)
    row_id_map = {r["row_index"]: r["id"] for r in db_rows}

    # ── Fetch KB data for all unique QIDs in one batch ─────────────────────────
    unique_qids = list({
        int(r["data"]["qid"])
        for r in rows_payload
        if r["data"].get("qid") and str(r["data"]["qid"]).isdigit()
    })
    kb_map: dict[str, dict] = {}
    if unique_qids:
        try:
            kb_results = await asyncio.to_thread(query_by_qids, unique_qids)
            kb_map = {str(kb["qid"]): kb for kb in kb_results if kb.get("qid")}
        except Exception:
            pass  # KB enrichment is best-effort; don't fail the whole scan

    # ── Analyse exploitability for all unique CVEs in one batch ────────────────
    # Prefer CVE IDs from KB results (cve_ids list); fall back to Excel cve column
    unique_cves: set[str] = set()
    for r in rows_payload:
        qid_key = str(r["data"].get("qid", ""))
        kb = kb_map.get(qid_key)
        if kb and kb.get("cve_ids"):
            for cid in kb["cve_ids"]:
                if cid.upper().startswith("CVE-"):
                    unique_cves.add(cid.upper())
        elif r["data"].get("cve") and r["data"]["cve"].upper().startswith("CVE-"):
            unique_cves.add(r["data"]["cve"].upper())
    exploit_map: dict[str, dict] = {}
    for cve_id in unique_cves:
        try:
            cached = get_cve_exploitability(cve_id)
            if cached:
                exploit_map[cve_id.upper()] = cached["result"]
            else:
                result_ex = await asyncio.to_thread(run_exploit_agent, cve_id)
                upsert_cve_exploitability(cve_id, result_ex)
                exploit_map[cve_id.upper()] = result_ex
        except Exception:
            pass  # exploit enrichment is best-effort; don't fail the whole scan

    # ── Fetch asset criticality for all unique IPs in one batch ───────────────
    unique_ips = {r["data"].get("asset_ipv4", "") for r in rows_payload if r["data"].get("asset_ipv4")}
    asset_map: dict[str, dict] = {}
    for ip in unique_ips:
        try:
            row_rec = await asyncio.to_thread(get_asset_criticality_by_ip, ip)
            if row_rec:
                asset_map[ip] = row_rec
        except Exception:
            pass

    async def _process_one(row_payload: dict):
        row_id = row_id_map[row_payload["row_index"]]
        try:
            result = dict(row_payload["data"])
            qid_key = str(result.get("qid", ""))
            kb = kb_map.get(qid_key)
            if kb:
                result["kb"] = kb

            cves_to_check = []
            if kb and kb.get("cve_ids"):
                cves_to_check.extend([c.upper() for c in kb["cve_ids"] if c.upper().startswith("CVE-")])
            elif result.get("cve") and result["cve"].upper().startswith("CVE-"):
                cves_to_check.append(result["cve"].upper())

            if cves_to_check:
                exploit = exploit_map.get(cves_to_check[0])
                if exploit:
                    result["exploit"] = exploit

            ip = result.get("asset_ipv4", "")
            if ip and ip in asset_map:
                result["asset_criticality"] = asset_map[ip]

            try:
                result["risk"] = await asyncio.to_thread(run_risk_agent, result)
            except Exception as risk_err:
                logger.error(f"[risk_agent] row {row_id} FAILED: {risk_err}\n{traceback.format_exc()}")
                result["risk"] = {"error": str(risk_err)}

            _update_qualys_row_result(row_id, result)
        except Exception as e:
            logger.error(f"[process_one] row {row_id} FAILED: {e}\n{traceback.format_exc()}")
            _update_qualys_row_error(row_id, str(e))

    await asyncio.gather(*[_process_one(r) for r in rows_payload])
    _update_qualys_session_status(scan_id, "done")
    return scan_id


# ── Risk Agent (CrewAI) ────────────────────────────────────────────────────────

def run_risk_agent(row: dict) -> dict:
    exploit = row.get("exploit") or {}
    kb      = row.get("kb") or {}
    asset   = row.get("asset_criticality") or {}
    asset_r = asset.get("result") or asset

    vuln = {
        "cve":                   row.get("cve", ""),
        "title":                 row.get("title", ""),
        "cvss_v3":               row.get("cvss_v3", ""),
        "cvss_v3_vector":        exploit.get("cvss_v3_vector", ""),
        "cvss_rating_label":     row.get("cvss_rating_label", ""),
        "cwe":                   exploit.get("cwe", []),
        "qvs_score":             row.get("qvs_score", ""),
        "trurisk_score":         row.get("trurisk_score", ""),
        "rti":                   row.get("rti", ""),
        "severity":              row.get("severity", ""),
        "vuln_status":           row.get("vuln_status", ""),
        "detection_age_days":    row.get("detection_age", ""),
        "first_detected":        row.get("first_detected", ""),
        "last_detected":         row.get("last_detected", ""),
        "times_detected":        row.get("times_detected", ""),
        "type_detected":         row.get("type_detected", ""),
        "vuln_patchable":        row.get("vuln_patchable", ""),
        "patch_released":        row.get("patch_released", ""),
        "port":                  row.get("port", ""),
        "protocol":              row.get("protocol", ""),
        "results_output":        row.get("results", ""),
        "threat":                row.get("threat", ""),
        "cve_description":       row.get("cve_description", ""),
        "kb_category":           kb.get("category", ""),
        "kb_vuln_type":          kb.get("vuln_type", ""),
        "kb_affected_software":  kb.get("affected_software", []),
        "kb_discovery_remote":   kb.get("discovery_remote", ""),
        "kb_patchable":          kb.get("patchable", ""),
        "kb_diagnosis":          kb.get("diagnosis", ""),
        "kb_consequence":        kb.get("consequence", ""),
    }

    exploit_signals = {
        "exploitability_score":   exploit.get("exploitability_score", ""),
        "exploitability_tier":    exploit.get("exploitability_tier", ""),
        "tier_label":             exploit.get("tier_label", ""),
        "exploit_maturity":       exploit.get("exploit_maturity", ""),
        "epss_estimate":          exploit.get("epss_estimate", ""),
        "exploit_count":          exploit.get("exploit_count", ""),
        "raw_exploit_count":      exploit.get("raw_exploit_count", ""),
        "raw_exploits_by_source": exploit.get("raw_exploits_by_source", {}),
        "has_metasploit":         exploit.get("has_metasploit", ""),
        "has_full_exploit":       exploit.get("has_full_exploit", ""),
        "in_the_wild":            exploit.get("in_the_wild", ""),
        "attack_complexity":      exploit.get("attack_complexity", ""),
        "patch_priority":         exploit.get("patch_priority", ""),
        "attacker_profile":       exploit.get("attacker_profile", ""),
        "most_dangerous_url":     exploit.get("most_dangerous_url", ""),
        "most_dangerous_notes":   exploit.get("most_dangerous_notes", ""),
        "analysis_notes":         exploit.get("analysis_notes", ""),
        "executive_summary":      exploit.get("executive_summary", ""),
        "mitigations":            exploit.get("mitigations", []),
        "affected_products":      exploit.get("affected_products", []),
        "sources_searched":       exploit.get("sources_searched", []),
        "unique_exploits": [
            {
                "name":          e.get("name", ""),
                "url":           e.get("url", ""),
                "source":        e.get("source", ""),
                "exploit_type":  e.get("exploit_type", ""),
                "reliability":   e.get("reliability", ""),
                "weaponization": e.get("weaponization", ""),
                "skill_required":e.get("skill_required", ""),
                "notes":         e.get("notes", ""),
            }
            for e in exploit.get("unique_exploits", [])
        ],
    }

    asset_signals = {
        "asset_ipv4":               row.get("asset_ipv4", ""),
        "asset_name":               row.get("asset_name", ""),
        "asset_tags":               row.get("asset_tags", ""),
        "asset_critical_score":     row.get("asset_critical_score", ""),
        "operating_system":         row.get("operating_system", ""),
        "criticality_score":        asset_r.get("score", ""),
        "criticality_tier":         asset_r.get("tier", ""),
        "criticality_tier_label":   asset_r.get("tier_label", ""),
        "baseline_criticality":     asset_r.get("baseline_criticality", ""),
        "environment":              asset_r.get("environment", ""),
        "data_classification":      asset_r.get("data_classification", ""),
        "internet_facing":          asset_r.get("internet_facing", ""),
        "confirmed_role":           asset_r.get("confirmed_role", ""),
        "declared_role":            asset_r.get("declared_role", ""),
        "role_mismatch":            asset_r.get("role_mismatch", ""),
        "mismatch_note":            asset_r.get("mismatch_note", ""),
        "role_confidence":          asset_r.get("role_confidence", ""),
        "role_reasoning":           asset_r.get("role_reasoning", ""),
        "open_ports":               asset_r.get("open_ports", []),
        "open_ports_count":         asset_r.get("open_ports_count", ""),
        "services":                 asset_r.get("services", []),
        "shodan_ports":             asset_r.get("shodan_ports", []),
        "shodan_vulns":             asset_r.get("shodan_vulns", []),
        "greynoise_classification": asset_r.get("greynoise_classification", ""),
        "abuse_confidence":         asset_r.get("abuse_confidence", ""),
        "abuse_reports":            asset_r.get("abuse_reports", ""),
        "is_known_scanner":         asset_r.get("is_known_scanner", ""),
        "threat_intel_summary":     asset_r.get("threat_intel_summary", ""),
        "asset_risk_factors":       asset_r.get("risk_factors", []),
        "asset_summary":            asset_r.get("summary", ""),
    }

    data_block = (
        f"VULNERABILITY:\n{json.dumps(vuln, indent=2)}\n\n"
        f"EXPLOIT INTELLIGENCE:\n{json.dumps(exploit_signals, indent=2)}\n\n"
        f"ASSET CRITICALITY:\n{json.dumps(asset_signals, indent=2)}"
    )

    def _build_crew(llm):
        analyst = Agent(
            role="Senior Threat Analyst",
            goal="Produce a deeply correlated risk assessment by reasoning across vulnerability, exploit, and asset data together.",
            backstory=(
                "You are a senior threat analyst with 15 years of experience. "
                "You never summarise data in isolation. You always look for what the data means "
                "when read together — contradictions, compounding factors, and non-obvious insights "
                "that only emerge from cross-referencing all sources."
            ),
            llm=llm,
            verbose=False,
        )
        task_understand = Task(
            description=(
                f"Read the following security data carefully.\n\n{data_block}\n\n"
                "Deeply understand what each data block is telling you individually. "
                "Note every signal — scores, timelines, roles, exploit details, asset context. "
                "Do not draw conclusions yet. Just build a complete mental model of the data."
            ),
            expected_output="A thorough understanding of all signals across the three data blocks, written as structured observations.",
            agent=analyst,
        )
        task_correlate = Task(
            description=(
                "Using your observations from the previous task, now correlate across all three data blocks. "
                "Find: what signals contradict each other, what signals compound each other, "
                "what the exploit landscape means specifically for this asset in this environment, "
                "and what a human analyst would miss reading each report separately. "
                "Think freely — do not follow a checklist. Reason like an expert."
            ),
            expected_output="A set of correlated findings — contradictions, compounding risks, and non-obvious insights derived from cross-referencing all three data blocks.",
            agent=analyst,
            context=[task_understand],
        )
        task_output = Task(
            description=(
                "Using your correlated findings, produce the final risk assessment. "
                "Return ONLY valid JSON with no extra text:\n"
                "{\n"
                '  "risk_score": <float 0-10, derived from your full analysis — not just CVSS>,\n'
                '  "risk_label": <"Critical"|"High"|"Medium"|"Low">,\n'
                '  "risk_summary": <string — your correlated insight, not a field summary>,\n'
                '  "asset_domain": <string>,\n'
                '  "urgency": <"Immediate"|"High"|"Medium"|"Low">,\n'
                '  "risk_factors": [<each item must connect signals from at least two different data blocks>],\n'
                '  "evidences": [<string>, ...]\n'
                "}"
            ),
            expected_output="Valid JSON risk assessment object.",
            agent=analyst,
            context=[task_correlate],
        )
        return Crew(
            agents=[analyst],
            tasks=[task_understand, task_correlate, task_output],
            process=Process.sequential,
            verbose=False,
        )

    total_attempts = (len(GROQ_API_KEYS) * len(GROQ_MODELS) if USE_GROQ else 0) + \
                     (len(GEMINI_API_KEYS) * len(GEMINI_MODELS) if USE_GEMINI else 0)
    prefer_groq = True

    for attempt in range(max(total_attempts, 1)):
        llm, provider = get_master_llm(temperature=0.3, prefer_groq=prefer_groq)
        result_holder: dict = {}

        def _run(crew=_build_crew(llm)):
            try:
                result_holder["raw"] = crew.kickoff()
            except Exception as e:
                result_holder["error"] = e

        t = threading.Thread(target=_run)
        t.start()
        t.join(timeout=300)

        if "error" not in result_holder:
            break

        err = result_holder["error"]
        if _is_rate_limit_error(err):
            logger.warning(f"[risk_agent] Rate limit on {provider} (attempt {attempt+1}/{total_attempts}) — rotating...")
            try:
                _, next_provider = get_next_llm(temperature=0.3, prefer_groq=prefer_groq)
                prefer_groq = (next_provider == "groq")
            except RuntimeError:
                raise RuntimeError(str(err))
        else:
            raise RuntimeError(str(err))
    else:
        if "error" in result_holder:
            raise RuntimeError(str(result_holder["error"]))

    raw_str = str(result_holder.get("raw", ""))
    try:
        start = raw_str.find("{")
        end   = raw_str.rfind("}") + 1
        return json.loads(raw_str[start:end])
    except Exception:
        return {"risk_summary": raw_str.strip()}
