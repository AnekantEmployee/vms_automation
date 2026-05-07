import json
import logging
import threading
import traceback
from crewai import Agent, Task, Crew, Process
from main_config.llm_manager import (
    get_master_llm, get_next_llm, _is_rate_limit_error,
    GROQ_API_KEYS, GEMINI_API_KEYS, GROQ_MODELS, GEMINI_MODELS,
    USE_GROQ, USE_GEMINI,
)

logger = logging.getLogger(__name__)


def run_attack_chain_agent(ip: str, rows: list[dict]) -> dict:
    """
    Given an IP and all its qualys rows (each with a populated `result` dict
    including `risk`, `exploit`, `kb`, `asset_criticality`), produce a
    correlated attack chain analysis.
    """

    # ── Build a compact summary of each vulnerability for the prompt ──────────
    vuln_summaries = []
    for i, row in enumerate(rows):
        r = row.get("result") or {}
        risk = r.get("risk") or {}
        exploit = r.get("exploit") or {}
        vuln_summaries.append({
            "index":               i + 1,
            "cve":                 r.get("cve", ""),
            "title":               r.get("title", ""),
            "severity":            r.get("severity", ""),
            "cvss_v3":             r.get("cvss_v3", ""),
            "port":                r.get("port", ""),
            "protocol":            r.get("protocol", ""),
            "vuln_status":         r.get("vuln_status", ""),
            "first_detected":      r.get("first_detected", ""),
            "last_detected":       r.get("last_detected", ""),
            "operating_system":    r.get("operating_system", ""),
            "risk_score":          risk.get("risk_score", ""),
            "risk_label":          risk.get("risk_label", ""),
            "urgency":             risk.get("urgency", ""),
            "risk_summary":        risk.get("risk_summary", ""),
            "risk_factors":        risk.get("risk_factors", []),
            "rti_validated":       risk.get("rti_validated", ""),
            "real_exploit_count":  risk.get("real_exploit_count", 0),
            "exploitability_score":exploit.get("exploitability_score", ""),
            "exploit_maturity":    exploit.get("exploit_maturity", ""),
            "has_metasploit":      exploit.get("has_metasploit", False),
            "has_full_exploit":    exploit.get("has_full_exploit", False),
            "in_the_wild":         exploit.get("in_the_wild", False),
            "attack_complexity":   exploit.get("attack_complexity", ""),
            "most_dangerous_url":  exploit.get("most_dangerous_url", ""),
        })

    # Pull asset context from the first row that has it
    asset_context = {}
    for row in rows:
        r = row.get("result") or {}
        ac = r.get("asset_criticality") or {}
        asset_r = ac.get("result") or ac
        if asset_r:
            asset_context = {
                "ip":                   ip,
                "asset_name":           r.get("asset_name", ""),
                "operating_system":     r.get("operating_system", ""),
                "asset_tags":           r.get("asset_tags", ""),
                "criticality_score":    asset_r.get("score", ""),
                "criticality_tier":     asset_r.get("tier", ""),
                "environment":          asset_r.get("environment", ""),
                "data_classification":  asset_r.get("data_classification", ""),
                "internet_facing":      asset_r.get("internet_facing", ""),
                "confirmed_role":       asset_r.get("confirmed_role", ""),
                "open_ports":           asset_r.get("open_ports", []),
                "services":             asset_r.get("services", []),
                "greynoise_classification": asset_r.get("greynoise_classification", ""),
                "abuse_confidence":     asset_r.get("abuse_confidence", ""),
                "threat_intel_summary": asset_r.get("threat_intel_summary", ""),
            }
            break

    if not asset_context:
        asset_context = {"ip": ip}

    data_block = (
        f"TARGET ASSET:\n{json.dumps(asset_context, indent=2)}\n\n"
        f"VULNERABILITIES ({len(vuln_summaries)} total):\n"
        f"{json.dumps(vuln_summaries, indent=2)}"
    )

    output_schema = (
        "Return ONLY valid JSON, no extra text:\n"
        "{\n"
        '  "asset_ip": "<string>",\n'
        '  "asset_summary": "<string — one paragraph about this asset and its overall exposure>",\n'
        '  "overall_risk_score": <float 0-10>,\n'
        '  "overall_risk_label": <"Critical"|"High"|"Medium"|"Low">,\n'
        '  "attack_chain": [\n'
        "    {\n"
        '      "step": <int — ordered position in the chain>,\n'
        '      "phase": <"Reconnaissance"|"Initial Access"|"Execution"|"Persistence"|"Privilege Escalation"|"Lateral Movement"|"Exfiltration"|"Impact">,\n'
        '      "cve": "<string or empty>",\n'
        '      "title": "<string>",\n'
        '      "description": "<string — what the attacker does at this step and why this vuln enables it>",\n'
        '      "depends_on_steps": [<int>, ...],\n'
        '      "risk_score": <float>,\n'
        '      "exploitability": "<string>",\n'
        '      "chaining_insight": "<string — how this step unlocks or amplifies the next step>"\n'
        "    }\n"
        "  ],\n"
        '  "entry_points": ["<cve or title>", ...],\n'
        '  "critical_path": ["<step description>", ...],\n'
        '  "blast_radius": "<string — what an attacker achieves if the full chain executes>",\n'
        '  "top_priority_fixes": [\n'
        "    {\n"
        '      "cve": "<string>",\n'
        '      "title": "<string>",\n'
        '      "reason": "<string — why fixing this breaks the most chain steps>"\n'
        "    }\n"
        "  ],\n"
        '  "chain_summary": "<string — narrative of the full attack scenario>"\n'
        "}"
    )

    def _build_crew(llm):
        analyst = Agent(
            role="Adversarial Attack Chain Analyst",
            goal=(
                "Model how a real attacker would chain the given vulnerabilities "
                "on this specific asset to achieve maximum impact."
            ),
            backstory=(
                "You are an elite red team operator and threat modeller with 20 years of experience. "
                "You think like an attacker — you look for how vulnerabilities chain together, "
                "not just their individual scores. You understand that a low-CVSS vuln can be "
                "the critical first step that enables a Critical-CVSS exploit. "
                "You map everything to MITRE ATT&CK phases and reason about realistic attacker paths."
            ),
            llm=llm,
            verbose=False,
        )

        task_triage = Task(
            description=(
                f"Analyse the following asset and its vulnerabilities.\n\n{data_block}\n\n"
                "For each vulnerability, determine:\n"
                "1. Which MITRE ATT&CK phase it maps to\n"
                "2. Whether it can be used as an entry point (no prior access needed)\n"
                "3. What it enables after exploitation (privilege, persistence, lateral movement, etc.)\n"
                "4. Its real exploitability based on has_metasploit, has_full_exploit, in_the_wild, real_exploit_count\n"
                "5. Which other vulnerabilities it unlocks or amplifies\n"
                "Think about port/protocol context — a vuln on port 22 vs 443 vs 3389 has different chaining implications."
            ),
            expected_output=(
                "Per-vulnerability triage: ATT&CK phase, entry point status, "
                "post-exploitation capabilities, real exploitability, and chaining relationships."
            ),
            agent=analyst,
        )

        task_chain = Task(
            description=(
                "Using your triage, construct the most realistic and damaging attack chain. "
                "Order the steps as an attacker would execute them — from initial access through to impact. "
                "For each step, explain what the attacker does, which vulnerability they use, "
                "and critically — how completing this step enables or amplifies the next step. "
                "Identify the entry points (vulnerabilities exploitable with no prior access), "
                "the critical path (the sequence that leads to maximum damage), "
                "and the blast radius (what the attacker achieves if the full chain runs). "
                "Also identify the top 3 vulnerabilities to fix that would break the most chain steps."
            ),
            expected_output=(
                "A complete ordered attack chain with step-by-step attacker actions, "
                "chaining insights, entry points, critical path, blast radius, and top priority fixes."
            ),
            agent=analyst,
            context=[task_triage],
        )

        task_output = Task(
            description=f"Format your attack chain analysis as the following JSON schema.\n\n{output_schema}",
            expected_output="Valid JSON attack chain object.",
            agent=analyst,
            context=[task_chain],
        )

        return Crew(
            agents=[analyst],
            tasks=[task_triage, task_chain, task_output],
            process=Process.sequential,
            verbose=False,
        )

    total_attempts = (
        (len(GROQ_API_KEYS) * len(GROQ_MODELS) if USE_GROQ else 0) +
        (len(GEMINI_API_KEYS) * len(GEMINI_MODELS) if USE_GEMINI else 0)
    )
    prefer_groq = True
    result_holder: dict = {}

    for attempt in range(max(total_attempts, 1)):
        llm, provider = get_master_llm(temperature=0.3, prefer_groq=prefer_groq)
        result_holder = {}

        def _run(crew=_build_crew(llm)):
            try:
                result_holder["raw"] = crew.kickoff()
            except Exception as e:
                result_holder["error"] = e

        t = threading.Thread(target=_run)
        t.start()
        t.join(timeout=600)

        if "error" not in result_holder:
            break

        err = result_holder["error"]
        if _is_rate_limit_error(err):
            logger.warning(f"[attack_chain] Rate limit on {provider} (attempt {attempt+1}) — rotating...")
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
        end = raw_str.rfind("}") + 1
        return json.loads(raw_str[start:end])
    except Exception:
        return {"chain_summary": raw_str.strip()}
