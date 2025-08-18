import io
import pandas as pd
import numpy as np
from typing import Dict, Any
from datetime import datetime
import streamlit as st


def determine_severity_score(result: Dict[str, Any]) -> str:
    """Severity: 1-Critical, 2-High, 3-Medium, 4-Low"""
    sev_labels = ["4-Low", "4-Low", "3-Medium", "2-High", "1-Critical"]

    def trurisk_adj(base, trurisk):
        if not trurisk:
            return base
        if trurisk >= 800 and not base.startswith(("1-", "2-")):
            return "2-High"
        if trurisk >= 600 and base.startswith("4-"):
            return "3-Medium"
        return base

    if result.get("cve_results"):
        max_score = max(c.score for c in result["cve_results"])
        base = (
            "1-Critical"
            if max_score >= 9
            else (
                "2-High"
                if max_score >= 7
                else "3-Medium" if max_score >= 4 else "4-Low"
            )
        )
        return trurisk_adj(base, result["original_data"].get("TruRisk Score"))

    severity = result["original_data"].get("Severity")
    if not severity:
        return "Unknown"
    base = sev_labels[min(max(int(severity), 1), 5) - 1]
    return trurisk_adj(base, result["original_data"].get("TruRisk Score"))


def get_days_diff(start_str: str, end_str: str) -> int:
    fmt = "%m-%d-%Y %H:%M"
    try:
        return (
            datetime.strptime(end_str, fmt) - datetime.strptime(start_str, fmt)
        ).days
    except:
        return 0


def is_nan(value):
    """Check if value is NaN/None/empty in a pandas-compatible way"""
    if value is None:
        return True
    if isinstance(value, float) and np.isnan(value):
        return True
    if isinstance(value, str) and value.lower() in ["nan", "none", ""]:
        return True
    return False


def clean_value(value, default=""):
    """Convert any NaN/None values to default"""
    return default if is_nan(value) else str(value)


def simplify_date(date):
    """Convert date string with robust NaN/None handling"""
    if is_nan(date):
        return ""
    try:
        # Handle multiple date formats
        for fmt in ("%m-%d-%Y %H:%M", "%m/%d/%Y %H:%M"):
            try:
                dt_obj = datetime.strptime(str(date), fmt)
                return f"{dt_obj.strftime('%B')} {dt_obj.day}, {dt_obj.year}"
            except ValueError:
                continue
        return str(date)  # Return original if no format matched
    except (ValueError, TypeError):
        return ""


def determine_sla_status(severity_score: str, vulnerability_age: int) -> str:
    """Determine SLA status based on severity and age thresholds"""
    thresholds = {
        "5-": ("Critical", 7),
        "4-": ("High", 14),
        "3-": ("Medium", 30),
        "2-": ("Low", 90),
    }

    for prefix, (level, days) in thresholds.items():
        if severity_score.startswith(prefix):
            status = "Breached" if vulnerability_age > days else "Within SLA"
            return status

    return "N/A - Needs Assessment"


def export_results_to_excel(processed_data: Dict[str, Any]) -> io.BytesIO:
    """Export with original report data included with robust NaN/None handling"""
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        # Enhanced detailed results with original data
        detailed_rows = []

        for result in processed_data.get("results", []):
            original_data = result.get("original_data", {})
            vulnerability_age = get_days_diff(
                clean_value(original_data.get("First Detected")),
                clean_value(original_data.get("Last Detected")),
            )
            severity_score = determine_severity_score(result)

            base_row = {
                "Asset Id": clean_value(original_data.get("Asset ID")),
                "Asset Name": clean_value(original_data.get("DNS")),
                "Asset IPV4": clean_value(original_data.get("IP")),
                "Operating System": clean_value(original_data.get("OS")),
                "QID": clean_value(original_data.get("QID")),
                "Title": clean_value(original_data.get("Title")),
                "Severity": clean_value(original_data.get("Severity")),
                "KB Severity": "",
                "Type Detected": (
                    "Confirmed"
                    if str(original_data.get("Type", "")).lower() == "vuln"
                    else "Potential"
                ),
                "First Detected": simplify_date(
                    clean_value(original_data.get("First Detected"))
                ),
                "Last Detected": simplify_date(
                    clean_value(original_data.get("Last Detected"))
                ),
                "Protocol": clean_value(original_data.get("Protocol"), "-"),
                "Port": clean_value(original_data.get("Port"), "0"),
                "Solution": clean_value(original_data.get("Solution")),
                "Asset Tags": clean_value(original_data.get("Associated Tags")),
                "Category": clean_value(original_data.get("Category")),
                "RTI": "",
                "Last Reopened": clean_value(original_data.get("Last Reopened")),
                "Times Detected": clean_value(original_data.get("Times Detected")),
                "Threat": clean_value(original_data.get("Threat")),
                "Vulnerability Tags": "",
                "QVS Score": "",
                "Detection AGE": vulnerability_age,
                "TruRisk Score": clean_value(original_data.get("TruRisk Score")),
                "Results": clean_value(original_data.get("Results")),
                "Vulnerability Status": "",
                "Vulnerability Age": vulnerability_age,
                "Vulnerability Category": "",
                "SLA Status": determine_sla_status(
                    severity_score,
                    vulnerability_age,
                ),
                "Remediation Marks": "",
                "Avg CVSS Score": round(
                    float(clean_value(result.get("avg_cvss_score"), "0")), 2
                ),
                "Highest CVSS Score": round(
                    float(clean_value(result.get("highest_score"), "0")), 2
                ),
            }

            cve_results = result.get("cve_results", [])
            if cve_results:
                for i, cve in enumerate(cve_results, 1):
                    row = base_row.copy()
                    row.update(
                        {
                            "CVE": clean_value(getattr(cve, "cve_id", "")),
                            "Published Date": simplify_date(
                                clean_value(getattr(cve, "published_date", ""))
                            ),
                            "Patch Released": simplify_date(
                                clean_value(getattr(cve, "modified_date", ""))
                            ),
                            "Asset Critical Score": severity_score,
                            "Severity Score": severity_score,
                            "CVE_CVSS_Score": round(
                                float(clean_value(getattr(cve, "score", "0"))), 2
                            ),
                            "CVE_Severity": clean_value(getattr(cve, "severity", "")),
                            "CVE_Description": clean_value(
                                getattr(cve, "description", "")
                            ),
                            "CVE_Vector_String": clean_value(
                                getattr(cve, "vector_string", "")
                            ),
                            "CVE_CWE_Info": (
                                ", ".join(
                                    map(
                                        str,
                                        filter(
                                            lambda x: not is_nan(x),
                                            getattr(cve, "cwe_info", []),
                                        ),
                                    )
                                )
                                if getattr(cve, "cwe_info", [])
                                else ""
                            ),
                            "CVE_Affected_Products": (
                                ", ".join(
                                    map(
                                        str,
                                        filter(
                                            lambda x: not is_nan(x),
                                            getattr(cve, "affected_products", [])[:5],
                                        ),
                                    )
                                )
                                if getattr(cve, "affected_products", [])
                                else ""
                            ),
                        }
                    )
                    detailed_rows.append(row)
            else:
                detailed_rows.append(base_row)

        # Convert to DataFrame and clean any remaining NaN values
        df = pd.DataFrame(detailed_rows)
        df = df.fillna("").replace([np.nan], [""])

        df.to_excel(writer, sheet_name="Complete_Analysis", index=False)

    output.seek(0)
    return output
