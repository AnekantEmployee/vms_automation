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
        try:
            trurisk_val = float(trurisk) if not is_nan(trurisk) else 0
            if trurisk_val >= 800 and not base.startswith(("1-", "2-")):
                return "2-High"
            if trurisk_val >= 600 and base.startswith("4-"):
                return "3-Medium"
        except (ValueError, TypeError):
            pass
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
    if not severity or is_nan(severity):
        return "Unknown"
    
    try:
        severity_val = int(float(str(severity)))
        base = sev_labels[min(max(severity_val, 1), 5) - 1]
        return trurisk_adj(base, result["original_data"].get("TruRisk Score"))
    except (ValueError, TypeError):
        return "Unknown"


def get_days_diff(start_str: str, end_str: str) -> int:
    """Calculate days difference with robust error handling"""
    if not start_str or not end_str or is_nan(start_str) or is_nan(end_str):
        return 0
        
    fmt = "%m-%d-%Y %H:%M"
    alt_fmt = "%m/%d/%Y %H:%M"
    
    try:
        # Try primary format
        start_date = datetime.strptime(str(start_str).strip(), fmt)
        end_date = datetime.strptime(str(end_str).strip(), fmt)
        return max(0, (end_date - start_date).days)
    except ValueError:
        try:
            # Try alternative format
            start_date = datetime.strptime(str(start_str).strip(), alt_fmt)
            end_date = datetime.strptime(str(end_str).strip(), alt_fmt)
            return max(0, (end_date - start_date).days)
        except ValueError:
            return 0


def is_nan(value):
    """Check if value is NaN/None/empty in a pandas-compatible way"""
    if value is None:
        return True
    if isinstance(value, float) and np.isnan(value):
        return True
    if isinstance(value, str) and value.lower().strip() in ["nan", "none", "", "nat"]:
        return True
    try:
        if pd.isna(value):
            return True
    except:
        pass
    return False


def clean_value(value, default=""):
    """Convert any NaN/None values to default with type safety"""
    if is_nan(value):
        return default
    try:
        return str(value).strip()
    except:
        return default


def safe_int_conversion(value, default=0):
    """Safely convert value to integer"""
    if is_nan(value):
        return default
    try:
        # Handle string representations of numbers
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return default
        return int(float(value))
    except (ValueError, TypeError):
        return default


def simplify_date(date):
    """Convert date string with robust NaN/None handling"""
    if is_nan(date):
        return ""
    
    date_str = clean_value(date)
    if not date_str:
        return ""
        
    try:
        # Handle multiple date formats
        for fmt in ("%m-%d-%Y %H:%M", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt_obj = datetime.strptime(date_str, fmt)
                return f"{dt_obj.strftime('%B')} {dt_obj.day}, {dt_obj.year}"
            except ValueError:
                continue
        
        # If no format matched, try to extract at least the date part
        date_part = date_str.split()[0] if ' ' in date_str else date_str
        for fmt in ("%m-%d-%Y", "%m/%d/%Y", "%Y-%m-%d"):
            try:
                dt_obj = datetime.strptime(date_part, fmt)
                return f"{dt_obj.strftime('%B')} {dt_obj.day}, {dt_obj.year}"
            except ValueError:
                continue
                
        return date_str  # Return original if no format matched
    except (ValueError, TypeError):
        return ""


def determine_sla_status(severity_score: str, vulnerability_age) -> str:
    """Determine SLA status based on severity and age thresholds with robust type handling"""
    # Safely convert vulnerability_age to integer
    try:
        if is_nan(vulnerability_age):
            age_days = 0
        elif isinstance(vulnerability_age, str):
            age_days = safe_int_conversion(vulnerability_age.strip(), 0)
        else:
            age_days = safe_int_conversion(vulnerability_age, 0)
    except:
        age_days = 0

    if not severity_score or is_nan(severity_score):
        return "N/A - Needs Assessment"

    severity_str = clean_value(severity_score)
    
    # Define thresholds based on severity score prefixes
    thresholds = {
        "1-": ("Critical", 7),
        "2-": ("High", 14), 
        "3-": ("Medium", 30),
        "4-": ("Low", 90),
    }

    for prefix, (level, threshold_days) in thresholds.items():
        if severity_str.startswith(prefix):
            status = "Breached" if age_days > threshold_days else "Within SLA"
            return status

    return "N/A - Needs Assessment"


def export_results_to_excel(processed_data: Dict[str, Any]) -> io.BytesIO:
    """Export with original report data included with robust NaN/None handling"""
    output = io.BytesIO()

    try:
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            # Enhanced detailed results with original data
            detailed_rows = []

            for result in processed_data.get("results", []):
                try:
                    original_data = result.get("original_data", {})
                    
                    # Calculate vulnerability age with error handling
                    first_detected = clean_value(original_data.get("First Detected"))
                    last_detected = clean_value(original_data.get("Last Detected"))
                    vulnerability_age = get_days_diff(first_detected, last_detected)
                    
                    # Get severity score
                    severity_score = determine_severity_score(result)
                    
                    # Build base row with safe value extraction
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
                        "First Detected": simplify_date(first_detected),
                        "Last Detected": simplify_date(last_detected),
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
                        "SLA Status": determine_sla_status(severity_score, vulnerability_age),
                        "Remediation Marks": "",
                        "Avg CVSS Score": round(
                            float(clean_value(result.get("avg_cvss_score"), "0") or "0"), 2
                        ),
                        "Highest CVSS Score": round(
                            float(clean_value(result.get("highest_score"), "0") or "0"), 2
                        ),
                    }

                    cve_results = result.get("cve_results", [])
                    if cve_results:
                        for i, cve in enumerate(cve_results, 1):
                            row = base_row.copy()
                            
                            # Safely extract CVE attributes
                            try:
                                cve_score = float(clean_value(getattr(cve, "score", "0") or "0"))
                            except (ValueError, TypeError):
                                cve_score = 0.0
                            
                            # Handle CWE info safely
                            cwe_info = getattr(cve, "cwe_info", []) or []
                            if isinstance(cwe_info, list):
                                cwe_string = ", ".join(
                                    str(item) for item in cwe_info 
                                    if item is not None and not is_nan(item)
                                )
                            else:
                                cwe_string = clean_value(cwe_info)
                            
                            # Handle affected products safely  
                            affected_products = getattr(cve, "affected_products", []) or []
                            if isinstance(affected_products, list):
                                products_string = ", ".join(
                                    str(item) for item in affected_products[:5]
                                    if item is not None and not is_nan(item)
                                )
                            else:
                                products_string = clean_value(affected_products)
                            
                            row.update({
                                "CVE": clean_value(getattr(cve, "cve_id", "")),
                                "Published Date": simplify_date(
                                    clean_value(getattr(cve, "published_date", ""))
                                ),
                                "Patch Released": simplify_date(
                                    clean_value(getattr(cve, "modified_date", ""))
                                ),
                                "Asset Critical Score": severity_score,
                                "Severity Score": severity_score,
                                "CVE_CVSS_Score": round(cve_score, 2),
                                "CVE_Severity": clean_value(getattr(cve, "severity", "")),
                                "CVE_Description": clean_value(getattr(cve, "description", "")),
                                "CVE_Vector_String": clean_value(getattr(cve, "vector_string", "")),
                                "CVE_CWE_Info": cwe_string,
                                "CVE_Affected_Products": products_string,
                            })
                            detailed_rows.append(row)
                    else:
                        # Add base row even if no CVEs found
                        base_row.update({
                            "CVE": "",
                            "Published Date": "",
                            "Patch Released": "",
                            "Asset Critical Score": severity_score,
                            "Severity Score": severity_score,
                            "CVE_CVSS_Score": 0.0,
                            "CVE_Severity": "",
                            "CVE_Description": "",
                            "CVE_Vector_String": "",
                            "CVE_CWE_Info": "",
                            "CVE_Affected_Products": "",
                        })
                        detailed_rows.append(base_row)
                        
                except Exception as e:
                    print(f"Error processing result: {e}")
                    # Add a minimal error row to avoid losing data
                    error_row = {
                        "Title": clean_value(result.get("title", "Error processing row")),
                        "Error": f"Processing error: {str(e)}"
                    }
                    detailed_rows.append(error_row)

            # Convert to DataFrame and clean any remaining NaN values
            if detailed_rows:
                df = pd.DataFrame(detailed_rows)
                # Replace NaN values more thoroughly
                df = df.fillna("")
                
                # Additional cleaning for any remaining NaN-like values
                for col in df.columns:
                    df[col] = df[col].astype(str).replace(['nan', 'None', 'NaT'], '')
                
                df.to_excel(writer, sheet_name="Complete_Analysis", index=False)
            else:
                # Create empty DataFrame if no data
                empty_df = pd.DataFrame([{"Message": "No data to export"}])
                empty_df.to_excel(writer, sheet_name="Complete_Analysis", index=False)

    except Exception as e:
        print(f"Error in export_results_to_excel: {e}")
        # Create a basic error report
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            error_df = pd.DataFrame([{"Error": f"Export failed: {str(e)}"}])
            error_df.to_excel(writer, sheet_name="Error_Report", index=False)

    output.seek(0)
    return output