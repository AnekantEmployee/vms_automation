import io
import pandas as pd
import streamlit as st
from typing import Dict, Any
from .export_utils import determine_severity_score, get_days_diff, is_nan, clean_value, simplify_date, determine_sla_status



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