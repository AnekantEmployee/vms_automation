import io
import asyncio
import pandas as pd
from typing import Dict, Any
from .remediation_agent import get_enhanced_remediation_data
from .export_utils import determine_severity_score, get_days_diff, is_nan, clean_value, simplify_date, determine_sla_status

def export_results_to_excel(processed_data: Dict[str, Any], progress_callback=None) -> io.BytesIO:
    """Export with original report data included with robust NaN/None handling and enhanced remediation per CVE"""
    output = io.BytesIO()

    try:
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            # Enhanced detailed results with original data
            detailed_rows = []
            
            # Calculate total items for progress tracking
            total_items = 0
            for result in processed_data.get("results", []):
                cve_results = result.get("cve_results", [])
                total_items += len(cve_results) if cve_results else 1
            
            processed_items = 0

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
                            
                            # Handle affected products safely  
                            affected_products = getattr(cve, "affected_products", []) or []
                            if isinstance(affected_products, list):
                                products_string = ", ".join(
                                    str(item) for item in affected_products[:5]
                                    if item is not None and not is_nan(item)
                                )
                            else:
                                products_string = clean_value(affected_products)
                            
                            # Update progress
                            if progress_callback:
                                progress_callback(processed_items, total_items, f"Generating remediation for CVE: {getattr(cve, 'cve_id', 'Unknown')}")
                            
                            # Get enhanced remediation data for THIS specific CVE
                            remediation_data = asyncio.run(get_enhanced_remediation_data(result, cve))
                            
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
                                "CVE_Affected_Products": products_string,
                                # Enhanced remediation columns for THIS CVE
                                "Remediation Guide": remediation_data.get("Remediation Guide", ""),
                                "Remediation Priority": remediation_data.get("Remediation Priority", ""),
                                "Estimated Effort": remediation_data.get("Estimated Effort", ""),
                                "Reference Links": remediation_data.get("Reference Links", ""),
                                "Additional Resources": remediation_data.get("Additional Resources", ""),
                                "Immediate Actions": remediation_data.get("Immediate Actions", ""),
                                "Detailed Steps": remediation_data.get("Detailed Steps", ""),
                                "Verification Steps": remediation_data.get("Verification Steps", ""),
                                "Rollback Plan": remediation_data.get("Rollback Plan", ""),
                            })
                            detailed_rows.append(row)
                            
                            processed_items += 1
                            if progress_callback:
                                progress_callback(processed_items, total_items, f"Completed CVE: {getattr(cve, 'cve_id', 'Unknown')}")
                            
                    else:
                        # Update progress for rows without CVEs
                        if progress_callback:
                            progress_callback(processed_items, total_items, f"Processing vulnerability: {clean_value(original_data.get('Title'))}")
                        
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
                            "Remediation Guide": "",
                            "Remediation Priority": "",
                            "Estimated Effort": "",
                            "Reference Links": "",
                            "Additional Resources": "",
                            "Immediate Actions": "",
                            "Detailed Steps": "",
                            "Verification Steps": "",
                            "Rollback Plan": "",
                        })
                        detailed_rows.append(base_row)
                        
                        processed_items += 1
                        if progress_callback:
                            progress_callback(processed_items, total_items, f"Completed vulnerability: {clean_value(original_data.get('Title'))}")
                        
                except Exception as e:
                    print(f"Error processing result: {e}")
                    # Add a minimal error row to avoid losing data
                    error_row = {
                        "Title": clean_value(result.get("title", "Error processing row")),
                        "Error": f"Processing error: {str(e)}"
                    }
                    detailed_rows.append(error_row)
                    
                    processed_items += 1
                    if progress_callback:
                        progress_callback(processed_items, total_items, f"Error processing: {str(e)}")

            # Update progress for DataFrame creation
            if progress_callback:
                progress_callback(total_items, total_items, "Creating Excel workbook...")
            
            # Convert to DataFrame and clean any remaining NaN values
            if detailed_rows:
                df = pd.DataFrame(detailed_rows)
                # Replace NaN values more thoroughly
                df = df.fillna("")
                
                # Additional cleaning for any remaining NaN-like values
                for col in df.columns:
                    df[col] = df[col].astype(str).replace(['nan', 'None', 'NaT'], '')
                
                df.to_excel(writer, sheet_name="Complete_Analysis", index=False)
                
                # Create a summary sheet for remediation priorities
                if 'Remediation Priority' in df.columns:
                    priority_summary = df.groupby(['Remediation Priority', 'Severity']).size().reset_index(name='Count')
                    priority_summary.to_excel(writer, sheet_name="Remediation_Summary", index=False)
                
            else:
                # Create empty DataFrame if no data
                empty_df = pd.DataFrame([{"Message": "No data to export"}])
                empty_df.to_excel(writer, sheet_name="Complete_Analysis", index=False)
                
            if progress_callback:
                progress_callback(total_items, total_items, "Excel export completed!")

    except Exception as e:
        print(f"Error in export_results_to_excel: {e}")
        if progress_callback:
            progress_callback(total_items, total_items, f"Export failed: {str(e)}")
        # Create a basic error report
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            error_df = pd.DataFrame([{"Error": f"Export failed: {str(e)}"}])
            error_df.to_excel(writer, sheet_name="Error_Report", index=False)

    output.seek(0)
    return output