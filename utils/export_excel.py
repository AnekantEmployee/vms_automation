import io
import pandas as pd
import streamlit as st
from typing import Dict, Any, List
from .export_utils import determine_severity_score, get_days_diff, is_nan, clean_value, simplify_date, determine_sla_status



def export_results_to_excel(processed_data: Dict[str, Any]) -> io.BytesIO:
    """Export with original report data, risk assessment, and remediation guidance for each CVE"""
    output = io.BytesIO()

    try:
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            # Enhanced detailed results with original data, risk assessment, and remediation
            detailed_rows = []
            remediation_summary_rows = []
            risk_assessment_summary_rows = []

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
                    remediation_data = result.get("remediation_data", [])
                    risk_assessment_data = result.get("risk_assessment_data", [])
                    
                    # Create mappings for easy lookup
                    remediation_map = {}
                    risk_assessment_map = {}
                    
                    for rem_data in remediation_data:
                        if isinstance(rem_data, dict) and "cve_id" in rem_data:
                            remediation_map[rem_data["cve_id"]] = rem_data.get("remediation", {})
                    
                    for risk_data in risk_assessment_data:
                        if isinstance(risk_data, dict) and "cve_id" in risk_data:
                            risk_assessment_map[risk_data["cve_id"]] = risk_data.get("risk_assessment", {})

                    if cve_results:
                        for i, cve in enumerate(cve_results, 1):
                            row = base_row.copy()
                            
                            # Safely extract CVE attributes
                            try:
                                cve_score = float(clean_value(getattr(cve, "score", "0") or "0"))
                            except (ValueError, TypeError):
                                cve_score = 0.0
                            
                            cve_id = clean_value(getattr(cve, "cve_id", ""))
                            
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
                            
                            # Get remediation and risk assessment data for this CVE
                            remediation = remediation_map.get(cve_id, {})
                            risk_assessment = risk_assessment_map.get(cve_id, {})
                            
                            # Format immediate actions for better display
                            immediate_actions = risk_assessment.get("immediate_actions", [])
                            if isinstance(immediate_actions, list):
                                immediate_actions_text = "\n".join(immediate_actions)
                            else:
                                immediate_actions_text = clean_value(immediate_actions)
                            
                            row.update({
                                "CVE": cve_id,
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
                                # Add risk assessment columns
                                "Risk_Category": clean_value(risk_assessment.get("risk_category", "")),
                                "Risk_Details": clean_value(risk_assessment.get("risk_details", "")),
                                "Business_Impact": clean_value(risk_assessment.get("business_impact", "")),
                                "Remediation_Urgency": clean_value(risk_assessment.get("remediation_urgency", "")),
                                "Risk_Immediate_Actions": immediate_actions_text,
                                "Exploitation_Methods": clean_value(risk_assessment.get("exploitation_methods", "")),  # NEW
                                # Add remediation columns
                                "Remediation_Guide": clean_value(remediation.get("Remediation Guide", "")),
                                "Remediation_Priority": clean_value(remediation.get("Remediation Priority", "")),
                                "Estimated_Effort": clean_value(remediation.get("Estimated Effort", "")),
                                "Immediate_Actions": clean_value(remediation.get("Immediate Actions", "")),
                                "Detailed_Steps": clean_value(remediation.get("Detailed Steps", "")),
                                "Verification_Steps": clean_value(remediation.get("Verification Steps", "")),
                                "Rollback_Plan": clean_value(remediation.get("Rollback Plan", "")),
                                "Reference_Links": clean_value(remediation.get("Reference Links", "")),
                                "Additional_Resources": clean_value(remediation.get("Additional Resources", "")),
                            })
                            detailed_rows.append(row)
                            
                            # Create remediation summary row for separate sheet
                            if remediation:
                                remediation_summary = {
                                    "Asset_IP": clean_value(original_data.get("IP")),
                                    "QID": clean_value(original_data.get("QID")),
                                    "Vulnerability_Title": clean_value(original_data.get("Title")),
                                    "CVE_ID": cve_id,
                                    "CVE_Severity": clean_value(getattr(cve, "severity", "")),
                                    "CVSS_Score": round(cve_score, 2),
                                    "Remediation_Priority": clean_value(remediation.get("Remediation Priority", "")),
                                    "Estimated_Effort": clean_value(remediation.get("Estimated Effort", "")),
                                    "Remediation_Guide": clean_value(remediation.get("Remediation Guide", "")),
                                    "Immediate_Actions": clean_value(remediation.get("Immediate Actions", "")),
                                    "Detailed_Steps": clean_value(remediation.get("Detailed Steps", "")),
                                    "Verification_Steps": clean_value(remediation.get("Verification Steps", "")),
                                    "Rollback_Plan": clean_value(remediation.get("Rollback Plan", "")),
                                    "Reference_Links": clean_value(remediation.get("Reference Links", "")),
                                    "Additional_Resources": clean_value(remediation.get("Additional Resources", "")),
                                }
                                remediation_summary_rows.append(remediation_summary)
                            
                            # Create risk assessment summary row for separate sheet
                            # Create risk assessment summary row for separate sheet
                            if risk_assessment:
                                risk_summary = {
                                    "Asset_IP": clean_value(original_data.get("IP")),
                                    "QID": clean_value(original_data.get("QID")),
                                    "Vulnerability_Title": clean_value(original_data.get("Title")),
                                    "CVE_ID": cve_id,
                                    "CVE_Severity": clean_value(getattr(cve, "severity", "")),
                                    "CVSS_Score": round(cve_score, 2),
                                    "Risk_Category": clean_value(risk_assessment.get("risk_category", "")),
                                    "Risk_Score": clean_value(risk_assessment.get("risk_score", "")),
                                    "Risk_Details": clean_value(risk_assessment.get("risk_details", "")),
                                    "Business_Impact": clean_value(risk_assessment.get("business_impact", "")),
                                    "Remediation_Urgency": clean_value(risk_assessment.get("remediation_urgency", "")),
                                    "Immediate_Actions": immediate_actions_text,
                                    "Exploitation_Methods": clean_value(risk_assessment.get("exploitation_methods", "")),  # NEW
                                }
                                risk_assessment_summary_rows.append(risk_summary)
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
                            # Empty risk assessment columns
                            "Risk_Category": "",
                            "Risk_Score": "",
                            "Risk_Details": "",
                            "Business_Impact": "",
                            "Remediation_Urgency": "",
                            "Risk_Immediate_Actions": "",
                            "Exploitation_Methods": "",  # NEW
                            # Empty remediation columns
                            "Remediation_Guide": "",
                            "Remediation_Priority": "",
                            "Estimated_Effort": "",
                            "Immediate_Actions": "",
                            "Detailed_Steps": "",
                            "Verification_Steps": "",
                            "Rollback_Plan": "",
                            "Reference_Links": "",
                            "Additional_Resources": "",
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

            # Create Complete Analysis sheet
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

            # Create Remediation Summary sheet
            if remediation_summary_rows:
                remediation_df = pd.DataFrame(remediation_summary_rows)
                remediation_df = remediation_df.fillna("")
                
                # Additional cleaning for remediation data
                for col in remediation_df.columns:
                    remediation_df[col] = remediation_df[col].astype(str).replace(['nan', 'None', 'NaT'], '')
                
                remediation_df.to_excel(writer, sheet_name="Remediation_Guide", index=False)
            else:
                # Create empty remediation sheet
                empty_remediation_df = pd.DataFrame([{"Message": "No remediation data available"}])
                empty_remediation_df.to_excel(writer, sheet_name="Remediation_Guide", index=False)

            # Create Risk Assessment Summary sheet
            if risk_assessment_summary_rows:
                risk_df = pd.DataFrame(risk_assessment_summary_rows)
                risk_df = risk_df.fillna("")
                
                # Additional cleaning for risk assessment data
                for col in risk_df.columns:
                    risk_df[col] = risk_df[col].astype(str).replace(['nan', 'None', 'NaT'], '')
                
                risk_df.to_excel(writer, sheet_name="Risk_Assessment", index=False)
            else:
                # Create empty risk assessment sheet
                empty_risk_df = pd.DataFrame([{"Message": "No risk assessment data available"}])
                empty_risk_df.to_excel(writer, sheet_name="Risk_Assessment", index=False)

            # Create Summary Statistics sheet
            create_summary_sheet(writer, processed_data, detailed_rows)
            
            # Create Priority Matrix sheet
            create_priority_matrix_sheet(writer, detailed_rows)

    except Exception as e:
        print(f"Error in export_results_to_excel: {e}")
        # Create a basic error report
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            error_df = pd.DataFrame([{"Error": f"Export failed: {str(e)}"}])
            error_df.to_excel(writer, sheet_name="Error_Report", index=False)

    output.seek(0)
    return output


def create_summary_sheet(writer, processed_data: Dict[str, Any], detailed_rows: List[Dict]):
    """Create a summary statistics sheet"""
    try:
        summary_data = []
        
        # Basic statistics
        summary_data.append({"Metric": "Total Vulnerabilities Processed", "Value": len(processed_data.get("results", []))})
        summary_data.append({"Metric": "Total CVEs Found", "Value": processed_data.get("summary", {}).get("total_cves_found", 0)})
        summary_data.append({"Metric": "Total Remediation Guides Generated", "Value": processed_data.get("summary", {}).get("total_remediations_generated", 0)})
        summary_data.append({"Metric": "Total Risk Assessments Generated", "Value": len([row for row in detailed_rows if row.get("Risk_Category")])})
        
        # Severity breakdown
        critical_count = len([row for row in detailed_rows if row.get("CVE_Severity", "").upper() == "CRITICAL"])
        high_count = len([row for row in detailed_rows if row.get("CVE_Severity", "").upper() == "HIGH"])
        medium_count = len([row for row in detailed_rows if row.get("CVE_Severity", "").upper() == "MEDIUM"])
        low_count = len([row for row in detailed_rows if row.get("CVE_Severity", "").upper() == "LOW"])
        
        summary_data.extend([
            {"Metric": "Critical Severity CVEs", "Value": critical_count},
            {"Metric": "High Severity CVEs", "Value": high_count},
            {"Metric": "Medium Severity CVEs", "Value": medium_count},
            {"Metric": "Low Severity CVEs", "Value": low_count}
        ])
        
        # Risk category breakdown
        risk_critical_count = len([row for row in detailed_rows if row.get("Risk_Category", "").upper() == "CRITICAL"])
        risk_high_count = len([row for row in detailed_rows if row.get("Risk_Category", "").upper() == "HIGH"])
        risk_medium_count = len([row for row in detailed_rows if row.get("Risk_Category", "").upper() == "MEDIUM"])
        risk_low_count = len([row for row in detailed_rows if row.get("Risk_Category", "").upper() == "LOW"])
        
        summary_data.extend([
            {"Metric": "Critical Risk Category", "Value": risk_critical_count},
            {"Metric": "High Risk Category", "Value": risk_high_count},
            {"Metric": "Medium Risk Category", "Value": risk_medium_count},
            {"Metric": "Low Risk Category", "Value": risk_low_count}
        ])
        
        # CVSS and Risk score statistics
        cvss_scores = [float(row.get("CVE_CVSS_Score", 0)) for row in detailed_rows if row.get("CVE_CVSS_Score")]
        risk_scores = [float(row.get("Risk_Score", 0)) for row in detailed_rows if row.get("Risk_Score") and str(row.get("Risk_Score")).replace('.','').isdigit()]
        
        if cvss_scores:
            summary_data.extend([
                {"Metric": "Average CVSS Score", "Value": round(sum(cvss_scores) / len(cvss_scores), 2)},
                {"Metric": "Highest CVSS Score", "Value": max(cvss_scores)},
                {"Metric": "Lowest CVSS Score", "Value": min(cvss_scores)}
            ])
        
        if risk_scores:
            summary_data.extend([
                {"Metric": "Average Risk Score", "Value": round(sum(risk_scores) / len(risk_scores), 2)},
                {"Metric": "Highest Risk Score", "Value": max(risk_scores)},
                {"Metric": "Lowest Risk Score", "Value": min(risk_scores)}
            ])
        
        # Priority breakdown
        critical_priority = len([row for row in detailed_rows if row.get("Remediation_Priority", "").lower() == "critical"])
        high_priority = len([row for row in detailed_rows if row.get("Remediation_Priority", "").lower() == "high"])
        medium_priority = len([row for row in detailed_rows if row.get("Remediation_Priority", "").lower() == "medium"])
        low_priority = len([row for row in detailed_rows if row.get("Remediation_Priority", "").lower() == "low"])
        
        summary_data.extend([
            {"Metric": "Critical Priority Remediations", "Value": critical_priority},
            {"Metric": "High Priority Remediations", "Value": high_priority},
            {"Metric": "Medium Priority Remediations", "Value": medium_priority},
            {"Metric": "Low Priority Remediations", "Value": low_priority}
        ])
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name="Summary_Statistics", index=False)
        
    except Exception as e:
        print(f"Error creating summary sheet: {e}")
        error_df = pd.DataFrame([{"Error": f"Summary creation failed: {str(e)}"}])
        error_df.to_excel(writer, sheet_name="Summary_Statistics", index=False)

def create_priority_matrix_sheet(writer, detailed_rows: List[Dict]):
    """Create a priority matrix for remediation planning"""
    try:
        priority_data = []
        
        # Group by priority and effort
        for row in detailed_rows:
            if row.get("CVE") and (row.get("Remediation_Priority") or row.get("Risk_Category")):  # Include rows with CVEs and either remediation or risk data
                priority_data.append({
                    "Asset_IP": row.get("Asset IPV4", ""),
                    "QID": row.get("QID", ""),
                    "CVE_ID": row.get("CVE", ""),
                    "Vulnerability_Title": row.get("Title", "")[:50],  # Truncate for readability
                    "CVE_Severity": row.get("CVE_Severity", ""),
                    "CVSS_Score": row.get("CVE_CVSS_Score", 0),
                    "Risk_Category": row.get("Risk_Category", ""),
                    "Risk_Score": row.get("Risk_Score", ""),
                    "Remediation_Priority": row.get("Remediation_Priority", ""),
                    "Remediation_Urgency": row.get("Remediation_Urgency", ""),
                    "Estimated_Effort": row.get("Estimated_Effort", ""),
                    "SLA_Status": row.get("SLA Status", ""),
                    "First_Detected": row.get("First Detected", ""),
                    "Vulnerability_Age": row.get("Vulnerability Age", ""),
                })
        
        if priority_data:
            # Sort by risk category first, then remediation priority, then by CVSS score
            risk_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
            priority_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
            
            priority_data.sort(key=lambda x: (
                risk_order.get(x["Risk_Category"], 5),
                priority_order.get(x["Remediation_Priority"], 5),
                -float(x["CVSS_Score"]) if x["CVSS_Score"] else 0
            ))
            
            priority_df = pd.DataFrame(priority_data)
            priority_df.to_excel(writer, sheet_name="Priority_Matrix", index=False)
        else:
            empty_df = pd.DataFrame([{"Message": "No priority data available"}])
            empty_df.to_excel(writer, sheet_name="Priority_Matrix", index=False)
            
    except Exception as e:
        print(f"Error creating priority matrix: {e}")
        error_df = pd.DataFrame([{"Error": f"Priority matrix creation failed: {str(e)}"}])
        error_df.to_excel(writer, sheet_name="Priority_Matrix", index=False)
