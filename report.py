import time
import asyncio
import pandas as pd
import streamlit as st
from datetime import datetime
from typing import Dict, Any, Tuple
from utils.export_excel import export_results_to_excel
from cve_search.core_functions import combined_cve_search
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.remediation_agent import get_enhanced_remediation_data
from utils.risk_assessment import get_vulnerability_risk_assessment
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="langchain_google_genai")


# Page configuration
st.set_page_config(
    page_title="Vulnerability Report Processor",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Streamlined CSS
st.markdown(
    """
<style>
    .chat-container {
        max-height: 400px; overflow-y: auto; border: 1px solid #e1e5e9;
        border-radius: 10px; padding: 1rem; background: #f8f9fa; margin: 1rem 0;
    }
    .chat-message {
        margin: 0.5rem 0; padding: 0.75rem; border-radius: 10px; 
        font-size: 0.9rem; line-height: 1.4;
    }
    .chat-system { background: #e3f2fd; color: #1565c0; border-left: 4px solid #1976d2; }
    .chat-processing { background: #fff3e0; color: #ef6c00; border-left: 4px solid #ff9800; }
    .chat-success { background: #e8f5e8; color: #2e7d32; border-left: 4px solid #4caf50; }
    .chat-error { background: #ffebee; color: #c62828; border-left: 4px solid #f44336; }
    .chat-warning { background: #fff8e1; color: #f57f17; border-left: 4px solid #ffc107; }
    .severity-critical { background: #ffebee !important; color: #c62828 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-high { background: #fff3e0 !important; color: #ef6c00 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-medium { background: #fff8e1 !important; color: #f57f17 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-low { background: #e8f5e8 !important; color: #2e7d32 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-unknown { background: #f5f5f5 !important; color: #666 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
</style>
""",
    unsafe_allow_html=True,
)

# Initialize session state
for key in ["chat_messages", "processed_data"]:
    if key not in st.session_state:
        st.session_state[key] = [] if key == "chat_messages" else None


class ChatInterface:
    """Streamlined chatbot interface"""

    @staticmethod
    def add_message(message: str, msg_type: str = "system"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        st.session_state.chat_messages.append(
            {"message": message, "type": msg_type, "timestamp": timestamp}
        )

    @staticmethod
    def display_chat():
        if st.session_state.chat_messages:
            st.markdown('<div class="chat-container">', unsafe_allow_html=True)
            for msg in st.session_state.chat_messages[-20:]:
                css_class = f"chat-{msg['type']}"
                st.markdown(
                    f"""
                    <div class="chat-message {css_class}">
                        <strong>[{msg['timestamp']}]</strong> {msg['message']}
                    </div>
                """,
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)

    @staticmethod
    def clear_chat():
        st.session_state.chat_messages = []

def read_uploaded_file(uploaded_file) -> pd.DataFrame:
    """Read uploaded file"""
    file_ext = uploaded_file.name.split(".")[-1].lower()
    if file_ext == "csv":
        return pd.read_csv(uploaded_file)
    elif file_ext in ["xlsx", "xls"]:
        return pd.read_excel(uploaded_file)
    else:
        raise ValueError(f"Unsupported file format: {file_ext}")


def find_header_row(df: pd.DataFrame) -> int:
    """Find row with 'Title' column"""
    for idx, row in df.iterrows():
        if any("title" in str(cell).lower() for cell in row.values if pd.notna(cell)):
            return idx
    return -1


async def process_single_vulnerability_async(
    idx: int,
    row: pd.Series,
    title_col: str,
    type_col: str,
    header_row: int,
    max_results_per_vuln: int,
) -> Tuple[Dict[str, Any], str]:
    """Process a single vulnerability row with remediation for each CVE (async version)"""
    
    title = str(row.get(title_col, "")).strip()
    vuln_type = str(row.get(type_col, "")).strip() if type_col else "Unknown"
    
    if not title or title == "nan":
        return None, "skipped_empty"
    
    # Skip if type column exists and doesn't contain "vuln" or "ig" (case-insensitive)
    if type_col and not any(keyword in vuln_type.lower() for keyword in ["vuln", "ig"]):
        return None, "skipped_type"
    
    try:
        # ========== MODIFICATION START ==========
        # Prepare vulnerability context for CVE validation
        vulnerability_context = {
            "Title": title,
            "Operating System": str(row.get("OS", "Unknown")),
            "QID": str(row.get("QID", "")),
            "Asset Name": str(row.get("DNS", "")),
            "Asset IP": str(row.get("IP", "")),
            "Severity": str(row.get("Severity", "")),
            "Category": str(row.get("Category", "")),
            "Type": vuln_type
        }
        
        # Call CVE search with context for validation
        cve_results = combined_cve_search(
            title, 
            max_results_per_vuln,
            vulnerability_context=vulnerability_context  # Pass context
        )
        # ========== MODIFICATION END ==========
        
        original_data = {col: str(row.get(col, "")) for col in row.index}
        
        if cve_results:
            severity_counts = {}
            total_score = score_count = 0
            remediation_data = []
            risk_assessment_data = []  # Array for risk assessments
            
            # Process each CVE and get remediation data
            for cve in cve_results:
                severity = cve.severity.upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if cve.score > 0:
                    total_score += cve.score
                    score_count += 1
                
                # Convert CVE object to dictionary format for risk assessment
                cve_data = {
                    "cve_id": cve.cve_id,
                    "description": cve.description,
                    "severity": cve.severity,
                    "published_date": cve.published_date,
                    "modified_date": cve.modified_date,
                    "score": cve.score,
                    "source": getattr(cve, 'source', 'Unknown'),
                    "vuln_status": getattr(cve, 'vuln_status', 'Unknown'),
                    "cwe_info": getattr(cve, 'cwe_info', []),
                    "affected_products": getattr(cve, 'affected_products', []),
                    "references": getattr(cve, 'references', []),
                    "exploitability_score": getattr(cve, 'exploitability_score', 0.0),
                    "impact_score": getattr(cve, 'impact_score', 0.0),
                    "vector_string": getattr(cve, 'vector_string', ''),
                    "cvss_version": getattr(cve, 'cvss_version', ''),
                    "confidence_score": getattr(cve, 'confidence_score', 0.0)
                }
                
                # Get risk assessment for this specific CVE
                try:
                    risk_assessment = await get_vulnerability_risk_assessment(original_data, cve_data)
                    risk_assessment_data.append({
                        "cve_id": cve.cve_id,
                        "risk_assessment": risk_assessment
                    })
                except Exception as e:
                    print(f"Error generating risk assessment for CVE {cve.cve_id}: {e}")
                    # Fallback risk assessment data
                    risk_assessment_data.append({
                        "cve_id": cve.cve_id,
                        "risk_assessment": {
                            "risk_category": "Medium",
                            "risk_score": 5.0,
                            "risk_details": f"Risk assessment unavailable for CVE {cve.cve_id}",
                            "business_impact": "Potential security exposure requiring assessment",
                            "remediation_urgency": "📅 Standard Priority (2 weeks)",
                            "immediate_actions": [
                                "🔒 Step 1: Apply latest security patches and updates",
                                "⚙️ Step 2: Review and harden system configurations", 
                                "📊 Step 3: Enable security monitoring and alerting"
                            ]
                        }
                    })
                
                # Get remediation data for this specific CVE
                try:
                    cve_remediation = await get_enhanced_remediation_data(
                        {"original_data": original_data}, 
                        cve
                    )
                    remediation_data.append({
                        "cve_id": cve.cve_id,
                        "remediation": cve_remediation
                    })
                except Exception as e:
                    print(f"Error generating remediation for CVE {cve.cve_id}: {e}")
                    # Fallback remediation data
                    remediation_data.append({
                        "cve_id": cve.cve_id,
                        "remediation": {
                            "exploitation_methods": f"Exploitation details unavailable for CVE {cve.cve_id}",
                            "remediation_guide": "Please refer to vendor security advisories",
                            "remediation_priority": "Medium",
                            "estimated_effort": "2-6 hours depending on system complexity",
                            "immediate_actions": [
                                "• Apply vendor security patches immediately",
                                "• Review and harden system configuration",
                                "• Enable security monitoring and alerting"
                            ],
                            "detailed_steps": [
                                "1. Check vendor advisories for security patches",
                                "2. Test patches in staging environment",
                                "3. Apply patches during maintenance window",
                                "4. Verify patch installation success",
                                "5. Monitor system for proper functionality"
                            ],
                            "verification_steps": [
                                "• Verify remediation has been applied successfully",
                                "• Run vulnerability scanner to confirm fix",
                                "• Test critical system functionality",
                                "• Document remediation for compliance audit"
                            ],
                            "rollback_plan": [
                                "• Maintain complete system backups before changes",
                                "• Document all configuration modifications",
                                "• Test rollback procedures in staging environment",
                                "• Keep previous configurations for quick restoration"
                            ],
                            "reference_links": [
                                f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
                            ],
                            "additional_resources": [
                                "https://nvd.nist.gov/",
                                "https://cve.mitre.org/",
                                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            ]
                        }
                    })
            
            # Return enhanced result with CVE data, remediation, and risk assessment
            return {
                "row_index": idx + header_row + 1,
                "title": title,
                "cve_count": len(cve_results),
                "original_data": original_data,
                "cve_results": cve_results,
                "remediation_data": remediation_data,
                "risk_assessment_data": risk_assessment_data,
                "severity_summary": dict(severity_counts),
                "avg_score": total_score / score_count if score_count > 0 else 0
            }, "success"
        else:
            return {
                "row_index": idx + header_row + 1,
                "title": title,
                "cve_count": 0,
                "original_data": original_data,
                "cve_results": [],
                "remediation_data": [],
                "risk_assessment_data": [],
                "severity_summary": {},
                "avg_score": 0
            }, "no_cves"
            
    except Exception as e:
        print(f"Error processing row {idx}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None, "error"


def process_single_vulnerability(
    idx: int,
    row: pd.Series,
    title_col: str,
    type_col: str,
    header_row: int,
    max_results_per_vuln: int,
) -> Tuple[Dict[str, Any], str]:
    """Synchronous wrapper for the async vulnerability processing function"""
    try:
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                process_single_vulnerability_async(
                    idx, row, title_col, type_col, header_row, max_results_per_vuln
                )
            )
            return result
        finally:
            loop.close()
    except Exception as e:
        print(f"Error in process_single_vulnerability: {e}")
        # Create original row data for error case
        original_data = {col: str(row.get(col, "")) for col in row.index}
        title = str(row.get(title_col, "")).strip()
        vuln_type = str(row.get(type_col, "")).strip() if type_col else "Unknown"
        
        error_result = {
            "original_row": idx + header_row + 2,
            "original_data": original_data,
            "title": title,
            "type": vuln_type,
            "remediation_data": [],  # Empty array on error
            "error": str(e),
            "processed_at": datetime.now().isoformat(),
        }
        return error_result, "error"

def process_vulnerability_report(
    df: pd.DataFrame, max_results_per_vuln: int = 3, max_workers: int = 5
) -> Dict[str, Any]:
    """Process vulnerability report with parallel processing (updated for remediation)"""

    ChatInterface.add_message("🔍 Analyzing report structure...", "system")
    header_row = find_header_row(df)

    if header_row == -1:
        ChatInterface.add_message("❌ Could not find 'Title' column", "error")
        return None

    # Preserve original DataFrame structure
    original_df = df.copy()

    # Process headers
    df.columns = df.iloc[header_row].values
    df = df.iloc[header_row + 1 :].reset_index(drop=True)
    df.columns = [str(col).strip() for col in df.columns]

    # Find columns
    title_col = next((col for col in df.columns if "title" in str(col).lower()), None)
    type_col = next((col for col in df.columns if "type" in str(col).lower()), None)

    if not title_col:
        ChatInterface.add_message("❌ 'Title' column not found", "error")
        return None

    ChatInterface.add_message(
        f"✅ Processing {len(df)} rows with {max_workers} parallel workers (including AI remediation)", "success"
    )

    results = []
    stats = {
        "processed": 0,
        "skipped_empty": 0,
        "skipped_type": 0,
        "success": 0,
        "success_no_cves": 0,
        "error": 0,
    }

    import streamlit as st
    progress_placeholder = st.empty()
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Initialize chat placeholder for real-time updates
    if "chat_placeholder" not in st.session_state:
        st.session_state.chat_placeholder = st.empty()

    # Process rows in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for idx, row in df.iterrows():
            futures.append(
                executor.submit(
                    process_single_vulnerability,
                    idx,
                    row,
                    title_col,
                    type_col,
                    header_row,
                    max_results_per_vuln,
                )
            )

        for i, future in enumerate(as_completed(futures)):
            result, status = future.result()

            # Update statistics
            stats[status] += 1
            if status in ["success", "success_no_cves"]:
                stats["processed"] += 1
                results.append(result)

                title = result["title"]
                if status == "success":
                    remediation_count = len(result.get("remediation_data", []))
                    ChatInterface.add_message(
                        f"✅ Found {result['cve_count']} CVE(s) with {remediation_count} remediation guides for '{title[:40]}...'",
                        "success",
                    )
                else:
                    ChatInterface.add_message(
                        f"⚠️ No CVEs found for '{title[:40]}...'", "warning"
                    )
            elif status == "error":
                ChatInterface.add_message(
                    f"❌ Error processing '{result['title'][:40]}...': {result['error']}",
                    "error",
                )

            # Update progress
            progress = (i + 1) / len(futures)
            progress_bar.progress(progress)
            
            # Calculate total remediation guides generated
            total_remediations = sum(len(r.get("remediation_data", [])) for r in results)
            
            status_text.text(
                f"Processed: {i+1}/{len(futures)} | "
                f"CVEs Found: {sum(len(r['cve_results']) for r in results if 'cve_results' in r)} | "
                f"Remediation Guides: {total_remediations} | "
                f"Errors: {stats['error']}"
            )

            # Update chat display periodically
            if i % 5 == 0 or i == len(futures) - 1:
                with st.session_state.chat_placeholder.container():
                    ChatInterface.display_chat()

    # Final summary
    total_cves = sum(len(r["cve_results"]) for r in results)
    total_remediations = sum(len(r.get("remediation_data", [])) for r in results)
    
    ChatInterface.add_message(
        f"🎯 Complete! Processed: {stats['processed']}, "
        f"Skipped: {stats['skipped_empty'] + stats['skipped_type']}, "
        f"Errors: {stats['error']}, "
        f"Total CVEs Found: {total_cves}, "
        f"Remediation Guides Generated: {total_remediations}",
        "success",
    )

    return {
        "results": results,
        "original_columns": list(df.columns),
        "summary": {
            "total_rows": len(df),
            "processed": stats["processed"],
            "skipped": stats["skipped_empty"] + stats["skipped_type"],
            "errors": stats["error"],
            "total_cves_found": total_cves,
            "total_remediations_generated": total_remediations,
        },
    }



def main():
    """Streamlined main application"""

    st.title("📊 Vulnerability Report Processor")
    st.markdown("### AI-Powered Bulk CVE Analysis with Real-time Chat")
    st.divider()

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")

        max_results_per_vuln = st.slider("Max CVEs per Vulnerability", 1, 10, 3)
        max_workers = st.slider(
            "Parallel Workers",
            1,
            10,
            5,
            help="Number of parallel threads for processing",
        )

        st.divider()
        st.subheader("ℹ️ SLA Status Note")
        st.markdown(
            """
        **1. Critical (5) - Immediate Action Required**  
        - CVSS ≥ 9.0 or TruRisk ≥ 800  
        - SLA: 7 days remediation  
        - Age >7 days = Breached  

        **2. High (4) - Urgent Attention Needed**  
        - CVSS 7.0-8.9 or TruRisk 600-799  
        - SLA: 14 days remediation  
        - Age >14 days = Breached  

        **3. Medium (3) - Important to Address**  
        - CVSS 4.0-6.9 or TruRisk 400-599  
        - SLA: 30 days remediation  
        - Age >30 days = Breached  

        **4. Low (2) - Schedule Remediation**  
        - CVSS <4.0 or TruRisk <400  
        - SLA: 90 days remediation  
        - Age >90 days = Breached  

        **5. Unknown (1) - Investigation Needed**  
        - No severity data available  
        - SLA: Case-by-case assessment  
        """
        )

        st.divider()
        st.subheader("📌 Severity Score Mapping (New System)")
        st.markdown(
            """
            **1. Critical (1)**  
            - CVSS ≥ 9.0 or TruRisk ≥ 800  
            - Highest urgency / high business risk  
            - Corresponds to **red priority**  

            **2. High (2)**  
            - CVSS 7.0–8.9 or TruRisk 600–799  
            - Requires prompt action  

            **3. Medium (3)**  
            - CVSS 4.0–6.9 or TruRisk 400–599  
            - Address during planned remediation cycles  

            **4. Low (4)**  
            - CVSS < 4.0 or TruRisk < 400  
            - Minimal business risk  

            **Unknown**  
            - No CVSS/TruRisk data — Requires investigation
            """
        )

    # File upload
    st.subheader("📤 Upload Vulnerability Report")
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=["csv", "xlsx", "xls"],
        help="Upload file with 'Title' column and optional 'Type' column",
    )

    if uploaded_file:
        try:
            with st.spinner("📖 Reading file..."):
                df = read_uploaded_file(uploaded_file)

            st.success(f"✅ Loaded {len(df)} rows and {len(df.columns)} columns")

            # Process button
            if st.button(
                "🚀 Start Processing Report", type="primary", use_container_width=True
            ):
                st.session_state.processed_data = None
                ChatInterface.clear_chat()
                ChatInterface.add_message(
                    "🎯 Starting vulnerability report processing...", "system"
                )

                # Create persistent chat placeholder for real-time updates
                chat_placeholder = st.empty()
                st.session_state.chat_placeholder = chat_placeholder

                start_time = time.time()
                with st.spinner("Processing vulnerabilities in parallel..."):
                    processed_data = process_vulnerability_report(
                        df, max_results_per_vuln, max_workers
                    )

                if processed_data:
                    st.session_state.processed_data = processed_data
                    processing_time = f"{time.time() - start_time:.2f} seconds"
                    ChatInterface.add_message(
                        f"🎉 Processing completed in {processing_time}!", "success"
                    )
                    st.rerun()

        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

    # Display chat
    if st.session_state.chat_messages:
        st.subheader("💬 Processing Chat")
        ChatInterface.display_chat()

    # Display results (unchanged from original)
    if st.session_state.processed_data:
        st.divider()
        st.subheader("📋 Results Summary")

        data = st.session_state.processed_data
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Processed", data["summary"]["processed"])
        with col2:
            st.metric("CVEs Found", data["summary"]["total_cves_found"])
        with col3:
            vulnerabilities_with_cves = sum(
                1 for r in data["results"] if r["cve_count"] > 0
            )
            st.metric("Vulns with CVEs", vulnerabilities_with_cves)
        with col4:
            avg_cves = data["summary"]["total_cves_found"] / max(
                len(data["results"]), 1
            )
            st.metric("Avg CVEs/Vuln", f"{avg_cves:.1f}")

        # Here add the summary
        
        
        # Export
        st.divider()
        st.subheader("📤 Export Enhanced Report")

        col1, col2 = st.columns(2)
        is_generated_report = False
        with col1:
            is_generated_report = st.button(
                "📊 Generate Excel Report", type="primary", use_container_width=True
            )

        with col2:
            if is_generated_report:
                try:
                    # st.write(data)
                    excel_file = export_results_to_excel(data)
                    st.download_button(
                        label="⬇️ Download Report",
                        data=excel_file,
                        file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")

    # Footer
    st.divider()
    st.markdown(
        """
        <div style='text-align: center; color: #666; font-size: 0.8rem;'>
            📊 Enhanced Vulnerability Report Processor • Preserves Original Data + CVE Intelligence
        </div>
    """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
