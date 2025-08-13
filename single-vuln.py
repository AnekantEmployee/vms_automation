import os
import streamlit as st
import time
from utils.core_functions import CVEResult
from cve_core import CVESearchAgent, combined_cve_search

# Page configuration
st.set_page_config(
    page_title="CVE Search Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Enhanced Custom CSS
st.markdown(
    """
<style>
    .main { padding-top: 2rem; }
    .cve-card {
        border: 1px solid #e1e5e9; border-radius: 10px; padding: 1.5rem; margin: 1rem 0;
        background: #f8f9fa; box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .cve-header {
        display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;
    }
    .severity-critical { background: #ffebee !important; color: #c62828 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-high { background: #fff3e0 !important; color: #ef6c00 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-medium { background: #fff8e1 !important; color: #f57f17 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-low { background: #e8f5e8 !important; color: #2e7d32 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .severity-unknown { background: #f5f5f5 !important; color: #666 !important; padding: 0.25rem 0.75rem; border-radius: 15px; font-weight: bold; font-size: 0.8rem; }
    .source-badge { background: #e3f2fd !important; color: #1565c0 !important; padding: 0.2rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: bold; margin-left: 0.5rem; }
    .status-badge { background: #f3e5f5 !important; color: #7b1fa2 !important; padding: 0.2rem 0.5rem; border-radius: 10px; font-size: 0.7rem; font-weight: bold; margin-left: 0.5rem; }
    .cvss-vector { background: #f5f5f5; padding: 0.5rem; border-radius: 5px; font-family: monospace; font-size: 0.8rem; margin: 0.5rem 0; }
    .cwe-tag { background: #e8f5e8; color: #2e7d32; padding: 0.2rem 0.5rem; border-radius: 8px; font-size: 0.7rem; margin: 0.2rem; display: inline-block; }
    .product-tag { background: #fff3e0; color: #ef6c00; padding: 0.2rem 0.5rem; border-radius: 8px; font-size: 0.7rem; margin: 0.2rem; display: inline-block; }
    .metric-box { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 1rem; margin: 0.5rem 0; }
    .reference-link { color: #1565c0; text-decoration: none; font-size: 0.8rem; }
    .reference-link:hover { text-decoration: underline; }
</style>
""",
    unsafe_allow_html=True,
)


# Initialize the agent with caching
@st.cache_resource
def initialize_agent():
    """Initialize the enhanced CVE agent with caching"""
    return CVESearchAgent()


# Enhanced caching with query normalization
@st.cache_data(ttl=600)  # 10 minutes cache
def cached_cve_search_with_ai(query: str, max_results: int):
    """Cached wrapper that combines enhanced CVE search and AI analysis"""

    # Get enhanced CVE results
    cve_results = combined_cve_search(query, max_results)

    # Get AI analysis if we have results
    ai_analysis = None
    if cve_results:
        try:
            agent = initialize_agent()
            ai_analysis = agent.get_ai_analysis(query)
        except Exception as e:
            ai_analysis = f"AI analysis failed: {str(e)}"

    return cve_results, ai_analysis


def format_enhanced_cve_card(cve: CVEResult):
    """Format CVE data as an enhanced card with detailed information"""
    severity_class = f"severity-{cve.severity.lower().replace(' ', '-')}"

    # Header with CVE ID, severity, and badges
    st.markdown(
        f"""
    <div class="cve-card">
        <div class="cve-header">
            <h4>🔒 {cve.cve_id}</h4>
            <div>
                <span class="{severity_class}">{cve.severity}</span>
                <span class="source-badge">{cve.source}</span>
                <span class="status-badge">{cve.vuln_status}</span>
            </div>
        </div>
    """,
        unsafe_allow_html=True,
    )

    # CVSS Metrics in columns
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("CVSS Score", f"{cve.score}/10.0", delta=f"v{cve.cvss_version}")

    with col2:
        if cve.exploitability_score > 0:
            st.metric("Exploitability", f"{cve.exploitability_score}/10.0")
        else:
            st.metric(
                "Published",
                (
                    cve.published_date.split("T")[0]
                    if "T" in cve.published_date
                    else cve.published_date
                ),
            )

    with col3:
        if cve.impact_score > 0:
            st.metric("Impact", f"{cve.impact_score}/10.0")
        else:
            st.metric(
                "Modified",
                (
                    cve.modified_date.split("T")[0]
                    if "T" in cve.modified_date
                    else cve.modified_date
                ),
            )

    with col4:
        st.metric("Version", f"CVSS {cve.cvss_version}")

    # CVSS Vector String (if available)
    if cve.vector_string:
        st.markdown(
            f"""
        <div class="cvss-vector">
            <strong>CVSS Vector:</strong> {cve.vector_string}
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Description
    st.markdown(f"**Description:** {cve.description}")

    # CWE Information
    if cve.cwe_info:
        cwe_tags = "".join(
            [f'<span class="cwe-tag">{cwe}</span>' for cwe in cve.cwe_info]
        )
        st.markdown(
            f"""
        <div style="margin: 1rem 0;">
            <strong>CWE Classifications:</strong><br>
            {cwe_tags}
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Affected Products
    if cve.affected_products:
        # Limit display to first 5 products, show count if more
        display_products = cve.affected_products[:5]
        product_tags = "".join(
            [
                f'<span class="product-tag">{product}</span>'
                for product in display_products
            ]
        )

        extra_count = len(cve.affected_products) - 5
        extra_text = f" <em>(+{extra_count} more)</em>" if extra_count > 0 else ""

        st.markdown(
            f"""
        <div style="margin: 1rem 0;">
            <strong>Affected Products:</strong>{extra_text}<br>
            {product_tags}
        </div>
        """,
            unsafe_allow_html=True,
        )

    # References
    if cve.references:
        ref_links = []
        for i, ref in enumerate(cve.references[:3]):  # Limit to first 3
            ref_links.append(
                f'<a href="{ref}" target="_blank" class="reference-link">Reference {i+1}</a>'
            )

        st.markdown(
            f"""
        <div style="margin: 1rem 0;">
            <strong>References:</strong><br>
            {' | '.join(ref_links)}
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Close the card div
    st.markdown("</div>", unsafe_allow_html=True)


def display_cve_summary_metrics(cve_results: list[CVEResult], search_time: str):
    """Display enhanced summary metrics"""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total CVEs", len(cve_results))

    with col2:
        critical_high = sum(
            1 for cve in cve_results if cve.severity.upper() in ["CRITICAL", "HIGH"]
        )
        st.metric("Critical/High", critical_high)

    with col3:
        scores = [cve.score for cve in cve_results if cve.score > 0]
        avg_score = sum(scores) / len(scores) if scores else 0
        st.metric("Avg CVSS Score", f"{avg_score:.1f}")

    with col4:
        # Count CVEs with CWE information
        cwe_count = sum(1 for cve in cve_results if cve.cwe_info)
        st.metric("With CWE Info", cwe_count)

    with col5:
        st.metric("Search Time", search_time)


def main():
    """Enhanced main Streamlit application"""

    # Header
    st.title("🛡️ CVE Search Agent")
    st.markdown(
        "### AI-Powered Vulnerability Intelligence Platform with Detailed Analysis"
    )
    st.markdown(
        "*Comprehensive vulnerability data from NIST and MITRE with CWE classifications, affected products, and CVSS metrics*"
    )
    st.divider()

    # Enhanced Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")

        # API Key status
        if os.getenv("GOOGLE_API_KEY"):
            st.success("✅ Google API Key configured")
        else:
            st.error("❌ Google API Key missing")

        st.divider()

        # Enhanced search settings
        st.subheader("🔍 Search Settings")
        max_results = st.slider("Max Results", 1, 12, 6)

        # Data source information
        st.subheader("📊 Enhanced Data Sources")
        st.info("🔍 **NIST NVD** - Complete vulnerability database with CVSS metrics")
        st.info("🔍 **MITRE CVE** - Original CVE database with classifications")
        st.info("🧠 **Google Gemini AI** - Intelligent analysis and recommendations")

        st.divider()

        # Legend for severity colors
        st.subheader("🎨 Severity Legend")
        st.markdown(
            """
            <div style="margin: 0.5rem 0;">
                <span class="severity-critical">CRITICAL</span>
                <span class="severity-high">HIGH</span>
                <span class="severity-medium">MEDIUM</span>
                <span class="severity-low">LOW</span>
                <span class="severity-unknown">UNKNOWN</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Initialize agent
    try:
        agent = initialize_agent()
    except ValueError as e:
        st.error(f"⚠️ {e}")
        st.info(
            "Please set your Google API key in the .env file or environment variables."
        )
        st.stop()

    # Enhanced search interface
    col1, col2 = st.columns([4, 1])

    with col1:
        search_query = st.text_input(
            "🔍 Enter software, CVE ID, or vulnerability description:",
            placeholder="e.g., CVE-2021-44228, Apache Log4j, Windows SMB, Chrome buffer overflow...",
        )

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        search_button = st.button("🚀 Search", type="primary", use_container_width=True)

    # Search execution
    if search_button and search_query.strip():

        # Show progress
        progress_bar = st.progress(0)
        status_text = st.empty()

        with st.spinner("🔍 Performing enhanced vulnerability search and analysis..."):
            start_time = time.time()

            # Update progress
            progress_bar.progress(25)
            status_text.text(
                "Searching NIST and MITRE databases with enhanced data extraction..."
            )

            # Single cached call for both CVE search and AI analysis
            cve_results, ai_analysis = cached_cve_search_with_ai(
                search_query, max_results
            )

            progress_bar.progress(100)
            status_text.text("Enhanced analysis complete!")
            time.sleep(0.5)  # Brief pause to show completion

            end_time = time.time()
            search_time = f"{end_time - start_time:.2f} seconds"

        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()

        # Display results
        if cve_results:
            st.success(
                f"✅ Found {len(cve_results)} CVE entries with enhanced data in {search_time}"
            )

            # Enhanced metrics display
            display_cve_summary_metrics(cve_results, search_time)

            st.divider()

            # AI Analysis section
            if ai_analysis:
                st.subheader("🤖 AI Security Analysis")
                with st.expander("View Enhanced AI Analysis", expanded=True):
                    st.markdown(ai_analysis)

                st.divider()

            # Enhanced CVE Results with improved filtering
            st.subheader(f"📋 Detailed CVE Analysis ({len(cve_results)} results)")

            # Enhanced filter options
            col1, col2, col3, col4 = st.columns(4)

            unique_severities = list(set(cve.severity.upper() for cve in cve_results))
            unique_sources = list(set(cve.source for cve in cve_results))
            unique_statuses = list(
                set(
                    cve.vuln_status
                    for cve in cve_results
                    if cve.vuln_status != "Unknown"
                )
            )

            with col1:
                severity_filter = st.multiselect(
                    "Filter by Severity:",
                    options=unique_severities,
                    default=unique_severities,
                )

            with col2:
                score_filter = st.slider("Min CVSS Score:", 0.0, 10.0, 0.0, 0.5)

            with col3:
                source_filter = st.multiselect(
                    "Filter by Source:",
                    options=unique_sources,
                    default=unique_sources,
                )

            with col4:
                if unique_statuses:
                    status_filter = st.multiselect(
                        "Filter by Status:",
                        options=unique_statuses,
                        default=unique_statuses,
                    )
                else:
                    status_filter = []

            # Additional filters
            col1, col2 = st.columns(2)

            with col1:
                has_cwe = st.checkbox(
                    "Only show CVEs with CWE classifications", value=False
                )

            with col2:
                has_products = st.checkbox(
                    "Only show CVEs with affected products", value=False
                )

            # Apply filters and sort
            filtered_results = []
            for cve in cve_results:
                # Basic filters
                if (
                    cve.severity.upper() in [s.upper() for s in severity_filter]
                    and cve.score >= score_filter
                    and cve.source in source_filter
                ):

                    # Status filter (only apply if there are statuses to filter)
                    if status_filter and cve.vuln_status not in status_filter:
                        continue

                    # CWE filter
                    if has_cwe and not cve.cwe_info:
                        continue

                    # Products filter
                    if has_products and not cve.affected_products:
                        continue

                    filtered_results.append(cve)

            # Sort by score (descending)
            filtered_results.sort(key=lambda x: x.score, reverse=True)

            # Display results
            if filtered_results:
                st.info(
                    f"Showing {len(filtered_results)} CVEs (from {len(cve_results)} total) with enhanced details"
                )

                for cve in filtered_results:
                    format_enhanced_cve_card(cve)
            else:
                st.error("❌ No CVEs match the current filters.")

        else:
            st.warning("⚠️ No CVE entries found for your search query.")
            st.info(
                """
            **Tips for better results:**
            - Try specific CVE IDs (e.g., CVE-2021-44228)
            - Use broader product terms (e.g., 'Chrome' vs 'Chrome 138.0.6408.109')
            - Search for vulnerability types (e.g., 'buffer overflow', 'privilege escalation')
            - Include version numbers for targeted searches
            """
            )

    elif search_button and not search_query.strip():
        st.error("❌ Please enter a search query.")

    # Enhanced footer
    st.divider()
    st.markdown(
        """
        <div style='text-align: center; color: #666; font-size: 0.8rem;'>
            🚀 Enhanced CVE Search Agent • Powered by NIST NVD, MITRE CVE & Google Gemini AI<br>
            <em>Comprehensive vulnerability intelligence with CWE classifications, CVSS metrics, and affected products</em>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
