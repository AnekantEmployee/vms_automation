import pandas as pd
from components.identify_vulnerability import create_vulnerability_analysis_from_columns


def create_findings_node(state):
    """
    Process Observations sheet columns to create unique vulnerability findings
    """
    try:
        print("🔍 Processing Observations sheet columns for unique vulnerabilities...")

        if not state.get("success", False):
            raise Exception("Previous node failed or no data available")

        observations_df = state["observations_df"]

        if observations_df is None or observations_df.empty:
            raise Exception("Observations DataFrame is empty or None")

        print(
            f"📊 Found observations data with {len(observations_df)} rows and {len(observations_df.columns)} columns"
        )

        # Analyze columns for vulnerabilities
        vulnerability_findings = create_vulnerability_analysis_from_columns(
            observations_df
        )

        if vulnerability_findings:
            findings_df = pd.DataFrame(vulnerability_findings)
            findings_df = findings_df.sort_values("Vulnerability", ascending=True)
            print(
                f"✓ Created findings sheet with {len(findings_df)} unique vulnerability entries"
            )
        else:
            findings_df = pd.DataFrame(
                {
                    "Result": ["No specific vulnerabilities identified"],
                    "Analysis_Summary": [
                        f"Processed {len(observations_df.columns)} columns (top 5 values each)"
                    ],
                    "Note": ["Consider manual review of the observations data"],
                }
            )
            print("✓ No vulnerabilities identified in columns")

        return {
            "success": True,
            "error": None,
            "findings_df": findings_df,
            "total_vulnerabilities": len(vulnerability_findings),
            "total_columns_processed": len(observations_df.columns),
        }

    except Exception as e:
        print(f"✗ Error in create_findings_node: {e}")
        return {
            "success": False,
            "error": str(e),
            "findings_df": pd.DataFrame(
                {"Error": [f"Failed to process observations: {str(e)}"]}
            ),
        }
