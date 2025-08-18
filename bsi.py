import pandas as pd
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, END, START

from nodes.export_excel import export_excel_node
from nodes.read_and_filter import read_and_filter_node
from nodes.create_findings import create_findings_node
from nodes.finding_vulnerability import finding_vulnerability_node
from nodes.analyze_vulnerability import analyze_vulnerability_node


class GraphState(TypedDict):
    input_file: str
    output_file: str
    source_sheet: Optional[str]
    success: bool
    error: Optional[str]
    # Intermediate data fields
    observations_df: Optional[pd.DataFrame]
    findings_df: Optional[pd.DataFrame]
    original_df: Optional[pd.DataFrame]
    enriched_findings_df: Optional[pd.DataFrame]
    # New fields for vulnerability analysis
    scorecard_df: Optional[pd.DataFrame]
    security_posture_score: Optional[float]
    security_grade: Optional[str]


def create_workflow():
    """Create and configure the vulnerability analysis workflow"""
    workflow = StateGraph(GraphState)

    # Add nodes to the workflow
    workflow.add_node("read_and_filter", read_and_filter_node)
    workflow.add_node("create_findings", create_findings_node)
    workflow.add_node("finding_vulnerability", finding_vulnerability_node)
    workflow.add_node("analyze_vulnerability", analyze_vulnerability_node)
    workflow.add_node("export_excel", export_excel_node)

    # Define the workflow edges
    workflow.add_edge(START, "read_and_filter")
    workflow.add_edge("read_and_filter", "create_findings")
    workflow.add_edge("create_findings", "finding_vulnerability")
    workflow.add_edge("finding_vulnerability", "analyze_vulnerability")
    workflow.add_edge("analyze_vulnerability", "export_excel")
    workflow.add_edge("export_excel", END)

    # Add error handling (optional)
    # workflow.add_edge("read_and_filter", END, "error")
    # workflow.add_edge("create_findings", END, "error")
    # ... etc for other nodes

    return workflow.compile()


def main():
    """Execute the vulnerability analysis workflow"""
    try:
        print("🚀 Starting vulnerability analysis workflow...")
        
        workflow = create_workflow()
        
        # Initial state with file paths
        initial_state = {
            "input_file": "input/BSI Raw Report.xlsx",
            "output_file": "output/BSI_Processed_Report.xlsx",  # Updated output path
            "source_sheet": None,
            "success": False,
            "error": None,
            "observations_df": None,
            "findings_df": None,
            "original_df": None,
            "enriched_findings_df": None,
            "scorecard_df": None,
            "security_posture_score": None,
            "security_grade": None
        }
        
        # Execute the workflow
        result = workflow.invoke(initial_state)
        
        # Print results
        print(f"\n🏁 Final Result: {'SUCCESS' if result['success'] else 'FAILED'}")
        if result.get("security_posture_score"):
            print(f"🔒 Security Posture: {result['security_posture_score']}% ({result['security_grade']})")
        if result.get("error"):
            print(f"❌ Error: {result['error']}")
        
        return result
        
    except Exception as e:
        print(f"🔥 Critical workflow error: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    main()