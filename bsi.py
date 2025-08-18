import pandas as pd
from typing import TypedDict
from langgraph.graph import StateGraph, END, START

from nodes.export_excel import export_excel_node
from nodes.read_and_filter import read_and_filter_node
from nodes.create_findings import create_findings_node
from nodes.finding_vulnerability import finding_vulnerability_node


class GraphState(TypedDict):
    input_file: str
    output_file: str
    source_sheet: str | None
    success: bool
    error: str | None
    # New fields for intermediate data
    observations_df: pd.DataFrame | None
    findings_df: pd.DataFrame | None
    original_df: pd.DataFrame | None
    enriched_findings_df: pd.DataFrame | None


def create_workflow():
    workflow = StateGraph(GraphState)

    # Add three nodes
    workflow.add_node("read_and_filter", read_and_filter_node)
    workflow.add_node("create_findings", create_findings_node)
    workflow.add_node("finding_vulnerability", finding_vulnerability_node)
    workflow.add_node("export_excel", export_excel_node)

    # Define the flow
    workflow.add_edge(START, "read_and_filter")
    workflow.add_edge("read_and_filter", "create_findings")
    workflow.add_edge("create_findings", "finding_vulnerability")
    workflow.add_edge("finding_vulnerability", "export_excel")
    workflow.add_edge("export_excel", END)

    return workflow.compile()


# Usage
if __name__ == "__main__":
    workflow = create_workflow()
    result = workflow.invoke(
        {
            "input_file": "input/BSI Raw Report.xlsx",
            "output_file": "bsi_processed_output.xlsx",
            "source_sheet": None,
            "success": False,
            "error": None,
            "observations_df": None,
            "findings_df": None,
            "original_df": None,
        }
    )

    print(f"\n🏁 Final Result: {'Success' if result['success'] else 'Failed'}")
    if result.get("error"):
        print(f"Error: {result['error']}")
