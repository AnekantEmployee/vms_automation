"""Agent graph construction for CVE search workflow."""

from langgraph.graph import StateGraph, START, END

from ..models.data_models import CVESearchState
from .agent_nodes import (
    query_analyzer_node,
    cve_search_node,
    external_search_node,
    result_scorer_node,
    should_continue_search
)


def create_cve_agent():
    """Create the CVE search agent using LangGraph."""
    workflow = StateGraph(CVESearchState)
    
    # Add nodes
    workflow.add_node("analyze_query", query_analyzer_node)
    workflow.add_node("search_cves", cve_search_node)
    # workflow.add_node("external_search", external_search_node)
    workflow.add_node("score_results", result_scorer_node)
    
    # Add edges
    workflow.add_edge(START, "analyze_query")
    workflow.add_edge("analyze_query", "search_cves")
    
    # Add conditional edges
    workflow.add_conditional_edges(
        "search_cves",
        should_continue_search,
        {
            "score_results": "score_results",
            "continue_search": "search_cves",
            "external_search": "external_search"
        }
    )
    
    workflow.add_edge("external_search", END)
    workflow.add_edge("score_results", END)
    
    # Compile and return the agent
    app = workflow.compile()
    return app