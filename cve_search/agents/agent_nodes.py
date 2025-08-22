"""Agent node implementations for CVE search workflow."""

from langchain_core.messages import AIMessage

from ..models.data_models import CVESearchState
from ..services.gemini_service import analyze_query_with_gemini
from ..services.external_search import search_external_cve_info
from ..tools.search_tools import extract_cve_keywords, search_cve_databases
from ..utils.helpers import calculate_relevance_score


def query_analyzer_node(state: CVESearchState) -> CVESearchState:
    """Analyze query with enhanced rate limiting and error handling."""
    print(f"\n--- Analyzing Query ---")
    print(f"Original query: {state['original_query']}")
    
    try:
        enhanced_query = analyze_query_with_gemini(state['original_query'])
        
        if not enhanced_query or len(enhanced_query) < 5:
            enhanced_query = extract_cve_keywords(state['original_query'])
        
        print(f"LLM Enhanced query: {enhanced_query}")
        
        enhanced_queries = list(dict.fromkeys([
            enhanced_query,
            extract_cve_keywords(state['original_query']),
            state['original_query'].lower()
        ]))
        
        return {
            **state,
            "enhanced_queries": enhanced_queries,
            "messages": state["messages"] + [AIMessage(content=f"Generated enhanced queries: {enhanced_queries}")]
        }
        
    except Exception as e:
        print(f"Query analysis failed: {e}")
        enhanced_query = extract_cve_keywords(state['original_query'])
        return {
            **state,
            "enhanced_queries": [enhanced_query, state['original_query'].lower()],
            "messages": state["messages"] + [AIMessage(content=f"Fallback query enhancement: {enhanced_query}")]
        }


def cve_search_node(state: CVESearchState) -> CVESearchState:
    """Search CVEs with enhanced rate limiting and timeout handling."""
    print(f"\n--- Searching for CVEs ---")
    search_attempts = state.get('search_attempts', 0)
    print(f"Attempt {search_attempts + 1}/{state.get('max_attempts', 3)}")
    
    if search_attempts >= state.get('max_attempts', 3):
        print("Max search attempts reached")
        return state

    all_results = []
    query_to_try = state['enhanced_queries'][search_attempts]
    print(f"Using query: '{query_to_try}'")
    
    # Search in actual CVE databases with error handling
    try:
        results = search_cve_databases(query_to_try)
        
        if results:
            all_results.extend(results)
            print(f"Found {len(results)} potential results for query.")
        else:
            print(f"No results found for query.")
            
    except Exception as e:
        print(f"CVE database search failed: {e}")
        # Continue with empty results rather than failing completely
    
    existing_cves = {cve.cve_id for cve in state.get('cve_results', [])}
    unique_results = [res for res in all_results if res.cve_id not in existing_cves]
    
    final_results = state.get('cve_results', []) + unique_results
    print(f"Total unique CVEs found so far: {len(final_results)}")
    
    return {
        **state,
        "cve_results": final_results,
        "search_attempts": search_attempts + 1,
        "messages": state["messages"] + [AIMessage(content=f"Found {len(unique_results)} new CVE results in attempt {search_attempts + 1}")]
    }


def external_search_node(state: CVESearchState) -> CVESearchState:
    """External search with enhanced error handling."""
    print("\n--- Performing External Search ---")
    if state.get('external_search_done', False):
        print("External search already completed.")
        return state
        
    try:
        external_results = search_external_cve_info(state['original_query'])
        return {
            **state,
            "search_results": [{"external_search": external_results}],
            "external_search_done": True,
            "messages": state["messages"] + [AIMessage(content="Performed external search for additional context")]
        }
    except Exception as e:
        print(f"External search failed: {e}")
        return {
            **state,
            "external_search_done": True,
            "messages": state["messages"] + [AIMessage(content=f"External search failed: {str(e)}")]
        }


def result_scorer_node(state: CVESearchState) -> CVESearchState:
    """Score results with error handling."""
    print("\n--- Scoring and Ranking Results ---")
    if not state['cve_results']:
        print("No CVE results to score.")
        return state
    
    try:
        print(f"Scoring {len(state['cve_results'])} CVE results...")
        for result in state['cve_results']:
            result.confidence_score = calculate_relevance_score(result, state['original_query'])
        
        state['cve_results'].sort(key=lambda x: (x.confidence_score, x.score), reverse=True)
        print("CVE results scored and ranked successfully.")
        
        return {
            **state,
            "messages": state["messages"] + [AIMessage(content="Scored and ranked CVE results by relevance")]
        }
    except Exception as e:
        print(f"Result scoring failed: {e}")
        return state


def should_continue_search(state: CVESearchState) -> str:
    """Decide next step based on search results and attempts."""
    print("\n--- Making a Decision ---")
    if state.get('cve_results'):
        print("Decision: Found CVE results. Proceeding to scoring.")
        return "score_results"
    
    if state.get('search_attempts', 0) < state.get('max_attempts', 3):
        print("Decision: No results yet, continuing search with next query.")
        return "continue_search"
    
    print("Decision: Max internal search attempts reached without results. Trying external search.")
    return "external_search"