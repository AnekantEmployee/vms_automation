"""Main entry point for CVE search system."""

import time
from typing import List
from langchain_core.messages import HumanMessage

from .models.data_models import CVEResult
from .agents.agent_graph import create_cve_agent
from .config.settings import TIMEOUT_CONFIG
from .config.rate_limiting import get_rate_limiter_status


def combined_cve_search(query: str, max_results: int = 10) -> List[CVEResult]:
    """Enhanced CVE search using agent-based approach with rate limiting and timeout handling."""
    print(f"======== Starting Enhanced Agent-Based CVE Search ========")
    print(f"Initial Query: '{query}'")
    print(f"Max Results: {max_results}")
    print(f"Rate Limiting: Enabled")
    print(f"Timeout Handling: Enabled")
    print(f"========================================================")
    
    try:
        agent = create_cve_agent()
        initial_state = {
            "messages": [HumanMessage(content=f"Search for CVEs related to: {query}")],
            "original_query": query,
            "enhanced_queries": [],
            "search_results": [],
            "cve_results": [],
            "search_attempts": 0,
            "max_attempts": 3,
            "search_strategy": "multi_source",
            "external_search_done": False
        }
        
        config = {
            "recursion_limit": 10,
            "timeout": TIMEOUT_CONFIG.get('default', 30) * 5  # 5x default timeout for full workflow
        }
        
        start_time = time.time()
        final_state = agent.invoke(initial_state, config=config)
        end_time = time.time()
        
        cve_results = final_state.get("cve_results", [])
        
        print(f"\n======== Enhanced Agent Search Complete ========")
        print(f"Total execution time: {end_time - start_time:.2f} seconds")
        print(f"Rate limiting applied successfully")
        print(f"Agent found {len(cve_results)} relevant CVE(s).")
        print(f"===============================================")
        
        if cve_results:
            return cve_results[:max_results]
        else:
            print(f"Agent found no relevant CVEs for query: '{query}'")
            return []
            
    except Exception as e:
        print(f"\n!!!!!!!! An error occurred during the enhanced agent search !!!!!!!!")
        print(f"Error for query '{query}': {e}")
        import traceback
        traceback.print_exc()
        return []
