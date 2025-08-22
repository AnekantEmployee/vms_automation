"""External search service using Tavily API."""

import time
import json

from ..config.rate_limiting import tavily_rate_limiter
from ..config.settings import TIMEOUT_CONFIG
from ..utils.retry import exponential_backoff_retry

# Optional TavilySearch import
try:
    from langchain_community.tools.tavily_search import TavilySearchResults
    TAVILY_AVAILABLE = True
    print("TavilySearch available")
except ImportError:
    TAVILY_AVAILABLE = False
    print("TavilySearch not available - continuing without it")


@exponential_backoff_retry
def search_external_cve_info(query: str) -> str:
    """Search for additional CVE information using external search if available."""
    if not TAVILY_AVAILABLE:
        print("External search not available")
        return f"External search not available. Query was: {query}"
    
    try:
        tavily_rate_limiter.wait_if_needed()
        
        search = TavilySearchResults(max_results=3, search_depth="basic")
        cve_query = f"CVE vulnerability {query} security"
        
        # Set timeout for Tavily search
        start_time = time.time()
        timeout = TIMEOUT_CONFIG['tavily_api']
        
        results = search.run(cve_query)
        
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            raise TimeoutError(f"Tavily search timed out after {elapsed_time:.2f} seconds")
        
        if results:
            print(f"Found {len(results)} external results for: {query}")
            return f"External search results for '{query}': {json.dumps(results, indent=2)}"
        else:
            return f"No external results found for: {query}"
            
    except Exception as e:
        print(f"External search failed: {e}")
        return f"External search failed: {str(e)}"