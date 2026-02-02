"""Gemini AI service for query analysis."""

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

from ..config.rate_limiting import gemini_rate_limiter
from ..config.settings import TIMEOUT_CONFIG
from ..utils.retry import exponential_backoff_retry


def analyze_query_with_gemini(query: str) -> str:
    """Analyze query using Gemini AI with enhanced rate limiting and error handling."""
    print(f"Analyzing query with Gemini: '{query}'")
    
    try:
        # Apply rate limiting for Gemini API
        gemini_rate_limiter.wait_if_needed()
        
        # Create LLM with timeout configuration
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash", 
            temperature=0.1, 
            max_tokens=150,
            timeout=TIMEOUT_CONFIG['gemini_api']
        )
        
        prompt = f"""
        Analyze this security vulnerability query and extract the most important search terms for finding CVEs:
        Query: "{query}"
        Focus on:
        1. Software/product names (Apache, Linux, Windows, etc.)
        2. Vulnerability types (RCE, XSS, buffer overflow, directory listing, etc.)
        3. Technical components (SSL, SSH, authentication, etc.)
        Return only the key search terms, maximum 6 words, separated by spaces.
        Be specific and use terms commonly found in CVE descriptions.
        Search terms:"""
        
        @exponential_backoff_retry
        def call_llm():
            return llm.invoke([HumanMessage(content=prompt)])
        
        response = call_llm()
        enhanced_query = response.content.strip().lower()
        
        print(f"Gemini enhanced query: {enhanced_query}")
        return enhanced_query
        
    except Exception as e:
        print(f"Gemini query analysis failed: {e}")
        raise