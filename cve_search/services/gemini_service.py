"""Gemini AI service for query analysis."""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from config.api_key_manager import generate_content_with_fallback

def analyze_query_with_gemini(query: str) -> str:
    """Analyze query using Gemini AI with automatic API key rotation."""
    print(f"Analyzing query with Gemini: '{query}'")
    
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
    
    try:
        enhanced_query = generate_content_with_fallback(
            prompt,
            generation_config={
                'temperature': 0.1,
                'max_output_tokens': 150
            }
        ).strip().lower()
        
        print(f"Gemini enhanced query: {enhanced_query}")
        return enhanced_query
        
    except Exception as e:
        print(f"Gemini query analysis failed: {e}")
        raise