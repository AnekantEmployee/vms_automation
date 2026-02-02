#!/usr/bin/env python3
"""Test script to verify the StructuredTool fix."""

import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from cve_search.main import combined_cve_search
    
    print("Testing the CVE search with the fix...")
    
    # Test with a simple query
    test_query = "Web Server Uses Plain-Text Form Based Authentication"
    print(f"Testing query: {test_query}")
    
    results = combined_cve_search(test_query, max_results=5)
    
    if results:
        print(f"Success! Found {len(results)} CVE results:")
        for i, result in enumerate(results[:3], 1):
            print(f"{i}. {result.cve_id}: {result.description[:100]}...")
    else:
        print("No results found, but no error occurred - fix successful!")
        
except Exception as e:
    print(f"Error occurred: {e}")
    import traceback
    traceback.print_exc()