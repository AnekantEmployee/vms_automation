#!/usr/bin/env python3
"""Test the LLM-driven CVE search system."""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_llm_driven_search():
    """Test LLM-driven CVE search."""
    print("=" * 80)
    print("Testing LLM-Driven CVE Search")
    print("=" * 80)
    
    try:
        # Import the LLM-driven version
        from cve_search.core_functions_llm import combined_cve_search
        
        test_query = "Web Server Uses Plain-Text Form Based Authentication"
        print(f"\nQuery: {test_query}\n")
        
        results = combined_cve_search(test_query, max_results=10)
        
        if results:
            print(f"\n✅ SUCCESS! Found {len(results)} CVE results:\n")
            for i, result in enumerate(results, 1):
                print(f"{i}. {result.cve_id}")
                print(f"   Severity: {result.severity} (Score: {result.score})")
                print(f"   Confidence: {result.confidence_score:.2f}")
                print(f"   Reasoning: {result.relevance_explanation}")
                print(f"   Description: {result.description[:120]}...")
                if result.cwe_details:
                    print(f"   CWEs:")
                    for cwe in result.cwe_details:
                        print(f"     - {cwe.cwe_id}: {cwe.name}")
                print()
        else:
            print("\n⚠️  No results found")
        
        return len(results) > 0
    
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_various_vulnerabilities():
    """Test with different vulnerability types."""
    print("\n" + "=" * 80)
    print("Testing Various Vulnerability Types")
    print("=" * 80)
    
    try:
        from cve_search.core_functions_llm import combined_cve_search
        
        test_cases = [
            "SQL Injection in web application",
            "Cross-Site Scripting vulnerability",
            "Buffer Overflow in C library",
            "Weak SSL/TLS Configuration",
            "Default Administrator Credentials"
        ]
        
        results_summary = []
        
        for query in test_cases:
            print(f"\n{'=' * 60}")
            print(f"Testing: {query}")
            print('=' * 60)
            
            results = combined_cve_search(query, max_results=3)
            
            count = len(results)
            results_summary.append((query, count))
            
            if results:
                print(f"\n✓ Found {count} CVEs:")
                for r in results:
                    print(f"  - {r.cve_id}: Score {r.score}, Confidence {r.confidence_score:.2f}")
                    print(f"    {r.relevance_explanation[:80]}...")
            else:
                print(f"\n✗ No CVEs found")
        
        print("\n" + "=" * 80)
        print("Summary:")
        print("=" * 80)
        for query, count in results_summary:
            status = "✅" if count > 0 else "❌"
            print(f"{status} {query}: {count} CVEs")
        
        total = sum(count for _, count in results_summary)
        print(f"\nTotal CVEs found: {total}")
        
        return total > 0
    
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("LLM-DRIVEN CVE SEARCH TEST SUITE")
    print("=" * 80)
    
    tests = [
        ("Original Problem Query", test_llm_driven_search),
        ("Various Vulnerabilities", test_various_vulnerabilities)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\n❌ {test_name} crashed: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 80)
    print("FINAL RESULTS")
    print("=" * 80)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    passed = sum(1 for _, success in results if success)
    print(f"\nResults: {passed}/{len(results)} tests passed")
    print("=" * 80 + "\n")
    
    sys.exit(0 if passed == len(results) else 1)