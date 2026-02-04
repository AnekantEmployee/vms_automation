#!/usr/bin/env python3
"""
Test the improved CVE search system with advanced validation
"""

import os
import sys
import json
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from improved_cve_search import ImprovedCVESearcher, format_results_for_display

def main():
    """Test the improved system"""
    
    load_dotenv()
    
    tavily_api_key = os.getenv("TAVILY_API_KEY")
    
    if not tavily_api_key:
        print("❌ TAVILY_API_KEY not found")
        return
    
    print("✅ API keys loaded")
    print()
    
    # Initialize searcher
    searcher = ImprovedCVESearcher(tavily_api_key=tavily_api_key)
    
    # Test cases
    test_cases = [
        {
            "vulnerability": "SSL Certificate - Signature Verification Failed Vulnerability",
            "context": {
                "Operating System": "Linux Ubuntu 20.04",
                "Asset Type": "Web Server"
            }
        },
        {
            "vulnerability": "SHA1 deprecated setting for SSH",
            "context": {
                "Operating System": "Linux",
                "Service": "OpenSSH"
            }
        },
        {
            "vulnerability": "Web Server Uses Plain-Text Form Based Authentication",
            "context": {
                "Operating System": "Windows Server 2019",
                "Service": "IIS"
            }
        },
        {
            "vulnerability": "SQL Injection vulnerability in login form",
            "context": {
                "Application": "Web Application",
                "Framework": "PHP"
            }
        },
        {
            "vulnerability": "Remote Code Execution via buffer overflow",
            "context": {
                "Operating System": "Windows 10",
                "Component": "SMB"
            }
        }
    ]
    
    all_results = []
    
    print("=" * 80)
    print("IMPROVED CVE SEARCH SYSTEM - TEST SUITE")
    print("=" * 80)
    print(f"Testing {len(test_cases)} vulnerabilities with ADVANCED VALIDATION")
    print("=" * 80)
    print()
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'#' * 80}")
        print(f"TEST CASE {i}/{len(test_cases)}")
        print(f"{'#' * 80}\n")
        
        try:
            results = searcher.search_vulnerability(
                vulnerability_description=test_case["vulnerability"],
                context=test_case.get("context"),
                max_cves=5
            )
            
            all_results.append(results)
            
            # Display results
            print("\n" + format_results_for_display(results))
            
            # Save individual result
            filename = f"improved_result_{i}.json"
            with open(filename, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to {filename}")
            
        except Exception as e:
            print(f"\n❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n\n" + "=" * 80)
    print("TEST SUMMARY - IMPROVED SYSTEM")
    print("=" * 80)
    
    total_cves = sum(len(r.get("cves", [])) for r in all_results)
    total_cwes = sum(len(r.get("cwes", [])) for r in all_results)
    
    # Calculate average relevance scores
    all_scores = []
    for r in all_results:
        for cve in r.get("cves", []):
            all_scores.append(cve.get("relevance_score", 0))
    
    avg_relevance = sum(all_scores) / len(all_scores) if all_scores else 0
    
    print(f"\nTotal test cases: {len(test_cases)}")
    print(f"Successful searches: {len(all_results)}")
    print(f"Total CVEs found: {total_cves}")
    print(f"Total CWEs identified: {total_cwes}")
    print(f"Average Relevance Score: {avg_relevance:.2f}")
    print(f"CVEs with score >= 0.7: {sum(1 for s in all_scores if s >= 0.7)}")
    print(f"CVEs with score >= 0.5: {sum(1 for s in all_scores if s >= 0.5)}")
    print(f"CVEs with score < 0.5: {sum(1 for s in all_scores if s < 0.5)}")
    
    # Save summary
    summary = {
        "test_cases": len(test_cases),
        "successful": len(all_results),
        "total_cves": total_cves,
        "total_cwes": total_cwes,
        "average_relevance_score": avg_relevance,
        "high_confidence_cves": sum(1 for s in all_scores if s >= 0.7),
        "medium_confidence_cves": sum(1 for s in all_scores if 0.5 <= s < 0.7),
        "low_confidence_cves": sum(1 for s in all_scores if s < 0.5),
        "results": all_results
    }
    
    with open("improved_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print("\n💾 Full summary saved to improved_summary.json")
    print("\n" + "=" * 80)
    print("TESTING COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()