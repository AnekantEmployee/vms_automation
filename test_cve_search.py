"""
Quick test script to verify CVE search functionality
"""
import os
import json
from dotenv import load_dotenv
from enhanced_cve_search.improved_cve_search import EnhancedCVESearchSystem

load_dotenv()

def test_cve_search():
    tavily_key = os.getenv("TAVILY_API_KEY")
    if not tavily_key:
        print("❌ TAVILY_API_KEY not found")
        return
    
    print("="*80)
    print("TESTING CVE SEARCH SYSTEM")
    print("="*80)
    
    searcher = EnhancedCVESearchSystem(tavily_api_key=tavily_key)
    
    # Test vulnerability
    test_vuln = "Cisco Internetwork Operating System (IOS) and IOS XE Software SNMPv3 Configuration Restriction Vulnerability"
    test_context = {"Operating System": "Cisco Device"}
    
    print(f"\nTest Query: {test_vuln}")
    print(f"Context: {test_context}")
    print("\n" + "="*80 + "\n")
    
    # Run search
    results = searcher.search_vulnerability(
        vulnerability_description=test_vuln,
        context=test_context,
        max_cves=5
    )
    
    # Check results
    print("\n" + "="*80)
    print("RESULTS ANALYSIS")
    print("="*80)
    
    print(f"\nResult Type: {type(results)}")
    print(f"Has 'cves' attribute: {hasattr(results, 'cves')}")
    
    if hasattr(results, 'cves'):
        cve_list = results.cves
        print(f"CVE Count: {len(cve_list)}")
        
        if cve_list:
            print("\n✅ CVEs Found:")
            for i, cve in enumerate(cve_list, 1):
                print(f"  {i}. {cve.cve_id} - {cve.severity} (Score: {cve.score})")
                print(f"     Description: {cve.description[:100]}...")
                print(f"     Relevance: {cve.relevance_score:.2f}")
        else:
            print("\n❌ No CVEs found in results.cves list")
    else:
        print("\n❌ Results object does not have 'cves' attribute")
    
    # Save to JSON for inspection
    output_file = "test_cve_output.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results.to_dict(), f, indent=2)
        print(f"\n✅ Full results saved to: {output_file}")
    except Exception as e:
        print(f"\n❌ Failed to save JSON: {e}")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    test_cve_search()
