#!/usr/bin/env python3
"""Test CVE search with real vulnerability inputs and save results"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cve_search.core_functions import combined_cve_search

def test_vulnerability_inputs():
    """Test CVE search with provided vulnerability inputs"""
    
    vulnerabilities = [
        "SSL Certificate - Signature Verification Failed Vulnerability",
        "Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-7682-1)",
        "Ubuntu Security Notification for Linux kernel Vulnerabilities (USN-7654-1)",
        "SHA1 deprecated setting for SSH",
        "Deprecated SSH Cryptographic Settings",
        "Web Server Uses Plain-Text Form Based Authentication",
        "SSL Certificate - Self-Signed Certificate"
    ]
    
    results = []
    results.append("=" * 80)
    results.append("CVE SEARCH RESULTS FOR VULNERABILITY INPUTS")
    results.append("=" * 80)
    results.append("")
    
    total_cves = 0
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n[{i}/{len(vulnerabilities)}] Testing: {vuln}")
        results.append(f"[{i}] {vuln}")
        results.append("-" * 60)
        
        try:
            cves = combined_cve_search(vuln, max_results=5)
            
            if cves:
                results.append(f"Found {len(cves)} relevant CVEs:")
                total_cves += len(cves)
                
                for j, cve in enumerate(cves, 1):
                    results.append(f"  {j}. {cve.cve_id} - Score: {cve.score} - {cve.severity}")
                    results.append(f"     {cve.description[:100]}...")
                    if hasattr(cve, 'confidence_score'):
                        results.append(f"     Confidence: {cve.confidence_score:.2f}")
            else:
                results.append("No relevant CVEs found")
                
        except Exception as e:
            results.append(f"Error: {str(e)}")
        
        results.append("")
    
    # Summary
    results.append("=" * 80)
    results.append("SUMMARY")
    results.append("=" * 80)
    results.append(f"Total vulnerabilities tested: {len(vulnerabilities)}")
    results.append(f"Total CVEs found: {total_cves}")
    results.append(f"Average CVEs per vulnerability: {total_cves/len(vulnerabilities):.1f}")
    results.append("")
    
    # Success rate
    successful = sum(1 for line in results if "Found" in line and "relevant CVEs" in line)
    success_rate = (successful / len(vulnerabilities)) * 100
    results.append(f"Success rate: {successful}/{len(vulnerabilities)} ({success_rate:.1f}%)")
    
    return "\n".join(results)

if __name__ == "__main__":
    print("Testing CVE search with vulnerability inputs...")
    results_text = test_vulnerability_inputs()
    print("\nTest completed!")
    
    # Save results
    with open("vms-explaination.txt", "w", encoding="utf-8") as f:
        f.write(results_text)
    
    print("Results saved to vms-explaination.txt")