import re
import json
from datetime import datetime
from tavily import TavilyClient
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional



@dataclass
class EnhancedCVEInfo:
    """Enhanced CVE (Common Vulnerabilities and Exposures) Information with all required properties"""
    cve_id: str
    description: str
    severity: str
    score: float  # CVSS score (formerly cvss_score)
    published_date: str
    modified_date: str
    
    # CVSS Details
    vector_string: str = ""  # CVSS vector (formerly cvss_vector)
    cvss_version: str = ""  # e.g., "3.1", "3.0", "2.0"
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    
    # Status and Source
    source: str = "NIST NVD"
    vuln_status: str = "Unknown"  # e.g., "Analyzed", "Modified", "Undergoing Analysis"
    
    # Affected Products and References
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Additional Metadata
    confidence_score: float = 1.0  # Confidence in the CVE match (0.0 to 1.0)
    exploit_available: bool = False
    patch_available: bool = False
    
    # Validation metadata (from advanced search)
    relevance_score: float = 0.0
    relevance_reasoning: str = ""
    
    # Additional NIST fields
    cpe_configurations: List[str] = field(default_factory=list)  # CPE URIs
    vendor_comments: List[str] = field(default_factory=list)
    cvss_metrics_v3: Dict[str, Any] = field(default_factory=dict)
    cvss_metrics_v2: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "published_date": self.published_date,
            "modified_date": self.modified_date,
            "vector_string": self.vector_string,
            "cvss_version": self.cvss_version,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "source": self.source,
            "vuln_status": self.vuln_status,
            "affected_products": self.affected_products,
            "references": self.references,
            "confidence_score": self.confidence_score,
            "exploit_available": self.exploit_available,
            "patch_available": self.patch_available,
            "relevance_score": self.relevance_score,
            "relevance_reasoning": self.relevance_reasoning,
            "cpe_configurations": self.cpe_configurations,
            "vendor_comments": self.vendor_comments,
            "cvss_metrics_v3": self.cvss_metrics_v3,
            "cvss_metrics_v2": self.cvss_metrics_v2
        }


@dataclass
class StructuredSearchResults:
    """Structured results with CVE lists"""
    query: str
    timestamp: str
    context: Dict[str, Any]
    
    # CVE list
    cves: List[EnhancedCVEInfo] = field(default_factory=list)
    
    # Analysis and metadata
    analysis: Dict[str, Any] = field(default_factory=dict)
    search_strategy: List[Dict[str, str]] = field(default_factory=list)
    summary_statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "query": self.query,
            "timestamp": self.timestamp,
            "context": self.context,
            "cves": [cve.to_dict() for cve in self.cves],
            "analysis": self.analysis,
            "search_strategy": self.search_strategy,
            "summary_statistics": self.summary_statistics
        }
    
    def get_cve_list(self) -> List[Dict[str, Any]]:
        """Get list of CVE dictionaries"""
        return [cve.to_dict() for cve in self.cves]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return {
            "total_cves": len(self.cves),
            "severity_breakdown": self._get_severity_breakdown(),
            "average_cvss_score": self._get_average_cvss(),
            "average_relevance_score": self._get_average_relevance(),
            "date_range": self._get_date_range()
        }
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of CVEs by severity"""
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for cve in self.cves:
            severity = cve.severity.upper()
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown["UNKNOWN"] += 1
        return breakdown
    
    def _get_average_cvss(self) -> float:
        """Get average CVSS score"""
        if not self.cves:
            return 0.0
        return sum(cve.score for cve in self.cves) / len(self.cves)
    
    def _get_average_relevance(self) -> float:
        """Get average relevance score"""
        if not self.cves:
            return 0.0
        return sum(cve.relevance_score for cve in self.cves) / len(self.cves)
    

    
    def _get_date_range(self) -> Dict[str, str]:
        """Get date range of CVEs"""
        if not self.cves:
            return {"earliest": "N/A", "latest": "N/A"}
        
        dates = [cve.published_date for cve in self.cves if cve.published_date]
        if not dates:
            return {"earliest": "N/A", "latest": "N/A"}
        
        return {
            "earliest": min(dates)[:10] if dates else "N/A",
            "latest": max(dates)[:10] if dates else "N/A"
        }


class EnhancedCVEParser:
    """Enhanced parser for NIST CVE data with complete field extraction"""
    
    @staticmethod
    def parse_nist_cve(cve_data: Dict[str, Any]) -> Optional[EnhancedCVEInfo]:
        """Parse CVE from NIST response with all available fields"""
        try:
            cve_id = cve_data.get("id", "")
            
            # Description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Vulnerability Status
            vuln_status = cve_data.get("vulnStatus", "Unknown")
            
            # CVSS metrics - try v3.1, v3.0, then v2.0
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            vector = ""
            cvss_version = ""
            exploitability_score = 0.0
            impact_score = 0.0
            cvss_v3_metrics = {}
            cvss_v2_metrics = {}
            
            # Try CVSS v3.1
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                vector = cvss_data.get("vectorString", "")
                cvss_version = "3.1"
                exploitability_score = metrics["cvssMetricV31"][0].get("exploitabilityScore", 0.0)
                impact_score = metrics["cvssMetricV31"][0].get("impactScore", 0.0)
                cvss_v3_metrics = {
                    "attackVector": cvss_data.get("attackVector", ""),
                    "attackComplexity": cvss_data.get("attackComplexity", ""),
                    "privilegesRequired": cvss_data.get("privilegesRequired", ""),
                    "userInteraction": cvss_data.get("userInteraction", ""),
                    "scope": cvss_data.get("scope", ""),
                    "confidentialityImpact": cvss_data.get("confidentialityImpact", ""),
                    "integrityImpact": cvss_data.get("integrityImpact", ""),
                    "availabilityImpact": cvss_data.get("availabilityImpact", "")
                }
            
            # Try CVSS v3.0
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                vector = cvss_data.get("vectorString", "")
                cvss_version = "3.0"
                exploitability_score = metrics["cvssMetricV30"][0].get("exploitabilityScore", 0.0)
                impact_score = metrics["cvssMetricV30"][0].get("impactScore", 0.0)
                cvss_v3_metrics = {
                    "attackVector": cvss_data.get("attackVector", ""),
                    "attackComplexity": cvss_data.get("attackComplexity", ""),
                    "privilegesRequired": cvss_data.get("privilegesRequired", ""),
                    "userInteraction": cvss_data.get("userInteraction", ""),
                    "scope": cvss_data.get("scope", ""),
                    "confidentialityImpact": cvss_data.get("confidentialityImpact", ""),
                    "integrityImpact": cvss_data.get("integrityImpact", ""),
                    "availabilityImpact": cvss_data.get("availabilityImpact", "")
                }
            
            # Try CVSS v2.0
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = EnhancedCVEParser._cvss2_to_severity(cvss_score)
                vector = cvss_data.get("vectorString", "")
                cvss_version = "2.0"
                exploitability_score = metrics["cvssMetricV2"][0].get("exploitabilityScore", 0.0)
                impact_score = metrics["cvssMetricV2"][0].get("impactScore", 0.0)
                cvss_v2_metrics = {
                    "accessVector": cvss_data.get("accessVector", ""),
                    "accessComplexity": cvss_data.get("accessComplexity", ""),
                    "authentication": cvss_data.get("authentication", ""),
                    "confidentialityImpact": cvss_data.get("confidentialityImpact", ""),
                    "integrityImpact": cvss_data.get("integrityImpact", ""),
                    "availabilityImpact": cvss_data.get("availabilityImpact", "")
                }
            
            # CWE IDs - removed
            
            # References
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)
            
            # Affected products and CPE configurations
            affected_products = []
            cpe_configurations = []
            
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            criteria = cpe_match.get("criteria", "")
                            if criteria:
                                cpe_configurations.append(criteria)
                                
                                # Extract vendor and product
                                parts = criteria.split(":")
                                if len(parts) >= 5:
                                    vendor_product = f"{parts[3]} {parts[4]}"
                                    if vendor_product not in affected_products:
                                        affected_products.append(vendor_product)
            
            # Vendor comments
            vendor_comments = []
            # Note: NIST API doesn't always provide vendor comments in the main feed
            
            return EnhancedCVEInfo(
                cve_id=cve_id,
                description=description,
                severity=severity,
                score=cvss_score,
                vector_string=vector,
                cvss_version=cvss_version,
                exploitability_score=exploitability_score,
                impact_score=impact_score,
                published_date=cve_data.get("published", ""),
                modified_date=cve_data.get("lastModified", ""),
                affected_products=affected_products[:20],
                references=references[:15],
                source="NIST NVD",
                vuln_status=vuln_status,
                cpe_configurations=cpe_configurations[:20],
                cvss_metrics_v3=cvss_v3_metrics,
                cvss_metrics_v2=cvss_v2_metrics,
                confidence_score=1.0  # NIST data is highly confident
            )
            
        except Exception as e:
            print(f"    ⚠ Failed to parse CVE: {e}")
            return None
    
    @staticmethod
    def _cvss2_to_severity(score: float) -> str:
        """Convert CVSS v2 score to severity rating"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "UNKNOWN"



# Example usage function
def demonstrate_enhanced_structure():
    """Demonstrate the enhanced data structures"""
    
    # Create sample CVE
    sample_cve = EnhancedCVEInfo(
        cve_id="CVE-2024-1234",
        description="Sample vulnerability description",
        severity="HIGH",
        score=8.5,
        published_date="2024-01-15T10:00:00Z",
        modified_date="2024-01-20T15:30:00Z",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_version="3.1",
        exploitability_score=3.9,
        impact_score=5.2,
        vuln_status="Analyzed",
        affected_products=["vendor1 product1", "vendor2 product2"],
        references=["https://example.com/advisory1", "https://example.com/patch1"],
        relevance_score=0.85,
        relevance_reasoning="High relevance due to matching vulnerability type and platform"
    )
    
    # Create structured results
    results = StructuredSearchResults(
        query="SQL injection vulnerability",
        timestamp=datetime.now().isoformat(),
        context={"Operating System": "Linux"},
        cves=[sample_cve]
    )
    
    # Convert to dictionary
    results_dict = results.to_dict()
    
    # Get CVE list
    cve_list = results.get_cve_list()
    
    print("CVE List:")
    print(json.dumps(cve_list, indent=2))
    
    print("\nSummary:")
    print(json.dumps(results.get_summary(), indent=2))


if __name__ == "__main__":
    demonstrate_enhanced_structure()