import re
import json
import requests
import time
from datetime import datetime
from tavily import TavilyClient
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class EnhancedCWEInfo:
    """Enhanced CWE (Common Weakness Enumeration) Information with complete details"""
    cwe_id: str
    name: str
    description: str
    abstraction_level: str = "Unknown"
    likelihood: str = "Unknown"
    impact: str = "Unknown"
    
    # Additional detailed properties
    status: str = "Unknown"  # Draft, Incomplete, Stable, Deprecated
    weakness_ordinality: str = "Unknown"  # Primary, Resultant
    applicable_platforms: List[str] = field(default_factory=list)
    common_consequences: List[Dict[str, str]] = field(default_factory=list)  # [{"scope": "Confidentiality", "impact": "Read Data"}]
    detection_methods: List[str] = field(default_factory=list)
    potential_mitigations: List[str] = field(default_factory=list)
    related_attack_patterns: List[str] = field(default_factory=list)  # CAPEC IDs
    taxonomy_mappings: List[Dict[str, str]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "abstraction_level": self.abstraction_level,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "status": self.status,
            "weakness_ordinality": self.weakness_ordinality,
            "applicable_platforms": self.applicable_platforms,
            "common_consequences": self.common_consequences,
            "detection_methods": self.detection_methods,
            "potential_mitigations": self.potential_mitigations,
            "related_attack_patterns": self.related_attack_patterns,
            "taxonomy_mappings": self.taxonomy_mappings,
            "references": self.references
        }


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
    
    # CWE Information
    cwe_info: List[str] = field(default_factory=list)  # List of CWE IDs
    cwe_details: List[EnhancedCWEInfo] = field(default_factory=list)  # Detailed CWE objects
    
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
            "cwe_info": self.cwe_info,
            "cwe_details": [cwe.to_dict() for cwe in self.cwe_details],
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
    """Structured results with separate CVE and CWE lists"""
    query: str
    timestamp: str
    context: Dict[str, Any]
    
    # Separate categorized lists
    cves: List[EnhancedCVEInfo] = field(default_factory=list)
    cwes: List[EnhancedCWEInfo] = field(default_factory=list)
    
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
            "cwes": [cwe.to_dict() for cwe in self.cwes],
            "analysis": self.analysis,
            "search_strategy": self.search_strategy,
            "summary_statistics": self.summary_statistics
        }
    
    def get_cve_list(self) -> List[Dict[str, Any]]:
        """Get list of CVE dictionaries"""
        return [cve.to_dict() for cve in self.cves]
    
    def get_cwe_list(self) -> List[Dict[str, Any]]:
        """Get list of CWE dictionaries"""
        return [cwe.to_dict() for cwe in self.cwes]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return {
            "total_cves": len(self.cves),
            "total_cwes": len(self.cwes),
            "severity_breakdown": self._get_severity_breakdown(),
            "average_cvss_score": self._get_average_cvss(),
            "average_relevance_score": self._get_average_relevance(),
            "top_cwes": self._get_top_cwes(),
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
    
    def _get_top_cwes(self) -> List[Dict[str, Any]]:
        """Get top 5 most common CWEs"""
        cwe_count = {}
        for cve in self.cves:
            for cwe_id in cve.cwe_info:
                cwe_count[cwe_id] = cwe_count.get(cwe_id, 0) + 1
        
        top_cwes = sorted(cwe_count.items(), key=lambda x: x[1], reverse=True)[:5]
        return [{"cwe_id": cwe_id, "count": count} for cwe_id, count in top_cwes]
    
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
            
            # CWE IDs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_id = desc.get("value", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_ids.append(cwe_id)
            
            # Remove duplicates while preserving order
            cwe_ids = list(dict.fromkeys(cwe_ids))
            
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
                cwe_info=cwe_ids,
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


class EnhancedCWEFetcher:
    """Enhanced CWE fetcher with detailed information extraction"""
    
    def __init__(self, tavily_client: TavilyClient):
        self.tavily = tavily_client
        self.cwe_cache = {}
    
    def get_cwe_details(self, cwe_id: str) -> Optional[EnhancedCWEInfo]:
        """Fetch detailed CWE information"""
        if cwe_id in self.cwe_cache:
            return self.cwe_cache[cwe_id]
        
        try:
            # Search for CWE information
            results = self.tavily.search(
                query=f"{cwe_id} MITRE CWE details",
                search_depth="advanced",
                max_results=3,
                include_domains=["cwe.mitre.org"]
            )
            
            name = cwe_id
            description = ""
            abstraction_level = "Unknown"
            
            for result in results.get("results", []):
                content = result.get("content", "")
                title = result.get("title", "")
                
                # Extract name from title
                if cwe_id in title:
                    name_match = re.search(rf'{cwe_id}:\s*(.+?)(?:\s*-\s*|\s*\||\s*$)', title)
                    if name_match:
                        name = name_match.group(1).strip()
                
                # Extract description
                if content and not description:
                    description = content[:800]
                
                # Try to extract abstraction level
                abstraction_match = re.search(r'Abstraction:\s*(\w+)', content, re.IGNORECASE)
                if abstraction_match:
                    abstraction_level = abstraction_match.group(1)
            
            # If we didn't get description from web search, use LLM
            if not description:
                description = self._get_cwe_description_with_llm(cwe_id)
            
            cwe_info = EnhancedCWEInfo(
                cwe_id=cwe_id,
                name=name,
                description=description,
                abstraction_level=abstraction_level
            )
            
            self.cwe_cache[cwe_id] = cwe_info
            return cwe_info
            
        except Exception as e:
            print(f"    ⚠ Failed to fetch CWE {cwe_id}: {e}")
            return EnhancedCWEInfo(
                cwe_id=cwe_id,
                name=cwe_id,
                description=f"Common Weakness Enumeration: {cwe_id}"
            )
    
    def _get_cwe_description_with_llm(self, cwe_id: str) -> str:
        """Get CWE description using LLM"""
        try:
            from config.api_key_manager import generate_content_with_fallback
            
            prompt = f"""Provide a technical description (3-4 sentences) of {cwe_id}.
Include:
1. What the weakness is
2. Why it's a security concern
3. Common contexts where it occurs

Be concise and technical."""

            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.1,
                max_output_tokens=300
            )
            
            return response.strip()
        except Exception:
            return f"Common Weakness Enumeration: {cwe_id}"


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
        cwe_info=["CWE-89", "CWE-79"],
        affected_products=["vendor1 product1", "vendor2 product2"],
        references=["https://example.com/advisory1", "https://example.com/patch1"],
        relevance_score=0.85,
        relevance_reasoning="High relevance due to matching vulnerability type and platform"
    )
    
    # Create sample CWE
    sample_cwe = EnhancedCWEInfo(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="The software constructs SQL queries using user input without proper validation...",
        abstraction_level="Base",
        likelihood="High",
        impact="High",
        status="Stable"
    )
    
    # Create structured results
    results = StructuredSearchResults(
        query="SQL injection vulnerability",
        timestamp=datetime.now().isoformat(),
        context={"Operating System": "Linux"},
        cves=[sample_cve],
        cwes=[sample_cwe]
    )
    
    # Convert to dictionary
    results_dict = results.to_dict()
    
    # Get separate lists
    cve_list = results.get_cve_list()
    cwe_list = results.get_cwe_list()
    
    print("CVE List:")
    print(json.dumps(cve_list, indent=2))
    
    print("\nCWE List:")
    print(json.dumps(cwe_list, indent=2))
    
    print("\nSummary:")
    print(json.dumps(results.get_summary(), indent=2))


if __name__ == "__main__":
    demonstrate_enhanced_structure()