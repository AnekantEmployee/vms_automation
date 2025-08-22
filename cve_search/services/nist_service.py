"""NIST NVD API service for CVE search."""

import requests
import urllib.parse
from typing import List

from ..models.data_models import CVEResult
from ..config.rate_limiting import nist_rate_limiter
from ..config.settings import TIMEOUT_CONFIG
from ..utils.retry import exponential_backoff_retry
from ..utils.cache import get_cached_nist_results, cache_nist_results
from ..utils.helpers import get_severity_from_score


@exponential_backoff_retry
def search_nist_nvd(query: str) -> List[CVEResult]:
    """Search the NIST National Vulnerability Database with rate limiting and timeout."""
    print(f"Searching NIST NVD for: {query}")
    
    try:
        # Check cache first
        cached_results = get_cached_nist_results(query)
        if cached_results is not None:
            print(f"Using cached NIST results for: {query}")
            return cached_results
        
        # Apply rate limiting
        nist_rate_limiter.wait_if_needed()
        
        # Encode query for URL
        encoded_query = urllib.parse.quote(query)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}"
        
        # Make request to NVD API with timeout
        headers = {
            "User-Agent": "CVE-Search-Agent/1.0 (Security Research)"
        }
        
        response = requests.get(
            url, 
            headers=headers, 
            timeout=TIMEOUT_CONFIG['nist_api']
        )
        
        if response.status_code == 429:
            raise Exception("NIST API rate limit exceeded")
        elif response.status_code != 200:
            raise Exception(f"NIST API returned status code: {response.status_code}")
        
        data = response.json()
        
        results = []
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                if "cve" not in vuln:
                    continue
                    
                try:
                    cve_data = vuln["cve"]
                    
                    # Extract basic information
                    cve_id = cve_data.get("id", "")
                    description = ""
                    if "descriptions" in cve_data and cve_data["descriptions"]:
                        for desc in cve_data["descriptions"]:
                            if desc.get("lang", "") == "en":
                                description = desc.get("value", "")
                                break
                    
                    # Extract metrics and severity
                    severity = "UNKNOWN"
                    score = 0.0
                    cvss_version = ""
                    vector_string = ""
                    
                    if "metrics" in cve_data:
                        metrics = cve_data["metrics"]
                        
                        # Check for CVSS v3.1
                        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                            score = cvss_data.get("baseScore", 0.0)
                            severity = get_severity_from_score(score)
                            cvss_version = "3.1"
                            vector_string = cvss_data.get("vectorString", "")
                        
                        # Fall back to CVSS v3.0
                        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                            score = cvss_data.get("baseScore", 0.0)
                            severity = get_severity_from_score(score)
                            cvss_version = "3.0"
                            vector_string = cvss_data.get("vectorString", "")
                        
                        # Fall back to CVSS v2.0
                        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                            score = cvss_data.get("baseScore", 0.0)
                            severity = get_severity_from_score(score)
                            cvss_version = "2.0"
                            vector_string = cvss_data.get("vectorString", "")
                    
                    # Extract dates
                    published_date = cve_data.get("published", "")
                    modified_date = cve_data.get("lastModified", "")
                    
                    # Extract CWE information
                    cwe_info = []
                    if "weaknesses" in cve_data:
                        for weakness in cve_data["weaknesses"]:
                            for desc in weakness.get("description", []):
                                if desc.get("lang", "") == "en":
                                    cwe_info.append(desc.get("value", ""))
                    
                    # Extract affected products
                    affected_products = []
                    if "configurations" in cve_data:
                        for config in cve_data["configurations"]:
                            for node in config.get("nodes", []):
                                for cpe in node.get("cpeMatch", []):
                                    criteria = cpe.get("criteria", "")
                                    if criteria and ":" in criteria:
                                        affected_products.append(criteria)
                    
                    # Extract references
                    references = []
                    if "references" in cve_data:
                        for ref in cve_data["references"]:
                            references.append(ref.get("url", ""))
                    
                    # Create CVE result object
                    cve_result = CVEResult(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        published_date=published_date,
                        modified_date=modified_date,
                        score=score,
                        source="NIST NVD",
                        cwe_info=cwe_info,
                        affected_products=affected_products,
                        references=references,
                        vector_string=vector_string,
                        cvss_version=cvss_version
                    )
                    
                    results.append(cve_result)
                    
                except Exception as e:
                    print(f"Error processing individual CVE record: {e}")
                    continue
        
        # Cache the results
        cache_nist_results(query, results)
            
        print(f"Found {len(results)} results from NIST NVD")
        return results
        
    except Exception as e:
        print(f"Error searching NIST NVD: {e}")
        raise  # Re-raise for retry mechanism