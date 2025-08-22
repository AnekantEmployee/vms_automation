"""CVE.org API service for CVE search."""

import requests
from typing import List

from ..models.data_models import CVEResult
from ..config.rate_limiting import cve_org_rate_limiter
from ..config.settings import TIMEOUT_CONFIG
from ..utils.retry import exponential_backoff_retry
from ..utils.cache import get_cached_cve_org_results, cache_cve_org_results


@exponential_backoff_retry
def search_cve_org(query: str) -> List[CVEResult]:
    """Search the CVE.org database with rate limiting and timeout."""
    print(f"Searching CVE.org for: {query}")
    
    try:
        # Check cache first
        cached_results = get_cached_cve_org_results(query)
        if cached_results is not None:
            print(f"Using cached CVE.org results for: {query}")
            return cached_results
        
        # Apply rate limiting
        cve_org_rate_limiter.wait_if_needed()
        
        # CVE.org API endpoint
        url = "https://www.cve.org/api/graphql"
        
        # GraphQL query to search for CVEs
        graphql_query = {
            "query": """
            query ($search: String!) {
                cveList (keyword: $search) {
                    cves {
                        cveId
                        descriptions {
                            lang
                            value
                        }
                        published
                        lastModified
                        metrics {
                            cvssMetricV31 {
                                cvssData {
                                    baseScore
                                    baseSeverity
                                    vectorString
                                }
                            }
                            cvssMetricV30 {
                                cvssData {
                                    baseScore
                                    baseSeverity
                                    vectorString
                                }
                            }
                            cvssMetricV2 {
                                cvssData {
                                    baseScore
                                    severity
                                    vectorString
                                }
                            }
                        }
                        references {
                            url
                        }
                        vendorComments {
                            comment
                        }
                    }
                }
            }
            """,
            "variables": {
                "search": query
            }
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CVE-Search-Agent/1.0 (Security Research)"
        }
        
        response = requests.post(
            url, 
            json=graphql_query, 
            headers=headers, 
            timeout=TIMEOUT_CONFIG['cve_org_api']
        )
        
        if response.status_code == 429:
            raise Exception("CVE.org API rate limit exceeded")
        elif response.status_code != 200:
            raise Exception(f"CVE.org API returned status code: {response.status_code}")
        
        data = response.json()
        
        results = []
        if "data" in data and "cveList" in data["data"] and "cves" in data["data"]["cveList"]:
            for cve_data in data["data"]["cveList"]["cves"]:
                try:
                    cve_id = cve_data.get("cveId", "")
                    
                    # Extract description
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
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            cvss_version = "3.1"
                            vector_string = cvss_data.get("vectorString", "")
                        
                        # Check for CVSS v3.0
                        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                            score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            cvss_version = "3.0"
                            vector_string = cvss_data.get("vectorString", "")
                        
                        # Check for CVSS v2.0
                        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                            score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("severity", "UNKNOWN")
                            cvss_version = "2.0"
                            vector_string = cvss_data.get("vectorString", "")
                    
                    # Extract dates
                    published_date = cve_data.get("published", "")
                    modified_date = cve_data.get("lastModified", "")
                    
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
                        source="CVE.org",
                        references=references,
                        vector_string=vector_string,
                        cvss_version=cvss_version
                    )
                    
                    results.append(cve_result)
                    
                except Exception as e:
                    print(f"Error processing individual CVE record from CVE.org: {e}")
                    continue
        
        # Cache the results
        cache_cve_org_results(query, results)
            
        print(f"Found {len(results)} results from CVE.org")
        return results
        
    except Exception as e:
        print(f"Error searching CVE.org: {e}")
        raise  # Re-raise for retry mechanism