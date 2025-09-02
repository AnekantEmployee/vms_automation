"""OSV API service for vulnerability search."""

import requests
from typing import List, Optional

from ..models.data_models import CVEResult
from ..config.rate_limiting import RateLimiter
from ..config.settings import TIMEOUT_CONFIG
from ..utils.retry import exponential_backoff_retry
from ..utils.cache import get_cache_lock

# Create OSV-specific rate limiter and cache
osv_rate_limiter = RateLimiter(max_requests=30, time_window=60)  # OSV is generally more permissive
_osv_cache = {}

@exponential_backoff_retry
def search_osv_by_id(osv_id: str) -> Optional[CVEResult]:
    """Search OSV database by specific vulnerability ID."""
    print(f"Searching OSV database for ID: {osv_id}")
    
    try:
        # Check cache first
        with get_cache_lock():
            cached_result = _osv_cache.get(osv_id)
            if cached_result is not None:
                print(f"Using cached OSV result for: {osv_id}")
                return cached_result
        
        # Apply rate limiting
        osv_rate_limiter.wait_if_needed()
        
        url = f"https://api.osv.dev/v1/vulns/{osv_id}"
        headers = {
            "User-Agent": "CVE-Search-Agent/1.0 (Security Research)"
        }
        
        response = requests.get(
            url, 
            headers=headers, 
            timeout=TIMEOUT_CONFIG.get('osv_api', 30)
        )
        
        if response.status_code == 404:
            print(f"OSV vulnerability {osv_id} not found")
            return None
        elif response.status_code == 429:
            raise Exception("OSV API rate limit exceeded")
        elif response.status_code != 200:
            raise Exception(f"OSV API returned status code: {response.status_code}")
        
        vulnerability = response.json()
        cve_result = _parse_osv_vulnerability(vulnerability)
        
        # Cache the result
        with get_cache_lock():
            _osv_cache[osv_id] = cve_result
        
        print(f"Found OSV vulnerability: {osv_id}")
        return cve_result
        
    except Exception as e:
        print(f"Error searching OSV database: {e}")
        raise

@exponential_backoff_retry 
def search_osv_database(query: str) -> List[CVEResult]:
    """Search OSV database with query-based search."""
    print(f"Searching OSV database for: {query}")
    
    try:
        # Check cache first
        cache_key = f"query_{query}"
        with get_cache_lock():
            cached_results = _osv_cache.get(cache_key)
            if cached_results is not None:
                print(f"Using cached OSV results for: {query}")
                return cached_results
        
        # Apply rate limiting
        osv_rate_limiter.wait_if_needed()
        
        # OSV query API endpoint
        url = "https://api.osv.dev/v1/query"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CVE-Search-Agent/1.0 (Security Research)"
        }
        
        # Query payload for OSV API
        query_payload = {
            "query": query
        }
        
        response = requests.post(
            url,
            json=query_payload,
            headers=headers,
            timeout=TIMEOUT_CONFIG.get('osv_api', 30)
        )
        
        if response.status_code == 429:
            raise Exception("OSV API rate limit exceeded")
        elif response.status_code != 200:
            raise Exception(f"OSV API returned status code: {response.status_code}")
        
        data = response.json()
        results = []
        
        if "vulns" in data and data["vulns"]:
            for vuln_summary in data["vulns"]:
                # Get detailed vulnerability info
                vuln_id = vuln_summary.get("id", "")
                if vuln_id:
                    detailed_vuln = search_osv_by_id(vuln_id)
                    if detailed_vuln:
                        results.append(detailed_vuln)
        
        # Cache the results
        with get_cache_lock():
            _osv_cache[cache_key] = results
        
        print(f"Found {len(results)} results from OSV database")
        return results
        
    except Exception as e:
        print(f"Error searching OSV database: {e}")
        raise

def _parse_osv_vulnerability(vulnerability: dict) -> CVEResult:
    """Parse OSV vulnerability data into CVEResult format."""
    try:
        osv_id = vulnerability.get("id", "")
        summary = vulnerability.get("summary", "")
        details = vulnerability.get("details", "")
        
        # Combine summary and details for description
        description = f"{summary}. {details}".strip(". ")
        
        # Extract dates
        published_date = vulnerability.get("published", "")
        modified_date = vulnerability.get("modified", "")
        
        # Extract severity and score
        severity = "UNKNOWN"
        score = 0.0
        affected_products = []
        
        if "affected" in vulnerability and vulnerability["affected"]:
            affected = vulnerability["affected"][0]
            
            # Get severity from ecosystem_specific
            if "ecosystem_specific" in affected and "severity" in affected["ecosystem_specific"]:
                severity = affected["ecosystem_specific"]["severity"]
            
            # Get package information
            if "package" in affected:
                package_info = affected["package"]
                package_name = package_info.get("name", "")
                ecosystem = package_info.get("ecosystem", "")
                if package_name:
                    affected_products.append(f"{ecosystem}:{package_name}")
        
        # Convert severity to score (approximate mapping)
        severity_score_map = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MODERATE": 6.0,
            "MEDIUM": 6.0,
            "LOW": 3.0,
            "UNKNOWN": 0.0
        }
        score = severity_score_map.get(severity.upper(), 0.0)
        
        # Extract references
        references = []
        if "references" in vulnerability:
            for ref in vulnerability["references"]:
                references.append(ref.get("url", ""))
        
        return CVEResult(
            cve_id=osv_id,
            description=description,
            severity=severity,
            published_date=published_date,
            modified_date=modified_date,
            score=score,
            source="OSV",
            affected_products=affected_products,
            references=references,
            cvss_version="OSV",  # OSV uses its own scoring
        )
        
    except Exception as e:
        print(f"Error parsing OSV vulnerability: {e}")
        # Return minimal result on parsing error
        return CVEResult(
            cve_id=vulnerability.get("id", "UNKNOWN"),
            description=vulnerability.get("summary", "Parse error"),
            severity="UNKNOWN",
            published_date=vulnerability.get("published", ""),
            modified_date=vulnerability.get("modified", ""),
            score=0.0,
            source="OSV"
        )

def clear_osv_cache():
    """Clear OSV cache."""
    global _osv_cache
    with get_cache_lock():
        _osv_cache.clear()
    print("OSV cache cleared.")
