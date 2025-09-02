"""Search tools and utilities for CVE discovery."""

import re
from typing import List
from langchain_core.tools import tool

from ..models.data_models import CVEResult
from ..services.nist_service import search_nist_nvd
from ..services.cve_org_service import search_cve_org
from ..services.osv_service import search_osv_database


@tool
def extract_cve_keywords(query: str) -> str:
    """Extract and enhance keywords for CVE searching from a vulnerability description."""
    keyword_mappings = {
        'ssl/tls': ['certificate', 'encryption', 'handshake', 'cipher'],
        'ssh': ['openssh', 'authentication', 'key exchange', 'protocol'],
        'web server': ['apache', 'nginx', 'iis', 'http', 'https'],
        'authentication': ['login', 'bypass', 'credential', 'password'],
        'injection': ['sql', 'command', 'code', 'script'],
        'buffer': ['overflow', 'underflow', 'memory', 'heap', 'stack'],
        'privilege': ['escalation', 'elevation', 'root', 'admin'],
        'denial': ['service', 'dos', 'crash', 'hang'],
        'cross-site': ['xss', 'scripting', 'javascript'],
        'remote': ['code', 'execution', 'rce', 'command'],
        'kernel': ['linux', 'windows', 'driver', 'system'],
        'certificate': ['validation', 'verification', 'chain', 'trust'],
        'directory': ['listing', 'traversal', 'disclosure', 'enumeration']
    }
    
    query_lower = query.lower()
    extracted_keywords = []
    words = re.findall(r'\b\w{3,}\b', query_lower)
    
    # Add words from the original query
    for word in words:
        if len(word) > 3:
            extracted_keywords.append(word)
    
    # Add related terms based on keyword mappings
    for main_term, related_terms in keyword_mappings.items():
        if main_term.replace('/', ' ') in query_lower or any(term in query_lower for term in main_term.split('/')):
            extracted_keywords.extend(related_terms[:2])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_keywords = []
    for keyword in extracted_keywords:
        if keyword not in seen and len(keyword) > 2:
            seen.add(keyword)
            unique_keywords.append(keyword)
    
    result = ' '.join(unique_keywords[:6])
    print(f"Extracted keywords from '{query}': {result}")
    return result


def search_cve_databases(query: str) -> List[CVEResult]:
    """Search multiple CVE databases with enhanced error handling."""
    print(f"Searching CVE databases for: '{query}'")
    
    results = []
    
    # Search OSV database
    try:
        osv_results = search_osv_database(query)
        if osv_results:
            results.extend(osv_results)
    except Exception as e:
        print(f"OSV search failed: {e}")
    
    # Search NIST NVD database
    try:
        nist_results = search_nist_nvd(query)
        if nist_results:
            results.extend(nist_results)
    except Exception as e:
        print(f"NIST search failed: {e}")
    
    # Search CVE.org database
    try:
        cve_org_results = search_cve_org(query)
        if cve_org_results:
            results.extend(cve_org_results)
    except Exception as e:
        print(f"CVE.org search failed: {e}")
    
    # If no results found, try a broader search
    if not results:
        print("No results found with original query, trying broader search")
        broader_query = " ".join(query.split()[:3])  # Use first 3 keywords
        if broader_query != query:
            try:
                nist_results = search_nist_nvd(broader_query)
                if nist_results:
                    results.extend(nist_results)
                    
                osv_results = search_osv_database(broader_query)
                if osv_results:
                    results.extend(osv_results)
            except Exception as e:
                print(f"Broader search failed: {e}")
    
    return results