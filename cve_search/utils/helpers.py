"""Helper utility functions for CVE search system."""

import re
from ..models.data_models import CVEResult


def calculate_relevance_score(cve_result: CVEResult, original_query: str) -> float:
    """Calculate how relevant a CVE is to the original query."""
    try:
        query_lower = original_query.lower()
        desc_lower = cve_result.description.lower()
        score = 0.0
        
        # Calculate word overlap
        query_words = set(re.findall(r'\b\w{3,}\b', query_lower))
        desc_words = set(re.findall(r'\b\w{3,}\b', desc_lower))
        matches = query_words.intersection(desc_words)
        score += len(matches) * 2.0
        
        # Boost score for high severity CVEs
        if cve_result.score > 7.0: 
            score += 1.5
        elif cve_result.score > 4.0: 
            score += 1.0
            
        # Boost score for recent CVEs
        if cve_result.published_date and '2024' in cve_result.published_date: 
            score += 0.5
            
        return min(score, 10.0)
    except Exception as e:
        print(f"Error calculating relevance score: {e}")
        return 1.0  # Default score


def get_severity_from_score(score: float) -> str:
    """Convert CVSS score to severity level."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "UNKNOWN"