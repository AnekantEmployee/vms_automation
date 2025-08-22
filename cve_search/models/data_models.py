"""Data models for CVE search system."""

from dataclasses import dataclass, field
from typing import List, Dict, TypedDict, Annotated

from langgraph.graph.message import add_messages


@dataclass
class CVEResult:
    """Data model for CVE search results."""
    
    cve_id: str
    description: str
    severity: str
    published_date: str
    modified_date: str
    score: float
    source: str = "NIST"
    vuln_status: str = "Unknown"
    cwe_info: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    vector_string: str = ""
    cvss_version: str = ""
    confidence_score: float = 1.0

    def to_dict(self):
        """Convert to dictionary for easy serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "published_date": self.published_date,
            "modified_date": self.modified_date,
            "score": self.score,
            "source": self.source,
            "vuln_status": self.vuln_status,
            "cwe_info": self.cwe_info,
            "affected_products": self.affected_products,
            "references": self.references,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "vector_string": self.vector_string,
            "cvss_version": self.cvss_version,
            "confidence_score": self.confidence_score
        }


class CVESearchState(TypedDict):
    """State definition for CVE search agent workflow."""
    
    messages: Annotated[list, add_messages]
    original_query: str
    enhanced_queries: List[str]
    search_results: List[Dict]
    cve_results: List[CVEResult]
    search_attempts: int
    max_attempts: int
    search_strategy: str
    external_search_done: bool