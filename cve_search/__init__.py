"""
CVE Search System - Enhanced vulnerability search with rate limiting and multi-source support.

This package provides a comprehensive CVE (Common Vulnerabilities and Exposures) search system
that leverages multiple data sources including NIST NVD, CVE.org, and external search engines.

Key Features:
- Multi-source CVE database search
- Rate limiting and timeout handling
- LangGraph-based agent workflow
- Caching and retry mechanisms
- External search integration with Tavily
"""

__version__ = "1.0.0"
__author__ = "CVE Search Team"

from .models.data_models import CVEResult
from .config.settings import CVESearchConfig

__all__ = [
    "CVEResult", 
    "CVESearchConfig"
]