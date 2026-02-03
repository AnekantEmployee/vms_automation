"""LLM-driven CVE search - Let AI do the heavy lifting instead of hardcoding."""

import re
import os
import json
import requests
import urllib.parse
from threading import Lock
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import List, Dict, Any, TypedDict, Annotated, Optional

from langchain_core.tools import tool
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import HumanMessage, AIMessage
from config.llm_config import generate_with_gemini

# Load environment
load_dotenv()

# Caching
_nist_cache = {}
_cwe_cache = {}
_cache_lock = Lock()


@dataclass
class CWEInfo:
    """CWE information"""
    cwe_id: str
    name: str
    description: str
    
    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description
        }


@dataclass
class CVEResult:
    cve_id: str
    description: str
    severity: str
    published_date: str
    modified_date: str
    score: float
    source: str = "NIST"
    vuln_status: str = "Unknown"
    cwe_info: List[str] = field(default_factory=list)
    cwe_details: List[CWEInfo] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    vector_string: str = ""
    cvss_version: str = ""
    confidence_score: float = 1.0
    relevance_explanation: str = ""  # LLM explanation of why it's relevant

    def to_dict(self):
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
            "cwe_details": [cwe.to_dict() for cwe in self.cwe_details],
            "affected_products": self.affected_products,
            "references": self.references,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "vector_string": self.vector_string,
            "cvss_version": self.cvss_version,
            "confidence_score": self.confidence_score,
            "relevance_explanation": self.relevance_explanation
        }


class CVESearchState(TypedDict):
    messages: Annotated[list, add_messages]
    original_query: str
    os_context: str
    qid: str
    asset_info: Dict[str, str]
    enhanced_queries: List[str]
    search_results: List[Dict]
    cve_results: List[CVEResult]
    search_attempts: int
    max_attempts: int
    search_strategy: str


def llm_generate_search_queries(vulnerability_query: str, context: Dict = None) -> List[str]:
    """Let LLM generate optimal search queries."""
    
    context_str = ""
    if context:
        context_str = f"\nContext:\n- OS: {context.get('os_context', 'Unknown')}\n- QID: {context.get('qid', 'N/A')}"
    
    prompt = f"""You are a CVE search expert. Generate 4-5 search queries to find relevant CVEs for this vulnerability.

Vulnerability: "{vulnerability_query}"{context_str}

Generate search queries from most specific to most general. Each query should be:
1. 3-8 words maximum
2. Focus on technical terms, not filler words
3. Use terms commonly found in CVE descriptions
4. Start specific, then broaden

Return ONLY a JSON array of search queries, nothing else:
["query1", "query2", "query3", "query4"]

Search queries:"""

    try:
        response = generate_with_gemini(prompt, temperature=0.2, max_output_tokens=200)
        
        # Extract JSON from response
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            queries = json.loads(json_match.group())
            print(f"LLM generated {len(queries)} search queries:")
            for i, q in enumerate(queries, 1):
                print(f"  {i}. {q}")
            return queries
        else:
            print("LLM response didn't contain valid JSON, using fallback")
            # Fallback
            return [vulnerability_query.lower()]
    
    except Exception as e:
        print(f"LLM query generation failed: llm_generate_search_queries")
        return [vulnerability_query.lower()]


def llm_validate_cve_relevance(cve: CVEResult, vulnerability_query: str, context: Dict = None) -> Dict[str, Any]:
    """Let LLM validate if CVE is relevant to the vulnerability."""
    
    context_str = ""
    if context:
        context_str = f"\nVulnerability Context:\n- OS: {context.get('os_context', 'Unknown')}\n- Asset: {context.get('asset_info', {})}"
    
    # Limit CVE description length for token efficiency
    cve_desc_short = cve.description[:500] if len(cve.description) > 500 else cve.description
    
    prompt = f"""Analyze if this CVE is relevant to the vulnerability.

Vulnerability Query: "{vulnerability_query}"{context_str}

CVE: {cve.cve_id}
Description: {cve_desc_short}
Severity: {cve.severity} (Score: {cve.score})
CWE: {', '.join(cve.cwe_info[:3]) if cve.cwe_info else 'None'}

Is this CVE relevant? Consider:
1. Does it relate to the same type of vulnerability?
2. Are the technical concepts similar?
3. Would fixing this CVE address the vulnerability?

Respond in JSON format:
{{
    "is_relevant": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}

Analysis:"""

    try:
        response = generate_with_gemini(prompt, temperature=0.1, max_output_tokens=150)
        
        # Extract JSON
        json_match = re.search(r'\{[^}]*"is_relevant"[^}]*\}', response, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            return {
                "is_relevant": result.get("is_relevant", False),
                "confidence": result.get("confidence", 0.5),
                "reasoning": result.get("reasoning", "")
            }
    
    except Exception as e:
        print(f"LLM validation failed for {cve.cve_id}: llm_validate_cve_relevance")
    
    # Fallback to simple keyword matching
    query_lower = vulnerability_query.lower()
    desc_lower = cve.description.lower()
    
    # Extract significant words
    query_words = set(re.findall(r'\b\w{4,}\b', query_lower))
    desc_words = set(re.findall(r'\b\w{4,}\b', desc_lower))
    
    overlap = len(query_words.intersection(desc_words))
    confidence = min(0.9, overlap * 0.15)
    
    return {
        "is_relevant": confidence > 0.3,
        "confidence": confidence,
        "reasoning": f"Keyword match: {overlap} common terms"
    }


def llm_extract_cwe_from_vulnerability(vulnerability_query: str) -> List[str]:
    """Let LLM identify relevant CWE IDs for a vulnerability description."""
    
    prompt = f"""Given this vulnerability description, identify the most relevant CWE (Common Weakness Enumeration) IDs.

Vulnerability: "{vulnerability_query}"

Common CWEs include:
- CWE-79: Cross-site Scripting
- CWE-89: SQL Injection
- CWE-119: Buffer Overflow
- CWE-200: Information Exposure
- CWE-287: Improper Authentication
- CWE-295: Certificate Validation
- CWE-319: Cleartext Transmission
- CWE-327: Weak Cryptography
- CWE-352: CSRF
- CWE-434: File Upload
- CWE-601: Open Redirect
- CWE-798: Hardcoded Credentials

Return ONLY a JSON array of the 1-3 most relevant CWE IDs:
["CWE-XXX", "CWE-YYY"]

CWE IDs:"""

    try:
        response = generate_with_gemini(prompt, temperature=0.1, max_output_tokens=100)
        
        # Extract CWE IDs from response
        cwe_ids = re.findall(r'CWE-\d+', response)
        if cwe_ids:
            print(f"LLM identified CWEs: {', '.join(cwe_ids)}")
            return list(set(cwe_ids))  # Remove duplicates
    
    except Exception as e:
        print(f"LLM CWE extraction failed: {e}")
    
    return []


def get_cwe_details(cwe_id: str) -> Optional[CWEInfo]:
    """Fetch CWE details - try cache first, then API, then LLM."""
    
    with _cache_lock:
        if cwe_id in _cwe_cache:
            return _cwe_cache[cwe_id]
    
    try:
        # Try MITRE website
        cwe_number = re.search(r'CWE-(\d+)', cwe_id)
        if not cwe_number:
            return None
        
        cwe_num = cwe_number.group(1)
        url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        
        response = requests.get(url, timeout=10, headers={"User-Agent": "CVE-Search/1.0"})
        
        if response.status_code == 200:
            content = response.text
            name_match = re.search(r'<h2>(.*?)</h2>', content)
            name = name_match.group(1) if name_match else cwe_id
            
            desc_match = re.search(r'<div[^>]*class="detail"[^>]*>(.*?)</div>', content, re.DOTALL)
            description = desc_match.group(1) if desc_match else ""
            description = re.sub(r'<[^>]+>', '', description).strip()[:300]
            
            cwe_info = CWEInfo(cwe_id=cwe_id, name=name, description=description)
            
            with _cache_lock:
                _cwe_cache[cwe_id] = cwe_info
            
            return cwe_info
    
    except Exception as e:
        print(f"Could not fetch CWE {cwe_id} from web: get_cwe_details")
    
    # Fallback: Ask LLM for CWE information
    try:
        prompt = f"""What is {cwe_id}? Provide a brief description (2-3 sentences).

Format your response as:
Name: [CWE name]
Description: [brief description]"""

        response = generate_with_gemini(prompt, temperature=0.1, max_output_tokens=150)
        
        name_match = re.search(r'Name:\s*(.+?)(?:\n|$)', response)
        desc_match = re.search(r'Description:\s*(.+)', response, re.DOTALL)
        
        name = name_match.group(1).strip() if name_match else cwe_id
        description = desc_match.group(1).strip()[:300] if desc_match else f"Common Weakness: {cwe_id}"
        
        cwe_info = CWEInfo(cwe_id=cwe_id, name=name, description=description)
        
        with _cache_lock:
            _cwe_cache[cwe_id] = cwe_info
        
        return cwe_info
    
    except Exception as e:
        print(f"LLM CWE description failed: get_cwe_details fallback")
    
    # Last resort
    return CWEInfo(cwe_id=cwe_id, name=cwe_id, description=f"Common Weakness: {cwe_id}")


def enrich_cves_with_cwe_data(cve_results: List[CVEResult]) -> List[CVEResult]:
    """Enrich CVE results with detailed CWE information."""
    print(f"\n--- Enriching {len(cve_results)} CVEs with CWE data ---")
    
    for cve in cve_results:
        if cve.cwe_info:
            for cwe_id in cve.cwe_info[:3]:  # Limit to top 3 CWEs
                cwe_details = get_cwe_details(cwe_id)
                if cwe_details:
                    cve.cwe_details.append(cwe_details)
                    print(f"  ✓ {cve.cve_id}: {cwe_id} - {cwe_details.name}")
    
    return cve_results


# --- Agent Nodes ---

def query_analyzer_node(state: CVESearchState) -> CVESearchState:
    """Use LLM to analyze query and generate search variations."""
    print(f"\n--- Analyzing Query with LLM ---")
    print(f"Original query: {state['original_query']}")
    
    context = {
        "os_context": state.get("os_context", "Unknown"),
        "qid": state.get("qid", ""),
        "asset_info": state.get("asset_info", {})
    }
    
    enhanced_queries = llm_generate_search_queries(state['original_query'], context)
    
    return {
        **state,
        "enhanced_queries": enhanced_queries,
        "messages": state["messages"] + [AIMessage(content=f"Generated {len(enhanced_queries)} search queries")]
    }


def cve_search_node(state: CVESearchState) -> CVESearchState:
    """Search for CVEs using generated queries."""
    print(f"\n--- Searching for CVEs ---")
    
    attempt_num = state.get('search_attempts', 0)
    max_attempts = state.get('max_attempts', 4)
    
    if attempt_num >= max_attempts or attempt_num >= len(state.get('enhanced_queries', [])):
        print(f"Max search attempts reached")
        return {**state, "search_attempts": attempt_num}
    
    query = state['enhanced_queries'][attempt_num]
    print(f"Attempt {attempt_num + 1}/{max_attempts}: '{query}'")
    
    results = search_nist_nvd(query)
    
    # Merge with existing results
    existing_ids = {cve.cve_id for cve in state.get('cve_results', [])}
    new_cves = [cve for cve in results if cve.cve_id not in existing_ids]
    
    all_results = state.get('cve_results', []) + new_cves
    
    print(f"Found {len(new_cves)} new CVEs (total: {len(all_results)})")
    
    return {
        **state,
        "search_attempts": attempt_num + 1,
        "cve_results": all_results,
        "messages": state["messages"] + [AIMessage(content=f"Found {len(new_cves)} new CVEs")]
    }


def result_scorer_node(state: CVESearchState) -> CVESearchState:
    """Use LLM to validate and score CVE relevance."""
    print(f"\n--- LLM-Based Validation and Scoring ---")
    
    cve_results = state.get("cve_results", [])
    if not cve_results:
        print("No CVE results to validate")
        return state
    
    print(f"Validating {len(cve_results)} CVE results with LLM...")
    
    context = {
        "os_context": state.get("os_context", "Unknown"),
        "qid": state.get("qid", ""),
        "asset_info": state.get("asset_info", {})
    }
    
    validated_results = []
    
    for i, cve in enumerate(cve_results, 1):
        print(f"  [{i}/{len(cve_results)}] Validating {cve.cve_id}...", end=" ")
        
        validation = llm_validate_cve_relevance(cve, state['original_query'], context)
        
        cve.confidence_score = validation['confidence']
        cve.relevance_explanation = validation['reasoning']
        
        if validation['is_relevant'] and validation['confidence'] > 0.3:
            validated_results.append(cve)
            print(f"✓ RELEVANT (confidence: {validation['confidence']:.2f})")
        else:
            print(f"✗ Not relevant (confidence: {validation['confidence']:.2f})")
    
    # If nothing passed, keep top 3 by score anyway
    if not validated_results and cve_results:
        print(f"\n⚠️  LLM filtered all CVEs - keeping top 3 by severity")
        validated_results = sorted(cve_results, key=lambda x: x.score, reverse=True)[:3]
        for cve in validated_results:
            cve.confidence_score = 0.4
            cve.relevance_explanation = "Kept as top severity match"
    
    # Enrich with CWE data
    validated_results = enrich_cves_with_cwe_data(validated_results)
    
    # Also try to identify CWEs from the original query
    suggested_cwes = llm_extract_cwe_from_vulnerability(state['original_query'])
    if suggested_cwes:
        print(f"\nLLM suggests these CWEs for the vulnerability: {', '.join(suggested_cwes)}")
    
    # Sort by score and confidence
    validated_results.sort(key=lambda x: (x.score, x.confidence_score), reverse=True)
    
    print(f"\nValidation complete: {len(validated_results)} relevant CVEs")
    
    return {
        **state,
        "cve_results": validated_results,
        "messages": state["messages"] + [AIMessage(content=f"Validated: {len(validated_results)} relevant CVEs")]
    }


def search_nist_nvd(query: str, max_results: int = 20) -> List[CVEResult]:
    """Search NIST NVD API."""
    print(f"Searching NIST NVD for: {query}")
    
    with _cache_lock:
        if query in _nist_cache:
            print(f"Using cached results")
            return _nist_cache[query]
    
    try:
        encoded_query = urllib.parse.quote(query)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}&resultsPerPage={max_results}"
        
        response = requests.get(
            url,
            headers={"User-Agent": "CVE-Search/1.0"},
            timeout=30
        )
        
        if response.status_code == 429:
            print("Rate limited - waiting...")
            import time
            time.sleep(2)
            response = requests.get(url, headers={"User-Agent": "CVE-Search/1.0"}, timeout=30)
        
        if response.status_code != 200:
            print(f"NIST API returned status: {response.status_code}")
            return []
        
        data = response.json()
        results = []
        
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                if "cve" not in vuln:
                    continue
                
                try:
                    cve_data = vuln["cve"]
                    cve_id = cve_data.get("id", "")
                    
                    # Description
                    description = ""
                    if "descriptions" in cve_data:
                        for desc in cve_data["descriptions"]:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break
                    
                    # Severity and score
                    severity = "UNKNOWN"
                    score = 0.0
                    cvss_version = ""
                    vector_string = ""
                    
                    if "metrics" in cve_data:
                        metrics = cve_data["metrics"]
                        
                        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            if version_key in metrics and metrics[version_key]:
                                cvss_data = metrics[version_key][0]["cvssData"]
                                score = cvss_data.get("baseScore", 0.0)
                                severity = cvss_data.get("baseSeverity", cvss_data.get("severity", "UNKNOWN"))
                                cvss_version = version_key.replace("cvssMetricV", "")
                                vector_string = cvss_data.get("vectorString", "")
                                break
                    
                    # CWE info
                    cwe_info = []
                    if "weaknesses" in cve_data:
                        for weakness in cve_data["weaknesses"]:
                            for desc in weakness.get("description", []):
                                if desc.get("lang") == "en":
                                    cwe_id = desc.get("value", "")
                                    if cwe_id and cwe_id not in cwe_info:
                                        cwe_info.append(cwe_id)
                    
                    # References
                    references = []
                    if "references" in cve_data:
                        for ref in cve_data["references"]:
                            url = ref.get("url", "")
                            if url:
                                references.append(url)
                    
                    # Dates
                    published_date = cve_data.get("published", "")
                    modified_date = cve_data.get("lastModified", "")
                    
                    cve_result = CVEResult(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        published_date=published_date,
                        modified_date=modified_date,
                        score=score,
                        source="NIST NVD",
                        cwe_info=cwe_info,
                        references=references,
                        vector_string=vector_string,
                        cvss_version=cvss_version
                    )
                    
                    results.append(cve_result)
                
                except Exception as e:
                    print(f"Error processing CVE: search_nist_nvd above")
                    continue
        
        with _cache_lock:
            _nist_cache[query] = results
        
        print(f"Found {len(results)} results from NIST NVD")
        return results
    
    except Exception as e:
        print(f"Error searching NIST NVD: search_nist_nvd")
        return []


def should_continue_search(state: CVESearchState) -> str:
    """Decide next step."""
    print("\n--- Making a Decision ---")
    
    search_attempts = state.get('search_attempts', 0)
    max_attempts = state.get('max_attempts', 4)
    enhanced_queries = state.get('enhanced_queries', [])
    cve_results = state.get('cve_results', [])
    
    # If we have results and tried at least 2 queries, validate
    if cve_results and search_attempts >= 2:
        print(f"Decision: Found {len(cve_results)} CVEs after {search_attempts} attempts. Proceeding to validation.")
        return "score_results"
    
    # If we haven't reached max attempts and have more queries to try
    if search_attempts < max_attempts and search_attempts < len(enhanced_queries):
        print("Decision: Continuing search with next query.")
        return "continue_search"
    
    # If we have any results, validate them
    if cve_results:
        print("Decision: Max attempts reached, proceeding to validation.")
        return "score_results"
    
    # No results found
    print("Decision: No results found after max attempts.")
    return "score_results"


def create_cve_agent():
    """Create the LLM-driven CVE search agent."""
    workflow = StateGraph(CVESearchState)
    
    workflow.add_node("analyze_query", query_analyzer_node)
    workflow.add_node("search_cves", cve_search_node)
    workflow.add_node("score_results", result_scorer_node)
    
    workflow.add_edge(START, "analyze_query")
    workflow.add_edge("analyze_query", "search_cves")
    
    workflow.add_conditional_edges(
        "search_cves",
        should_continue_search,
        {
            "score_results": "score_results",
            "continue_search": "search_cves"
        }
    )
    
    workflow.add_edge("score_results", END)
    
    return workflow.compile()


def combined_cve_search(
    query: str,
    max_results: int = 10,
    vulnerability_context: Dict[str, Any] = None
) -> List[CVEResult]:
    """
    LLM-driven CVE search with intelligent query generation and validation.
    
    Args:
        query: Vulnerability description
        max_results: Maximum results to return
        vulnerability_context: Optional context (OS, QID, asset info)
    
    Returns:
        List of relevant CVE results with CWE enrichment
    """
    print(f"======== Starting LLM-Driven CVE Search ========")
    print(f"Query: '{query}'")
    if vulnerability_context:
        print(f"Context: OS={vulnerability_context.get('Operating System', 'N/A')}")
    print(f"=================================================")
    
    try:
        agent = create_cve_agent()
        
        if not vulnerability_context:
            vulnerability_context = {}
        
        initial_state = {
            "messages": [HumanMessage(content=f"Search for CVEs: {query}")],
            "original_query": query,
            "os_context": vulnerability_context.get("Operating System", "Unknown"),
            "qid": vulnerability_context.get("QID", ""),
            "asset_info": {
                k: str(v) for k, v in vulnerability_context.items()
                if k not in ["Operating System", "QID"]
            },
            "enhanced_queries": [],
            "search_results": [],
            "cve_results": [],
            "search_attempts": 0,
            "max_attempts": 4,
            "search_strategy": "llm_driven"
        }
        
        config = {"recursion_limit": 15}
        final_state = agent.invoke(initial_state, config=config)
        
        cve_results = final_state.get("cve_results", [])
        
        if cve_results:
            print(f"\n======== Search Complete ========")
            print(f"Found {len(cve_results)} relevant CVEs with LLM validation")
            print(f"=================================\n")
            return cve_results[:max_results]
        else:
            print(f"\n======== Search Complete ========")
            print(f"No relevant CVEs found")
            print(f"=================================\n")
            return []
    
    except Exception as e:
        print(f"\n!!!!!!!! Error during search !!!!!!!!")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return []