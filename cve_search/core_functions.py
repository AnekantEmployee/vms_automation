import re
import json
import sys
import time
import requests
import urllib.parse
import concurrent.futures
from threading import Lock
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import List, Dict, Any, TypedDict, Annotated
import os
from dotenv import load_dotenv

# LangGraph and LangChain imports
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI

# Optional TavilySearch import
try:
    from langchain_community.tools.tavily_search import TavilySearchResults
    TAVILY_AVAILABLE = True
    print("TavilySearch available")
except ImportError:
    TAVILY_AVAILABLE = False
    print("TavilySearch not available - continuing without it")
    
# Add the project root to path so we can import cve_validator
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from cve_validator import CVEValidator
    CVE_VALIDATION_ENABLED = True
    print("✅ CVE Validation enabled")
except ImportError:
    CVE_VALIDATION_ENABLED = False
    print("⚠️ CVE Validation not available - install cve_validator.py")

# Load environment variables
load_dotenv()

# --- Caching ---
_nist_cache = {}
_cve_org_cache = {}
_cache_lock = Lock()


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
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    vector_string: str = ""
    cvss_version: str = ""
    confidence_score: float = 1.0

    def to_dict(self):
        """Convert to dictionary for easy serialization"""
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


# --- State Definition and Tools ---
class CVESearchState(TypedDict):
    messages: Annotated[list, add_messages]
    original_query: str
    os_context: str  # NEW: OS/platform context for validation
    qid: str  # NEW: QID for specific validation rules
    asset_info: Dict[str, str]  # NEW: Additional asset context
    enhanced_queries: List[str]
    search_results: List[Dict]
    cve_results: List[CVEResult]
    search_attempts: int
    max_attempts: int
    search_strategy: str
    external_search_done: bool


def extract_cve_keywords_func(query: str) -> str:
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
        'certificate': ['validation', 'verification', 'chain', 'trust']
    }
    query_lower = query.lower()
    extracted_keywords = []
    words = re.findall(r'\b\w{3,}\b', query_lower)
    for word in words:
        if len(word) > 3:
            extracted_keywords.append(word)
    for main_term, related_terms in keyword_mappings.items():
        if main_term.replace('/', ' ') in query_lower or any(term in query_lower for term in main_term.split('/')):
            extracted_keywords.extend(related_terms[:2])
    seen = set()
    unique_keywords = []
    for keyword in extracted_keywords:
        if keyword not in seen and len(keyword) > 2:
            seen.add(keyword)
            unique_keywords.append(keyword)
    result = ' '.join(unique_keywords[:6])
    print(f"Extracted keywords from '{query}': {result}")
    return result


@tool
def extract_cve_keywords(query: str) -> str:
    """Extract and enhance keywords for CVE searching from a vulnerability description."""
    return extract_cve_keywords_func(query)


@tool
def search_external_cve_info_tool(query: str) -> str:
    """Search for additional CVE information using external search if available."""
    return search_external_cve_info_func(query)


def search_external_cve_info_func(query: str) -> str:
    """Search for additional CVE information using external search if available."""
    if not TAVILY_AVAILABLE:
        print("External search not available")
        return f"External search not available. Query was: {query}"
    try:
        search = TavilySearchResults(max_results=3, search_depth="basic")
        cve_query = f"CVE vulnerability {query} security"
        results = search.run(cve_query)
        if results:
            print(f"Found {len(results)} external results for: {query}")
            return f"External search results for '{query}': {json.dumps(results, indent=2)}"
        else:
            return f"No external results found for: {query}"
    except Exception as e:
        print(f"External search failed: {e}")
        return f"External search failed: {str(e)}"


# --- Agent Nodes ---
def query_analyzer_node(state: CVESearchState) -> CVESearchState:
    print(f"\n--- Analyzing Query ---")
    print(f"Original query: {state['original_query']}")
    try:
        llm = ChatGoogleGenerativeAI(model=os.getenv("MODEL_NAME", "gemini-2.5-flash"), temperature=0.1, max_tokens=150)
        prompt = f"""
        Analyze this security vulnerability query and extract the most important search terms for finding CVEs:
        Query: "{state['original_query']}"
        Focus on:
        1. Software/product names (Apache, Linux, Windows, etc.)
        2. Vulnerability types (RCE, XSS, buffer overflow, etc.)
        3. Technical components (SSL, SSH, authentication, etc.)
        Return only the key search terms, maximum 6 words, separated by spaces.
        Be specific and use terms commonly found in CVE descriptions.
        Search terms:"""
        response = llm.invoke([HumanMessage(content=prompt)])
        enhanced_query = response.content.strip().lower()
        if not enhanced_query or len(enhanced_query) < 5:
            enhanced_query = extract_cve_keywords_func(state['original_query'])
        print(f"LLM Enhanced query: {enhanced_query}")
        enhanced_queries = list(dict.fromkeys([
            enhanced_query,
            extract_cve_keywords_func(state['original_query']),
            state['original_query'].lower()
        ]))
        return {
            **state,
            "enhanced_queries": enhanced_queries,
            "messages": state["messages"] + [AIMessage(content=f"Generated enhanced queries: {enhanced_queries}")]
        }
    except Exception as e:
        print(f"Query analysis failed: {e}")
        enhanced_query = extract_cve_keywords_func(state['original_query'])
        return {
            **state,
            "enhanced_queries": [enhanced_query, state['original_query'].lower()],
            "messages": state["messages"] + [AIMessage(content=f"Fallback query enhancement: {enhanced_query}")]
        }


def cve_search_node(state: CVESearchState) -> CVESearchState:
    print(f"\n--- Searching for CVEs ---")
    search_attempts = state.get('search_attempts', 0)
    print(f"Attempt {search_attempts + 1}/{state.get('max_attempts', 3)}")
    if search_attempts >= state.get('max_attempts', 3):
        print("Max search attempts reached")
        return state

    all_results = []
    query_to_try = state['enhanced_queries'][search_attempts]
    print(f"Using query: '{query_to_try}'")
    
    # Search in actual CVE databases
    results = search_cve_databases(query_to_try)
    
    if results:
        all_results.extend(results)
        print(f"Found {len(results)} potential results for query.")
    else:
        print(f"No results found for query.")
    
    existing_cves = {cve.cve_id for cve in state.get('cve_results', [])}
    unique_results = [res for res in all_results if res.cve_id not in existing_cves]
    
    final_results = state.get('cve_results', []) + unique_results
    print(f"Total unique CVEs found so far: {len(final_results)}")
    
    return {
        **state,
        "cve_results": final_results,
        "search_attempts": search_attempts + 1,
        "messages": state["messages"] + [AIMessage(content=f"Found {len(unique_results)} new CVE results in attempt {search_attempts + 1}")]
    }


def external_search_node(state: CVESearchState) -> CVESearchState:
    print("\n--- Performing External Search ---")
    if state.get('external_search_done', False):
        print("External search already completed.")
        return state
    try:
        external_results = search_external_cve_info_func(state['original_query'])
        return {
            **state,
            "search_results": [{"external_search": external_results}],
            "external_search_done": True,
            "messages": state["messages"] + [AIMessage(content="Performed external search for additional context")]
        }
    except Exception as e:
        print(f"External search failed: {e}")
        return {
            **state,
            "external_search_done": True,
            "messages": state["messages"] + [AIMessage(content=f"External search failed: {str(e)}")]
        }

def result_scorer_node(state: CVESearchState) -> CVESearchState:
    """Enhanced scoring with CVE validation"""
    print("\n--- Scoring, Validating, and Ranking Results ---")
    
    if not state['cve_results']:
        print("No CVE results to score.")
        return state
    
    print(f"Processing {len(state['cve_results'])} CVE results...")
    
    # Get vulnerability context for validation
    vulnerability_context = {
        "Title": state.get('original_query', ''),
        "Operating System": state.get('os_context', 'Unknown'),
        "QID": state.get('qid', ''),
        **state.get('asset_info', {})
    }
    
    # Initialize validator if available
    validator = None
    if CVE_VALIDATION_ENABLED:
        validator = CVEValidator()
        print("Using CVE validation")
    else:
        print("CVE validation not available, using basic scoring only")
    
    validated_results = []
    filtered_count = 0
    
    for result in state['cve_results']:
        # Calculate basic relevance score
        basic_score = calculate_relevance_score(result, state['original_query'])
        
        # Perform validation if available
        if validator:
            cve_dict = {
                "cve_id": result.cve_id,
                "description": result.description,
                "affected_products": result.affected_products,
                "score": result.score,
                "severity": result.severity
            }
            
            validation = validator.validate_cve_relevance(cve_dict, vulnerability_context)
            
            if not validation.is_relevant:
                print(f"  ❌ {result.cve_id}: FILTERED OUT (confidence: {validation.confidence_score:.2f})")
                if validation.warning_flags:
                    for warning in validation.warning_flags[:2]:  # Show first 2 warnings
                        print(f"     ⚠️  {warning}")
                filtered_count += 1
                continue
            
            # Combine basic score with validation confidence
            result.confidence_score = (basic_score * 0.3) + (validation.confidence_score * 10.0 * 0.7)
            
            print(f"  ✅ {result.cve_id}: RELEVANT (validation: {validation.confidence_score:.2f}, final: {result.confidence_score:.1f})")
            if validation.relevance_reasons:
                for reason in validation.relevance_reasons[:2]:  # Show first 2 reasons
                    print(f"     ✓ {reason}")
        else:
            # Fallback to basic scoring only
            result.confidence_score = basic_score
        
        validated_results.append(result)
    
    # Sort by confidence score and CVSS score
    validated_results.sort(key=lambda x: (x.confidence_score, x.score), reverse=True)
    
    print(f"\nValidation Summary:")
    print(f"  Total CVEs found: {len(state['cve_results'])}")
    print(f"  Validated as relevant: {len(validated_results)}")
    print(f"  Filtered out: {filtered_count}")
    
    return {
        **state,
        "cve_results": validated_results,
        "messages": state["messages"] + [
            AIMessage(content=f"Validated {len(validated_results)}/{len(state['cve_results'])} CVEs as relevant")
        ]
    }


# --- Helper Functions with Real CVE Database Search ---
def calculate_relevance_score(cve_result: CVEResult, original_query: str) -> float:
    """Calculate how relevant a CVE is to the original query."""
    query_lower = original_query.lower()
    desc_lower = cve_result.description.lower()
    score = 0.0
    query_words = set(re.findall(r'\b\w{3,}\b', query_lower))
    desc_words = set(re.findall(r'\b\w{3,}\b', desc_lower))
    matches = query_words.intersection(desc_words)
    score += len(matches) * 2.0
    if cve_result.score > 7.0: score += 1.5
    elif cve_result.score > 4.0: score += 1.0
    if cve_result.published_date and '2024' in cve_result.published_date: score += 0.5
    return min(score, 10.0)


def search_cve_databases(query: str) -> List[CVEResult]:
    """Search multiple CVE databases for the given query."""
    print(f"Searching CVE databases for: '{query}'")
    
    results = []
    
    # Search NIST NVD database
    nist_results = search_nist_nvd(query)
    if nist_results:
        results.extend(nist_results)
    
    # Search CVE.org database
    cve_org_results = search_cve_org(query)
    if cve_org_results:
        results.extend(cve_org_results)
    
    # If no results found, try a broader search
    if not results:
        print("No results found with original query, trying broader search")
        broader_query = " ".join(query.split()[:3])  # Use first 3 keywords
        if broader_query != query:
            nist_results = search_nist_nvd(broader_query)
            if nist_results:
                results.extend(nist_results)
    
    return results


def search_nist_nvd(query: str) -> List[CVEResult]:
    """Search the NIST National Vulnerability Database."""
    print(f"Searching NIST NVD for: {query}")
    
    try:
        # Check cache first
        with _cache_lock:
            if query in _nist_cache:
                print(f"Using cached NIST results for: {query}")
                return _nist_cache[query]
        
        # Encode query for URL
        encoded_query = urllib.parse.quote(query)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}"
        
        # Make request to NVD API
        headers = {
            "User-Agent": "CVE-Search-Agent/1.0 (Security Research)"
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"NVD API returned status code: {response.status_code}")
            return []
        
        data = response.json()
        
        results = []
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                if "cve" not in vuln:
                    continue
                    
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
        
        # Cache the results
        with _cache_lock:
            _nist_cache[query] = results
            
        print(f"Found {len(results)} results from NIST NVD")
        return results
        
    except Exception as e:
        print(f"Error searching NIST NVD: {e}")
        return []


def search_cve_org(query: str) -> List[CVEResult]:
    """Search the CVE.org database."""
    print(f"Searching CVE.org for: {query}")
    
    try:
        # Check cache first
        with _cache_lock:
            if query in _cve_org_cache:
                print(f"Using cached CVE.org results for: {query}")
                return _cve_org_cache[query]
        
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
        
        response = requests.post(url, json=graphql_query, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"CVE.org API returned status code: {response.status_code}")
            return []
        
        data = response.json()
        
        results = []
        if "data" in data and "cveList" in data["data"] and "cves" in data["data"]["cveList"]:
            for cve_data in data["data"]["cveList"]["cves"]:
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
        
        # Cache the results
        with _cache_lock:
            _cve_org_cache[query] = results
            
        print(f"Found {len(results)} results from CVE.org")
        return results
        
    except Exception as e:
        print(f"Error searching CVE.org: {e}")
        return []


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


# --- Decision Functions ---
def should_continue_search(state: CVESearchState) -> str:
    """Decide next step based on search results and attempts."""
    print("\n--- Making a Decision ---")
    if state.get('cve_results'):
        print("Decision: Found CVE results. Proceeding to scoring.")
        return "score_results"
    
    if state.get('search_attempts', 0) < state.get('max_attempts', 3):
        print("Decision: No results yet, continuing search with next query.")
        return "continue_search"
    
    print("Decision: Max internal search attempts reached without results. Trying external search.")
    return "external_search"


# --- Build Agent Graph ---
def create_cve_agent():
    """Create the CVE search agent using LangGraph."""
    workflow = StateGraph(CVESearchState)
    workflow.add_node("analyze_query", query_analyzer_node)
    workflow.add_node("search_cves", cve_search_node)
    workflow.add_node("external_search", external_search_node)
    workflow.add_node("score_results", result_scorer_node)
    
    workflow.add_edge(START, "analyze_query")
    workflow.add_edge("analyze_query", "search_cves")
    
    workflow.add_conditional_edges(
        "search_cves",
        should_continue_search,
        {
            "score_results": "score_results",
            "continue_search": "search_cves",
            "external_search": "external_search"
        }
    )
    
    workflow.add_edge("external_search", END)
    workflow.add_edge("score_results", END)
    
    app = workflow.compile()
    return app


def combined_cve_search(
    query: str, 
    max_results: int = 10,
    vulnerability_context: Dict[str, Any] = None
) -> List[CVEResult]:
    """
    Enhanced CVE search using agent-based approach with validation.
    
    Args:
        query: Search query (vulnerability title/description)
        max_results: Maximum number of results to return
        vulnerability_context: Additional context for validation
            - Operating System: OS/platform info
            - QID: Qualys QID
            - Asset Name: Asset hostname
            - etc.
    
    Returns:
        List of validated, relevant CVE results
    """
    print(f"======== Starting Agent-Based CVE Search with Validation ========")
    print(f"Initial Query: '{query}'")
    if vulnerability_context:
        print(f"Context: OS={vulnerability_context.get('Operating System', 'N/A')}, QID={vulnerability_context.get('QID', 'N/A')}")
    print(f"=================================================================")
    
    try:
        agent = create_cve_agent()
        
        # Prepare vulnerability context
        if not vulnerability_context:
            vulnerability_context = {}
        
        initial_state = {
            "messages": [HumanMessage(content=f"Search for CVEs related to: {query}")],
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
            "max_attempts": 3,
            "search_strategy": "multi_source",
            "external_search_done": False
        }
        
        config = {"recursion_limit": 10}
        final_state = agent.invoke(initial_state, config=config)
        
        cve_results = final_state.get("cve_results", [])
        
        if cve_results:
            print(f"\n======== Agent Search Complete ========")
            print(f"Found {len(cve_results)} validated and relevant CVE(s).")
            print(f"========================================\n")
            return cve_results[:max_results]
        else:
            print(f"\n======== Agent Search Complete ========")
            print(f"No relevant CVEs found for query: '{query}'")
            print(f"========================================\n")
            return []
            
    except Exception as e:
        print(f"\n!!!!!!!! An error occurred during the agent search !!!!!!!!")
        print(f"Error for query '{query}': {e}")
        import traceback
        traceback.print_exc()
        return []
