import re
import json
import requests
import time
from datetime import datetime
from tavily import TavilyClient
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from enhanced_cve_search.cve_structures import (
    EnhancedCVEInfo,
    StructuredSearchResults,
    EnhancedCVEParser,
    EnhancedCWEFetcher
)
from enhanced_cve_search.threaded_cve_validator import validate_cves_threaded


class EnhancedCVESearchSystem:
    """
    Enhanced CVE search system with comprehensive data extraction and robust fallbacks
    """
    
    def __init__(self, tavily_api_key: str):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        self.cve_parser = EnhancedCVEParser()
        self.cwe_fetcher = EnhancedCWEFetcher(self.tavily)
        
        # Rate limiting
        self.nist_last_request = 0
        self.nist_min_interval = 6
        self.tenable_last_request = 0
        self.tenable_min_interval = 2
        
        # Caching
        self.cve_cache = {}
        self.cwe_cache = {}
        
        # Search source priorities
        self.search_sources = [
            "nist_api",
            "tenable",
            "web_search",
            "cwe_based",
            "mitre_org",
            "exploit_db"
        ]
        
    def search_vulnerability(
        self,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]] = None,
        max_cves: int = 10
    ) -> StructuredSearchResults:
        """
        Main search function returning structured results with robust fallback
        """
        print(f"\n{'='*80}")
        print(f"🔍 ENHANCED CVE/CWE SEARCH SYSTEM (WITH ROBUST FALLBACK)")
        print(f"{'='*80}")
        print(f"Query: {vulnerability_description}")
        if context:
            print(f"Context: {json.dumps(context, indent=2)}")
        print(f"{'='*80}\n")
        
        # Initialize results structure
        results = StructuredSearchResults(
            query=vulnerability_description,
            timestamp=datetime.now().isoformat(),
            context=context or {}
        )
        
        # Step 1: LLM analyzes vulnerability (with fallback)
        print("📊 Step 1: Analyzing vulnerability with LLM...")
        analysis = self._analyze_vulnerability_with_llm(vulnerability_description, context)
        results.analysis = analysis
        
        # Extract and fetch detailed CWE information
        for cwe_data in analysis.get("cwes", []):
            cwe_id = cwe_data.get("cwe_id", "")
            if cwe_id:
                cwe_details = self.cwe_fetcher.get_cwe_details(cwe_id)
                if cwe_details:
                    results.cwes.append(cwe_details)
        
        # Step 2: Generate search queries (with fallback)
        print("\n🎯 Step 2: Generating search queries...")
        search_queries = self._generate_search_queries(vulnerability_description, analysis, context)
        results.search_strategy = search_queries
        
        # Step 3: Search for CVEs using multiple sources
        print("\n🔎 Step 3: Searching for CVEs from multiple sources...")
        all_cves = []
        
        # Source 1: NIST API search
        print("  → Searching NIST NVD API...")
        for query in search_queries[:3]:
            cves = self._search_nist_api(query["query"])
            all_cves.extend(cves)
            if len(all_cves) >= 5:  # Early success
                break
            time.sleep(0.5)
        
        # Source 2: Tenable CVE Search (NEW)
        print("  → Searching Tenable CVE Database...")
        tenable_cves = self._search_tenable_cve(vulnerability_description, context)
        all_cves.extend(tenable_cves)
        
        # Source 3: Web search
        print("  → Searching web for additional CVEs...")
        web_cves = self._search_web_for_cves(vulnerability_description, context)
        all_cves.extend(web_cves)
        
        # Source 4: CWE-based search
        if results.cwes:
            print(f"  → Searching by CWE IDs...")
            for cwe in results.cwes[:2]:
                cwe_cves = self._search_by_cwe(cwe.cwe_id)
                all_cves.extend(cwe_cves)
                time.sleep(0.5)
        
        # Source 5: MITRE CVE.org search (NEW)
        print("  → Searching MITRE CVE.org...")
        mitre_cves = self._search_mitre_org(vulnerability_description, context)
        all_cves.extend(mitre_cves)
        
        # Source 6: Keyword-based CVE ID extraction (NEW)
        print("  → Extracting CVE IDs from query...")
        extracted_cves = self._extract_and_fetch_cve_ids(vulnerability_description)
        all_cves.extend(extracted_cves)
        
        # Deduplicate
        unique_cves = self._deduplicate_cves(all_cves)
        print(f"\n📋 Found {len(unique_cves)} unique CVEs from all sources")
        
        # Step 4: Validate CVEs
        print("\n✅ Step 4: Running CVE validation...")
        validated_cves = self._validate_cves(
            unique_cves,
            vulnerability_description,
            analysis,
            context
        )
        
        # Step 5: Enrich CVEs with detailed CWE information
        print("\n🔬 Step 5: Enriching CVEs with CWE details...")
        enriched_cves = self._enrich_cves_with_cwes(validated_cves)
        
        # Sort and limit
        final_cves = sorted(
            enriched_cves,
            key=lambda x: (x.relevance_score, x.score),
            reverse=True
        )[:max_cves]
        
        results.cves = final_cves
        
        # Calculate summary statistics
        results.summary_statistics = results.get_summary()
        
        print(f"\n{'='*80}")
        print(f"✨ SEARCH COMPLETE")
        print(f"{'='*80}")
        print(f"Total CVEs: {len(final_cves)}")
        print(f"Total CWEs: {len(results.cwes)}")
        print(f"Average CVSS Score: {results.summary_statistics.get('average_cvss_score', 0):.2f}")
        print(f"Average Relevance: {results.summary_statistics.get('average_relevance_score', 0):.2f}")
        print(f"{'='*80}\n")
        
        return results
    
    def _analyze_vulnerability_with_llm(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Use LLM to analyze vulnerability with robust fallback"""
        try:
            from config.api_key_manager import generate_content_with_fallback
            
            context_str = ""
            if context:
                context_str = f"\n\nContext:\n{json.dumps(context, indent=2)}"
            
            prompt = f"""You are a cybersecurity expert analyzing a vulnerability.

Vulnerability Description: {vulnerability}{context_str}

Provide a comprehensive analysis in JSON format:
{{
    "vulnerability_type": "specific type (e.g., 'SQL Injection', 'Certificate Validation')",
    "severity_estimate": "Critical/High/Medium/Low",
    "affected_components": ["list of likely affected software/components"],
    "cwes": [
        {{
            "cwe_id": "CWE-XXX",
            "relevance": "why this CWE is relevant",
            "confidence": 0.0-1.0
        }}
    ],
    "key_terms": ["important technical terms for searching"],
    "search_focus": "what to prioritize when searching for CVEs"
}}

Return ONLY valid JSON."""

            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.2,
                max_output_tokens=1200
            )
            
            analysis = self._parse_json_robust(response)
            
            if analysis:
                print(f"  ✓ Identified: {analysis.get('vulnerability_type', 'Unknown')}")
                print(f"  ✓ CWEs: {len(analysis.get('cwes', []))}")
                return analysis
            else:
                print("  ⚠ JSON parsing failed, using rule-based fallback")
                return self._fallback_analysis(vulnerability, context)
        
        except Exception as e:
            print(f"  ⚠ LLM analysis failed: {str(e)[:100]}")
            print("  → Using rule-based analysis fallback")
            return self._fallback_analysis(vulnerability, context)
    
    def _fallback_analysis(self, vulnerability: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Enhanced rule-based fallback analysis when LLM fails"""
        vuln_lower = vulnerability.lower()
        
        # Extract keywords
        keywords = re.findall(r'\b\w{4,}\b', vuln_lower)
        unique_keywords = list(dict.fromkeys(keywords))[:10]
        
        # Detect vulnerability type using pattern matching
        vuln_type = "Unknown"
        cwes = []
        severity = "Medium"
        
        # Vulnerability type detection patterns
        vuln_patterns = {
            "SQL Injection": {
                "keywords": ["sql", "injection", "sqli", "database"],
                "cwes": [{"cwe_id": "CWE-89", "relevance": "SQL injection vulnerability", "confidence": 0.8}],
                "severity": "Critical"
            },
            "Cross-Site Scripting": {
                "keywords": ["xss", "cross-site", "scripting", "javascript"],
                "cwes": [{"cwe_id": "CWE-79", "relevance": "XSS vulnerability", "confidence": 0.8}],
                "severity": "High"
            },
            "Buffer Overflow": {
                "keywords": ["buffer", "overflow", "memory", "heap", "stack"],
                "cwes": [{"cwe_id": "CWE-119", "relevance": "Buffer overflow", "confidence": 0.8}],
                "severity": "Critical"
            },
            "Authentication Bypass": {
                "keywords": ["authentication", "bypass", "auth", "login"],
                "cwes": [{"cwe_id": "CWE-287", "relevance": "Authentication bypass", "confidence": 0.8}],
                "severity": "Critical"
            },
            "Path Traversal": {
                "keywords": ["path", "traversal", "directory", "file"],
                "cwes": [{"cwe_id": "CWE-22", "relevance": "Path traversal", "confidence": 0.8}],
                "severity": "High"
            },
            "Remote Code Execution": {
                "keywords": ["rce", "remote", "code", "execution", "execute"],
                "cwes": [{"cwe_id": "CWE-94", "relevance": "Code execution", "confidence": 0.8}],
                "severity": "Critical"
            },
            "Privilege Escalation": {
                "keywords": ["privilege", "escalation", "elevation", "root"],
                "cwes": [{"cwe_id": "CWE-269", "relevance": "Privilege escalation", "confidence": 0.8}],
                "severity": "High"
            },
            "Denial of Service": {
                "keywords": ["dos", "ddos", "denial", "service", "crash"],
                "cwes": [{"cwe_id": "CWE-400", "relevance": "DoS vulnerability", "confidence": 0.7}],
                "severity": "Medium"
            },
            "Information Disclosure": {
                "keywords": ["information", "disclosure", "leak", "exposure"],
                "cwes": [{"cwe_id": "CWE-200", "relevance": "Information disclosure", "confidence": 0.7}],
                "severity": "Medium"
            },
            "Certificate Validation": {
                "keywords": ["certificate", "ssl", "tls", "validation", "crypto"],
                "cwes": [{"cwe_id": "CWE-295", "relevance": "Certificate validation", "confidence": 0.8}],
                "severity": "High"
            },
            "Command Injection": {
                "keywords": ["command", "injection", "shell", "exec"],
                "cwes": [{"cwe_id": "CWE-77", "relevance": "Command injection", "confidence": 0.8}],
                "severity": "Critical"
            }
        }
        
        # Match patterns
        best_match_score = 0
        for pattern_name, pattern_data in vuln_patterns.items():
            pattern_keywords = pattern_data["keywords"]
            match_count = sum(1 for kw in pattern_keywords if kw in vuln_lower)
            match_score = match_count / len(pattern_keywords)
            
            if match_score > best_match_score and match_count >= 2:
                best_match_score = match_score
                vuln_type = pattern_name
                cwes = pattern_data["cwes"]
                severity = pattern_data["severity"]
        
        # Extract components from context
        affected_components = []
        if context:
            os_name = context.get("Operating System", "")
            if os_name:
                affected_components.append(os_name)
            asset_type = context.get("Asset Type", "")
            if asset_type:
                affected_components.append(asset_type)
        
        # Extract software names from vulnerability description
        software_patterns = [
            r'\b(apache|nginx|mysql|postgresql|mongodb|redis|elasticsearch)\b',
            r'\b(windows|linux|ubuntu|debian|centos|rhel)\b',
            r'\b(wordpress|drupal|joomla|php|python|java|node\.?js)\b',
            r'\b(openssh|openssl|openswan|apache2)\b'
        ]
        for pattern in software_patterns:
            matches = re.findall(pattern, vuln_lower, re.IGNORECASE)
            affected_components.extend(matches)
        
        print(f"  ✓ Rule-based detection: {vuln_type}")
        print(f"  ✓ Estimated severity: {severity}")
        print(f"  ✓ Matched CWEs: {len(cwes)}")
        
        return {
            "vulnerability_type": vuln_type,
            "severity_estimate": severity,
            "affected_components": list(set(affected_components))[:5],
            "cwes": cwes,
            "key_terms": unique_keywords,
            "search_focus": f"Focus on {vuln_type} vulnerabilities in {', '.join(affected_components[:2]) if affected_components else 'various systems'}"
        }
    
    def _generate_search_queries(
        self,
        vulnerability: str,
        analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, str]]:
        """Generate search queries with robust fallback"""
        try:
            from config.api_key_manager import generate_content_with_fallback
            
            context_str = ""
            if context:
                context_str = f"\nContext: {json.dumps(context)}"
            
            prompt = f"""Generate 5 optimal search queries for finding CVEs.

Vulnerability: {vulnerability}
Analysis: {json.dumps(analysis)}{context_str}

Return ONLY JSON array:
[
    {{"query": "text", "rationale": "why"}},
    ...
]"""

            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.3,
                max_output_tokens=500
            )
            
            cleaned = response.strip()
            json_match = re.search(r'\[[^\[\]]*(?:\{[^{}]*\}[^\[\]]*)*\]', cleaned, re.DOTALL)
            
            if json_match:
                queries = json.loads(json_match.group().strip())
                if isinstance(queries, list) and len(queries) > 0:
                    print(f"  ✓ Generated {len(queries)} LLM queries:")
                    for i, q in enumerate(queries, 1):
                        print(f"    {i}. {q.get('query', '')}")
                    return queries
        except Exception as e:
            print(f"  ⚠ LLM query generation failed: {str(e)[:100]}")
        
        # Fallback queries
        print("  → Using rule-based query generation")
        return self._generate_fallback_queries(vulnerability, analysis, context)
    
    def _generate_fallback_queries(
        self,
        vulnerability: str,
        analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Enhanced fallback query generation with better strategies"""
        key_terms = analysis.get("key_terms", [])
        vuln_type = analysis.get("vulnerability_type", "")
        affected_components = analysis.get("affected_components", [])
        
        queries = []
        
        # Query 1: Vulnerability type + components
        if vuln_type != "Unknown" and affected_components:
            queries.append({
                "query": f"{vuln_type} {affected_components[0]}",
                "rationale": "Vulnerability type with primary component"
            })
        
        # Query 2: Key terms combination
        if len(key_terms) >= 2:
            queries.append({
                "query": " ".join(key_terms[:3]),
                "rationale": "Top 3 key terms"
            })
        
        # Query 3: Vulnerability type alone
        if vuln_type != "Unknown":
            queries.append({
                "query": vuln_type,
                "rationale": "Vulnerability type only"
            })
        
        # Query 4: Original description (truncated)
        queries.append({
            "query": vulnerability[:60].strip(),
            "rationale": "Original description (truncated)"
        })
        
        # Query 5: Context-based query
        if context:
            os_name = context.get("Operating System", "")
            if os_name and key_terms:
                queries.append({
                    "query": f"{os_name} {key_terms[0] if key_terms else 'vulnerability'}",
                    "rationale": "OS + primary keyword"
                })
            elif affected_components:
                queries.append({
                    "query": f"{affected_components[0]} vulnerability",
                    "rationale": "Component-based search"
                })
        
        # Query 6: CWE-based (if available)
        cwes = analysis.get("cwes", [])
        if cwes:
            cwe_id = cwes[0].get("cwe_id", "")
            if cwe_id:
                queries.append({
                    "query": cwe_id,
                    "rationale": "Primary CWE ID"
                })
        
        # Deduplicate and limit
        seen = set()
        unique_queries = []
        for q in queries:
            query_text = q["query"].lower()
            if query_text not in seen and len(query_text) > 2:
                seen.add(query_text)
                unique_queries.append(q)
        
        print(f"  ✓ Generated {len(unique_queries[:5])} fallback queries:")
        for i, q in enumerate(unique_queries[:5], 1):
            print(f"    {i}. {q['query']}")
        
        return unique_queries[:5]
    
    def _search_nist_api(self, query: str) -> List[EnhancedCVEInfo]:
        """Search NIST NVD API with better error handling"""
        cache_key = f"nist:{query}"
        if cache_key in self.cve_cache:
            print(f"    📦 Using cached results for: {query}")
            return self.cve_cache[cache_key]
        
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.nist_last_request
        if time_since_last < self.nist_min_interval:
            time.sleep(self.nist_min_interval - time_since_last)
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": query,
                "resultsPerPage": 20
            }
            headers = {"User-Agent": "EnhancedCVESearcher/2.0"}
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            self.nist_last_request = time.time()
            
            if response.status_code != 200:
                print(f"    ⚠ NIST API returned status {response.status_code}")
                return []
            
            data = response.json()
            cves = []
            
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_info = self.cve_parser.parse_nist_cve(cve_data)
                if cve_info:
                    cves.append(cve_info)
            
            print(f"    ✓ Found {len(cves)} CVEs from NIST")
            self.cve_cache[cache_key] = cves
            return cves
            
        except requests.Timeout:
            print(f"    ⚠ NIST API timeout")
            return []
        except requests.RequestException as e:
            print(f"    ⚠ NIST API error: {str(e)[:50]}")
            return []
        except Exception as e:
            print(f"    ❌ NIST search failed: {str(e)[:50]}")
            return []
    
    def _search_tenable_cve(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[EnhancedCVEInfo]:
        """Search Tenable CVE database (NEW)"""
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.tenable_last_request
        if time_since_last < self.tenable_min_interval:
            time.sleep(self.tenable_min_interval - time_since_last)
        
        try:
            # Build search query
            search_query = vulnerability[:100]
            if context and context.get("Operating System"):
                search_query += f" {context['Operating System']}"
            
            # Tenable CVE search URL
            url = "https://www.tenable.com/cve/search"
            params = {
                "q": search_query,
                "sort": "",
                "page": 1
            }
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=15)
            self.tenable_last_request = time.time()
            
            if response.status_code != 200:
                print(f"    ⚠ Tenable returned status {response.status_code}")
                return []
            
            # Parse HTML to extract CVE IDs
            soup = BeautifulSoup(response.text, 'html.parser')
            cve_ids = set()
            
            # Find CVE links and references
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
            
            # Extract from text content
            page_text = soup.get_text()
            found_cves = cve_pattern.findall(page_text)
            cve_ids.update(found_cves[:10])  # Limit to first 10
            
            print(f"    ✓ Found {len(cve_ids)} CVE IDs from Tenable")
            
            # Fetch details for each CVE
            cves = []
            for cve_id in list(cve_ids)[:5]:  # Limit to 5 to avoid rate limits
                cve_info = self._get_cve_by_id(cve_id)
                if cve_info:
                    cve_info.source = "Tenable"
                    cves.append(cve_info)
                time.sleep(0.5)
            
            return cves
            
        except requests.Timeout:
            print(f"    ⚠ Tenable search timeout")
            return []
        except Exception as e:
            print(f"    ⚠ Tenable search failed: {str(e)[:50]}")
            return []
    
    def _search_mitre_org(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[EnhancedCVEInfo]:
        """Search MITRE CVE.org (NEW)"""
        try:
            # Use Tavily to search cve.mitre.org
            search_query = f"site:cve.mitre.org {vulnerability[:80]}"
            
            results = self.tavily.search(
                query=search_query,
                search_depth="basic",
                max_results=5,
                include_domains=["cve.mitre.org"]
            )
            
            cve_ids = set()
            for result in results.get("results", []):
                content = result.get("content", "") + result.get("title", "") + result.get("url", "")
                found_cves = re.findall(r'CVE-\d{4}-\d{4,}', content)
                cve_ids.update(found_cves)
            
            print(f"    ✓ Found {len(cve_ids)} CVE IDs from MITRE")
            
            # Fetch details
            cves = []
            for cve_id in list(cve_ids)[:5]:
                cve_info = self._get_cve_by_id(cve_id)
                if cve_info:
                    cve_info.source = "MITRE CVE.org"
                    cves.append(cve_info)
                time.sleep(0.5)
            
            return cves
            
        except Exception as e:
            print(f"    ⚠ MITRE search failed: {str(e)[:50]}")
            return []
    
    def _extract_and_fetch_cve_ids(self, vulnerability: str) -> List[EnhancedCVEInfo]:
        """Extract CVE IDs mentioned in the query and fetch them (NEW)"""
        try:
            # Find CVE IDs in the query
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
            found_cve_ids = cve_pattern.findall(vulnerability.upper())
            
            if not found_cve_ids:
                return []
            
            print(f"    ✓ Extracted {len(found_cve_ids)} CVE IDs from query")
            
            cves = []
            for cve_id in found_cve_ids[:10]:  # Limit to 10
                cve_info = self._get_cve_by_id(cve_id)
                if cve_info:
                    cve_info.source = "Direct Query"
                    cves.append(cve_info)
                time.sleep(0.5)
            
            return cves
            
        except Exception as e:
            print(f"    ⚠ CVE ID extraction failed: {str(e)[:50]}")
            return []
    
    def _search_web_for_cves(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[EnhancedCVEInfo]:
        """Search web for CVEs with better domain targeting"""
        try:
            search_query = f"CVE {vulnerability}"
            if context and context.get("Operating System"):
                search_query += f" {context['Operating System']}"
            
            results = self.tavily.search(
                query=search_query,
                search_depth="advanced",
                max_results=8,
                include_domains=[
                    "nvd.nist.gov",
                    "cve.org",
                    "mitre.org",
                    "ubuntu.com/security",
                    "access.redhat.com/security",
                    "security.debian.org",
                    "tenable.com/cve"
                ]
            )
            
            cve_ids = set()
            for result in results.get("results", []):
                content = result.get("content", "") + result.get("title", "")
                found_cves = re.findall(r'CVE-\d{4}-\d{4,}', content)
                cve_ids.update(found_cves)
            
            print(f"    ✓ Found {len(cve_ids)} CVE IDs from web")
            
            cves = []
            for cve_id in list(cve_ids)[:8]:
                cve_info = self._get_cve_by_id(cve_id)
                if cve_info:
                    cves.append(cve_info)
                time.sleep(0.5)
            
            return cves
            
        except Exception as e:
            print(f"    ⚠ Web search failed: {str(e)[:50]}")
            return []
    
    def _get_cve_by_id(self, cve_id: str) -> Optional[EnhancedCVEInfo]:
        """Get CVE by ID with caching"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.nist_last_request
        if time_since_last < self.nist_min_interval:
            time.sleep(self.nist_min_interval - time_since_last)
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cveId": cve_id}
            headers = {"User-Agent": "EnhancedCVESearcher/2.0"}
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            self.nist_last_request = time.time()
            
            if response.status_code == 200:
                data = response.json()
                if data.get("vulnerabilities"):
                    cve_data = data["vulnerabilities"][0].get("cve", {})
                    cve_info = self.cve_parser.parse_nist_cve(cve_data)
                    if cve_info:
                        self.cve_cache[cve_id] = cve_info
                    return cve_info
        except Exception as e:
            print(f"    ⚠ Failed to fetch {cve_id}: {str(e)[:50]}")
        
        return None
    
    def _search_by_cwe(self, cwe_id: str) -> List[EnhancedCVEInfo]:
        """Search by CWE ID"""
        return self._search_nist_api(cwe_id)
    
    def _deduplicate_cves(self, cves: List[EnhancedCVEInfo]) -> List[EnhancedCVEInfo]:
        """Remove duplicate CVEs"""
        seen = set()
        unique = []
        for cve in cves:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique.append(cve)
        return unique
    
    def _validate_cves(
        self,
        cves: List[EnhancedCVEInfo],
        vulnerability: str,
        analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[EnhancedCVEInfo]:
        """Validate CVEs for relevance"""
        if not cves:
            return []
        
        try:
            # Try to use threaded validation if available            
            validated_cves = validate_cves_threaded(
                cves=cves,
                vulnerability_description=vulnerability,
                context=context,
                analysis=analysis,
                tavily_api_key=self.tavily.api_key,
                max_workers=8
            )
            
            return validated_cves
            
        except Exception as e:
            print(f"  ❌ Validation failed: {str(e)[:100]}")
            print(f"  ⚠ Using all CVEs with default scores...")
            
            # Fallback: assign default scores
            for cve in cves:
                cve.relevance_score = 0.5
                cve.relevance_reasoning = "Validation unavailable"
            
            return cves
    
    def _enrich_cves_with_cwes(
        self,
        cves: List[EnhancedCVEInfo]
    ) -> List[EnhancedCVEInfo]:
        """Enrich CVEs with detailed CWE information"""
        for cve in cves:
            for cwe_id in cve.cwe_info[:3]:
                cwe_details = self.cwe_fetcher.get_cwe_details(cwe_id)
                if cwe_details:
                    cve.cwe_details.append(cwe_details)
        return cves
    
    def _parse_json_robust(self, response: str) -> Optional[Dict[str, Any]]:
        """Robust JSON parsing"""
        try:
            cleaned = response.strip()
            cleaned = re.sub(r'^```json\s*', '', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s*```$', '', cleaned)
            cleaned = re.sub(r'^```\s*', '', cleaned)
            
            result = json.loads(cleaned)
            if isinstance(result, dict):
                return result
        except:
            pass
        
        return None


def format_results_for_display(results: StructuredSearchResults) -> str:
    """Format results for display"""
    output = []
    output.append("=" * 80)
    output.append("ENHANCED CVE & CWE SEARCH RESULTS")
    output.append("=" * 80)
    output.append(f"\nQuery: {results.query}")
    output.append(f"Timestamp: {results.timestamp}")
    
    # Summary Statistics
    output.append(f"\n{'─' * 80}")
    output.append("SUMMARY STATISTICS")
    output.append(f"{'─' * 80}")
    stats = results.summary_statistics
    output.append(f"Total CVEs: {stats.get('total_cves', 0)}")
    output.append(f"Total CWEs: {stats.get('total_cwes', 0)}")
    output.append(f"Average CVSS Score: {stats.get('average_cvss_score', 0):.2f}")
    output.append(f"Average Relevance: {stats.get('average_relevance_score', 0):.2f}")
    
    severity_breakdown = stats.get('severity_breakdown', {})
    output.append(f"\nSeverity Breakdown:")
    for severity, count in severity_breakdown.items():
        if count > 0:
            output.append(f"  {severity}: {count}")
    
    # CWEs
    if results.cwes:
        output.append(f"\n{'─' * 80}")
        output.append(f"IDENTIFIED CWEs ({len(results.cwes)})")
        output.append(f"{'─' * 80}")
        for cwe in results.cwes:
            output.append(f"\n{cwe.cwe_id}: {cwe.name}")
            output.append(f"Description: {cwe.description[:200]}...")
            output.append(f"Abstraction: {cwe.abstraction_level}")
    
    # CVEs
    if results.cves:
        output.append(f"\n{'─' * 80}")
        output.append(f"RELEVANT CVEs ({len(results.cves)})")
        output.append(f"{'─' * 80}")
        
        for i, cve in enumerate(results.cves, 1):
            output.append(f"\n[{i}] {cve.cve_id}")
            output.append(f"Source: {cve.source}")
            output.append(f"Severity: {cve.severity} (CVSS {cve.cvss_version}: {cve.score})")
            output.append(f"Status: {cve.vuln_status}")
            output.append(f"Relevance: {cve.relevance_score:.2f}")
            output.append(f"Reason: {cve.relevance_reasoning}")
            output.append(f"Description: {cve.description[:200]}...")
            if cve.cwe_info:
                output.append(f"CWEs: {', '.join(cve.cwe_info[:5])}")
            if cve.affected_products:
                output.append(f"Affected: {', '.join(cve.affected_products[:3])}...")
            output.append(f"Published: {cve.published_date[:10]}")
            output.append(f"Exploitability: {cve.exploitability_score:.1f} | Impact: {cve.impact_score:.1f}")
    else:
        output.append("\n❌ No relevant CVEs found")
    
    output.append(f"\n{'=' * 80}")
    return "\n".join(output)


# Example usage
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()
    tavily_key = os.getenv("TAVILY_API_KEY")
    if not tavily_key:
        print("❌ TAVILY_API_KEY not found")
        exit(1)
    
    searcher = EnhancedCVESearchSystem(tavily_api_key=tavily_key)
    
    results = searcher.search_vulnerability(
        vulnerability_description="SSL certificate validation bypass",
        context={"Operating System": "Linux"},
        max_cves=5
    )
    
    # Display formatted results
    print(format_results_for_display(results))
    
    # Access structured data
    print("\n" + "="*80)
    print("STRUCTURED DATA ACCESS")
    print("="*80)
    
    print(f"\nCVE List ({len(results.get_cve_list())} items):")
    for cve_dict in results.get_cve_list()[:2]:
        print(f"  - {cve_dict['cve_id']}: Score {cve_dict['score']}, Relevance {cve_dict['relevance_score']:.2f}")
    
    print(f"\nCWE List ({len(results.get_cwe_list())} items):")
    for cwe_dict in results.get_cwe_list()[:2]:
        print(f"  - {cwe_dict['cwe_id']}: {cwe_dict['name']}")
    
    # Save to JSON
    output_file = "enhanced_cve_results.json"
    with open(output_file, 'w') as f:
        json.dump(results.to_dict(), f, indent=2)
    print(f"\n✅ Results saved to: {output_file}")