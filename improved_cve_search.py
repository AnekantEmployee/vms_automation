import re
import json
import requests
import time
from datetime import datetime
from tavily import TavilyClient
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from config.api_key_manager import generate_content_with_fallback


@dataclass
class CWEInfo:
    """CWE (Common Weakness Enumeration) Information"""
    cwe_id: str
    name: str
    description: str
    abstraction_level: str = "Unknown"
    likelihood: str = "Unknown"
    impact: str = "Unknown"
    
    def to_dict(self):
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "abstraction_level": self.abstraction_level,
            "likelihood": self.likelihood,
            "impact": self.impact
        }


@dataclass
class CVEInfo:
    """CVE (Common Vulnerabilities and Exposures) Information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str = ""
    published_date: str = ""
    modified_date: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    cwe_details: List[CWEInfo] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    
    # Validation metadata
    relevance_score: float = 0.0
    relevance_reasoning: str = ""
    source: str = "NIST NVD"
    
    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published_date": self.published_date,
            "modified_date": self.modified_date,
            "cwe_ids": self.cwe_ids,
            "cwe_details": [cwe.to_dict() for cwe in self.cwe_details],
            "affected_products": self.affected_products,
            "references": self.references[:5],
            "exploit_available": self.exploit_available,
            "patch_available": self.patch_available,
            "relevance_score": self.relevance_score,
            "relevance_reasoning": self.relevance_reasoning,
            "source": self.source
        }


class ImprovedCVESearcher:
    """
    Improved LLM-powered CVE/CWE search system with advanced validation
    """
    
    def __init__(self, tavily_api_key: str):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        
        # Rate limiting
        self.nist_last_request = 0
        self.nist_min_interval = 6
        
        # Caching
        self.cve_cache = {}
        self.cwe_cache = {}
        
    def search_vulnerability(
        self,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]] = None,
        max_cves: int = 10
    ) -> Dict[str, Any]:
        """
        Main search function with advanced validation
        """
        print(f"\n{'='*80}")
        print(f"🔍 IMPROVED INTELLIGENT CVE SEARCH")
        print(f"{'='*80}")
        print(f"Query: {vulnerability_description}")
        if context:
            print(f"Context: {json.dumps(context, indent=2)}")
        print(f"{'='*80}\n")
        
        results = {
            "query": vulnerability_description,
            "context": context or {},
            "timestamp": datetime.now().isoformat(),
            "cves": [],
            "cwes": [],
            "analysis": {},
            "search_strategy": []
        }
        
        # Step 1: LLM analyzes vulnerability
        print("📊 Step 1: Analyzing vulnerability with LLM...")
        analysis = self._analyze_vulnerability_with_llm(vulnerability_description, context)
        results["analysis"] = analysis
        results["cwes"] = analysis.get("cwes", [])
        
        # Step 2: Generate search queries
        print("\n🎯 Step 2: Generating search queries...")
        search_queries = self._generate_search_queries(vulnerability_description, analysis, context)
        results["search_strategy"] = search_queries
        
        # Step 3: Search for CVEs
        print("\n🔎 Step 3: Searching for CVEs...")
        all_cves = []
        
        # NIST API search
        print("  → Searching NIST NVD API...")
        for query in search_queries[:3]:
            cves = self._search_nist_api(query["query"])
            all_cves.extend(cves)
            time.sleep(0.5)
        
        # Web search
        print("  → Searching web for additional CVEs...")
        web_cves = self._search_web_for_cves(vulnerability_description, context)
        all_cves.extend(web_cves)
        
        # CWE-based search
        if results["cwes"]:
            print(f"  → Searching by CWE IDs...")
            for cwe_info in results["cwes"][:2]:
                cwe_cves = self._search_by_cwe(cwe_info["cwe_id"])
                all_cves.extend(cwe_cves)
                time.sleep(0.5)
        
        # Deduplicate
        unique_cves = self._deduplicate_cves(all_cves)
        print(f"\n📋 Found {len(unique_cves)} unique CVEs")
        
        # Step 4: ADVANCED VALIDATION
        print("\n✅ Step 4: Running advanced CVE validation...")
        validated_cves = self._validate_cves_advanced(
            unique_cves,
            vulnerability_description,
            analysis,
            context
        )
        
        # Step 5: Enrich with CWE details
        print("\n🔬 Step 5: Enriching CVEs with CWE information...")
        enriched_cves = self._enrich_cves_with_cwes(validated_cves)
        
        # Sort and limit
        final_cves = sorted(
            enriched_cves,
            key=lambda x: (x.relevance_score, x.cvss_score),
            reverse=True
        )[:max_cves]
        
        results["cves"] = [cve.to_dict() for cve in final_cves]
        
        print(f"\n{'='*80}")
        print(f"✨ SEARCH COMPLETE")
        print(f"{'='*80}")
        print(f"Total CVEs found: {len(final_cves)}")
        print(f"Total CWEs identified: {len(results['cwes'])}")
        print(f"Average Relevance Score: {sum(c.relevance_score for c in final_cves) / len(final_cves):.2f}" if final_cves else "N/A")
        print(f"{'='*80}\n")
        
        return results
    
    def _analyze_vulnerability_with_llm(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Use LLM to analyze vulnerability"""
        
        context_str = ""
        if context:
            context_str = f"\n\nContext:\n{json.dumps(context, indent=2)}"
        
        prompt = f"""You are a cybersecurity expert analyzing a vulnerability.

Vulnerability Description: {vulnerability}{context_str}

Provide a comprehensive analysis in JSON format:
{{
    "vulnerability_type": "specific type (e.g., 'SQL Injection', 'Certificate Validation', 'Buffer Overflow')",
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

Common CWEs:
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting
- CWE-295: Improper Certificate Validation  
- CWE-327: Use of Broken Cryptographic Algorithm
- CWE-119: Buffer Overflow
- CWE-287: Improper Authentication
- CWE-200: Information Exposure
- CWE-352: CSRF

Return ONLY valid JSON."""

        try:
            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.2,
                max_output_tokens=1200  # Increased token limit
            )
            
            # Robust JSON parsing
            analysis = self._parse_json_robust(response)
            
            if analysis:
                print(f"  ✓ Identified vulnerability type: {analysis.get('vulnerability_type', 'Unknown')}")
                print(f"  ✓ Identified {len(analysis.get('cwes', []))} relevant CWEs")
                return analysis
            else:
                print("  ⚠ Could not parse LLM response as JSON")
                return self._fallback_analysis(vulnerability)
        
        except Exception as e:
            print(f"  ⚠ LLM analysis failed: {e}")
            return self._fallback_analysis(vulnerability)
    
    def _parse_json_robust(self, response: str) -> Optional[Dict[str, Any]]:
        """Robust JSON parsing that handles partial/truncated responses"""
        
        from json_completion import complete_analysis_json
        
        # Clean response
        cleaned = response.strip()
        
        # Remove markdown code blocks
        cleaned = re.sub(r'^```json\s*', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'\s*```$', '', cleaned)
        cleaned = re.sub(r'^```\s*', '', cleaned)
        
        # Try to complete the truncated JSON
        result = complete_analysis_json(cleaned)
        
        if result and isinstance(result, dict):
            return result
        
        return None
    
    def _fallback_analysis(self, vulnerability: str) -> Dict[str, Any]:
        """Fallback analysis"""
        keywords = re.findall(r'\b\w{4,}\b', vulnerability.lower())
        return {
            "vulnerability_type": "Unknown",
            "severity_estimate": "Medium",
            "affected_components": [],
            "cwes": [],
            "key_terms": list(set(keywords))[:10],
            "search_focus": "General vulnerability search"
        }
    
    def _generate_search_queries(
        self,
        vulnerability: str,
        analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, str]]:
        """Generate intelligent search queries"""
        
        context_str = ""
        if context:
            context_str = f"\nContext: {json.dumps(context)}"
        
        prompt = f"""Generate 5 optimal search queries for finding CVEs.

Vulnerability: {vulnerability}
Analysis: {json.dumps(analysis)}{context_str}

Create queries that:
1. Start specific, then broaden
2. Use technical CVE terminology
3. Include platform/software when relevant
4. Are 3-8 words each
5. Focus on vulnerability TYPE

Return ONLY JSON array:
[
    {{"query": "text", "rationale": "why"}},
    ...
]"""

        try:
            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.3,
                max_output_tokens=500
            )
            
            # Clean response and extract JSON array
            cleaned_response = response.strip()
            
            # Try multiple JSON extraction methods for arrays
            json_patterns = [
                r'\[[^\[\]]*(?:\{[^{}]*\}[^\[\]]*)*\]',  # Array with objects
                r'\[.*?\](?=\s*$)',  # Array at end
                r'\[.*\]',  # Simple array match
            ]
            
            queries = None
            for pattern in json_patterns:
                json_match = re.search(pattern, cleaned_response, re.DOTALL)
                if json_match:
                    try:
                        json_str = json_match.group().strip()
                        # Fix common JSON issues
                        json_str = re.sub(r',\s*}', '}', json_str)  # Remove trailing commas in objects
                        json_str = re.sub(r',\s*]', ']', json_str)   # Remove trailing commas in arrays
                        
                        queries = json.loads(json_str)
                        break
                    except json.JSONDecodeError:
                        continue
            
            if queries and isinstance(queries, list):
                for i, q in enumerate(queries, 1):
                    print(f"    {i}. {q.get('query', 'Unknown query')}")
                return queries
            else:
                print(f"  ⚠ Could not parse query generation response")
        except Exception as e:
            print(f"  ⚠ Query generation failed: {e}")
        
        # Fallback: create queries from analysis
        key_terms = analysis.get("key_terms", [])
        vuln_type = analysis.get("vulnerability_type", "")
        
        fallback_queries = []
        
        # Query 1: Vulnerability type + key terms
        if vuln_type and key_terms:
            query1 = f"{vuln_type} {' '.join(key_terms[:2])}"
            fallback_queries.append({"query": query1, "rationale": "Vulnerability type + key terms"})
        
        # Query 2: Just key terms
        if key_terms:
            query2 = " ".join(key_terms[:4])
            fallback_queries.append({"query": query2, "rationale": "Main keywords"})
        
        # Query 3: Vulnerability type only
        if vuln_type:
            fallback_queries.append({"query": vuln_type, "rationale": "Vulnerability type"})
        
        # Query 4: Original description (truncated)
        query4 = vulnerability[:50].strip()
        fallback_queries.append({"query": query4, "rationale": "Original description"})
        
        # Query 5: Context-based if available
        if context and context.get("Operating System"):
            os_name = context["Operating System"]
            if key_terms:
                query5 = f"{os_name} {key_terms[0]}"
                fallback_queries.append({"query": query5, "rationale": "OS + main keyword"})
        
        # Ensure we have at least 3 queries
        if len(fallback_queries) < 3:
            fallback_queries.extend([
                {"query": "certificate validation", "rationale": "Generic cert query"},
                {"query": "ssl tls", "rationale": "Generic SSL/TLS query"},
                {"query": "signature verification", "rationale": "Generic signature query"}
            ])
        
        print(f"  ⚠ Using fallback queries:")
        for i, q in enumerate(fallback_queries[:5], 1):
            print(f"    {i}. {q['query']}")
        
        return fallback_queries[:5]
    
    def _search_nist_api(self, query: str) -> List[CVEInfo]:
        """Search NIST NVD API"""
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.nist_last_request
        if time_since_last < self.nist_min_interval:
            time.sleep(self.nist_min_interval - time_since_last)
        
        # Check cache
        cache_key = f"nist:{query}"
        if cache_key in self.cve_cache:
            print(f"    📦 Using cached results for: {query}")
            return self.cve_cache[cache_key]
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": query,
                "resultsPerPage": 20
            }
            headers = {"User-Agent": "ImprovedCVESearcher/2.0"}
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            self.nist_last_request = time.time()
            
            if response.status_code != 200:
                print(f"    ⚠ NIST API returned status {response.status_code}")
                return []
            
            data = response.json()
            cves = []
            
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_info = self._parse_nist_cve(cve_data)
                if cve_info:
                    cves.append(cve_info)
            
            print(f"    ✓ Found {len(cves)} CVEs from NIST")
            self.cve_cache[cache_key] = cves
            return cves
            
        except Exception as e:
            print(f"    ❌ NIST search failed: {e}")
            return []
    
    def _parse_nist_cve(self, cve_data: Dict[str, Any]) -> Optional[CVEInfo]:
        """Parse CVE from NIST response"""
        try:
            cve_id = cve_data.get("id", "")
            
            # Description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # CVSS metrics
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            vector = ""
            
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", cvss_data.get("severity", "UNKNOWN"))
                    vector = cvss_data.get("vectorString", "")
                    break
            
            # CWE IDs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_id = desc.get("value", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_ids.append(cwe_id)
            
            # References
            references = [ref.get("url", "") for ref in cve_data.get("references", [])[:10] if ref.get("url")]
            
            # Affected products
            affected_products = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            criteria = cpe_match.get("criteria", "")
                            if criteria:
                                parts = criteria.split(":")
                                if len(parts) >= 5:
                                    vendor_product = f"{parts[3]} {parts[4]}"
                                    if vendor_product not in affected_products:
                                        affected_products.append(vendor_product)
            
            return CVEInfo(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=vector,
                published_date=cve_data.get("published", ""),
                modified_date=cve_data.get("lastModified", ""),
                cwe_ids=cwe_ids,
                affected_products=affected_products[:10],
                references=references,
                source="NIST NVD"
            )
            
        except Exception as e:
            print(f"    ⚠ Failed to parse CVE: {e}")
            return None
    
    def _search_web_for_cves(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CVEInfo]:
        """Use Tavily to search for CVEs"""
        try:
            search_query = f"CVE {vulnerability}"
            if context and context.get("Operating System"):
                search_query += f" {context['Operating System']}"
            
            results = self.tavily.search(
                query=search_query,
                search_depth="advanced",
                max_results=5,
                include_domains=["nvd.nist.gov", "cve.org", "mitre.org"]
            )
            
            cve_ids = set()
            for result in results.get("results", []):
                content = result.get("content", "") + result.get("title", "")
                found_cves = re.findall(r'CVE-\d{4}-\d{4,}', content)
                cve_ids.update(found_cves)
            
            print(f"    ✓ Found {len(cve_ids)} CVE IDs from web search")
            
            cves = []
            for cve_id in list(cve_ids)[:5]:
                cve_info = self._get_cve_by_id(cve_id)
                if cve_info:
                    cves.append(cve_info)
                time.sleep(0.5)
            
            return cves
            
        except Exception as e:
            print(f"    ⚠ Web search failed: {e}")
            return []
    
    def _get_cve_by_id(self, cve_id: str) -> Optional[CVEInfo]:
        """Get CVE by ID"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        current_time = time.time()
        time_since_last = current_time - self.nist_last_request
        if time_since_last < self.nist_min_interval:
            time.sleep(self.nist_min_interval - time_since_last)
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cveId": cve_id}
            headers = {"User-Agent": "ImprovedCVESearcher/2.0"}
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            self.nist_last_request = time.time()
            
            if response.status_code == 200:
                data = response.json()
                if data.get("vulnerabilities"):
                    cve_data = data["vulnerabilities"][0].get("cve", {})
                    cve_info = self._parse_nist_cve(cve_data)
                    if cve_info:
                        self.cve_cache[cve_id] = cve_info
                    return cve_info
        except Exception as e:
            print(f"    ⚠ Failed to fetch {cve_id}: {e}")
        
        return None
    
    def _search_by_cwe(self, cwe_id: str) -> List[CVEInfo]:
        """Search by CWE ID"""
        return self._search_nist_api(cwe_id)
    
    def _deduplicate_cves(self, cves: List[CVEInfo]) -> List[CVEInfo]:
        """Remove duplicates"""
        seen = set()
        unique = []
        for cve in cves:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique.append(cve)
        return unique
    
    def _validate_cves_advanced(
        self,
        cves: List[CVEInfo],
        vulnerability: str,
        analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[CVEInfo]:
        """Use fast threaded validation system"""
        
        if not cves:
            return []
        
        try:
            # Import threaded validator for speed
            from threaded_cve_validator import validate_cves_threaded
            
            validated_cves = validate_cves_threaded(
                cves=cves,
                vulnerability_description=vulnerability,
                context=context,
                analysis=analysis,
                tavily_api_key=self.tavily.api_key,
                max_workers=8  # Use 8 threads for speed
            )
            
            return validated_cves
            
        except Exception as e:
            print(f"  ❌ Threaded validation failed: {e}")
            print(f"  ⚠ Using all CVEs with default scores...")
            
            # Fallback: assign default scores
            for cve in cves:
                cve.relevance_score = 0.5
                cve.relevance_reasoning = f"Validation unavailable due to error: {str(e)}"
            
            return cves
    
    def _enrich_cves_with_cwes(self, cves: List[CVEInfo]) -> List[CVEInfo]:
        """Enrich CVEs with CWE details"""
        for cve in cves:
            for cwe_id in cve.cwe_ids[:3]:
                cwe_info = self._get_cwe_details(cwe_id)
                if cwe_info:
                    cve.cwe_details.append(cwe_info)
        return cves
    
    def _get_cwe_details(self, cwe_id: str) -> Optional[CWEInfo]:
        """Get CWE details"""
        if cwe_id in self.cwe_cache:
            return self.cwe_cache[cwe_id]
        
        try:
            results = self.tavily.search(
                query=f"{cwe_id} MITRE CWE",
                search_depth="basic",
                max_results=2,
                include_domains=["cwe.mitre.org"]
            )
            
            name = cwe_id
            description = ""
            
            for result in results.get("results", []):
                content = result.get("content", "")
                title = result.get("title", "")
                
                if cwe_id in title:
                    name = title.replace(cwe_id, "").replace("-", "").strip()
                
                if content:
                    description = content[:500]
                    break
            
            if not description:
                description = self._get_cwe_description_with_llm(cwe_id)
            
            cwe_info = CWEInfo(cwe_id=cwe_id, name=name, description=description)
            self.cwe_cache[cwe_id] = cwe_info
            return cwe_info
            
        except Exception as e:
            print(f"    ⚠ Failed to fetch CWE {cwe_id}: {e}")
            return CWEInfo(cwe_id=cwe_id, name=cwe_id, description=f"Common Weakness: {cwe_id}")
    
    def _get_cwe_description_with_llm(self, cwe_id: str) -> str:
        """Get CWE description from LLM"""
        try:
            prompt = f"""Provide a brief technical description (2-3 sentences) of {cwe_id}.
Focus on what the weakness is and why it's a security concern.
Do not include the CWE ID or name, just the explanation."""

            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.1,
                max_output_tokens=200
            )
            
            return response.strip()
        except Exception:
            return f"Common Weakness Enumeration: {cwe_id}"


def format_results_for_display(results: Dict[str, Any]) -> str:
    """Format results for display"""
    output = []
    output.append("=" * 80)
    output.append("CVE & CWE SEARCH RESULTS")
    output.append("=" * 80)
    output.append(f"\nQuery: {results['query']}")
    output.append(f"Timestamp: {results['timestamp']}")
    
    # Analysis
    analysis = results.get("analysis", {})
    if analysis:
        output.append(f"\n{'─' * 80}")
        output.append("VULNERABILITY ANALYSIS")
        output.append(f"{'─' * 80}")
        output.append(f"Type: {analysis.get('vulnerability_type', 'Unknown')}")
        output.append(f"Severity: {analysis.get('severity_estimate', 'Unknown')}")
    
    # CWEs
    cwes = results.get("cwes", [])
    if cwes:
        output.append(f"\n{'─' * 80}")
        output.append(f"IDENTIFIED CWEs ({len(cwes)})")
        output.append(f"{'─' * 80}")
        for cwe in cwes:
            output.append(f"\n{cwe['cwe_id']}: {cwe.get('relevance', '')}")
    
    # CVEs
    cves = results.get("cves", [])
    if cves:
        output.append(f"\n{'─' * 80}")
        output.append(f"RELEVANT CVEs ({len(cves)})")
        output.append(f"{'─' * 80}")
        
        for i, cve in enumerate(cves, 1):
            output.append(f"\n[{i}] {cve['cve_id']}")
            output.append(f"Severity: {cve['severity']} (CVSS: {cve['cvss_score']})")
            output.append(f"Relevance: {cve['relevance_score']:.2f}")
            output.append(f"Reason: {cve['relevance_reasoning']}")
            output.append(f"Description: {cve['description'][:200]}...")
            if cve['cwe_ids']:
                output.append(f"CWEs: {', '.join(cve['cwe_ids'][:5])}")
            output.append(f"Published: {cve['published_date'][:10]}")
    else:
        output.append("\n❌ No relevant CVEs found")
    
    output.append(f"\n{'=' * 80}")
    return "\n".join(output)