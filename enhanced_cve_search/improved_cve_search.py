import re
import json
import requests
import time
from datetime import datetime
from tavily import TavilyClient
from typing import List, Dict, Any, Optional
from enhanced_cve_search.cve_structures import (
    EnhancedCVEInfo,
    EnhancedCWEInfo,
    StructuredSearchResults,
    EnhancedCVEParser,
    EnhancedCWEFetcher
)
from enhanced_cve_search.threaded_cve_validator import validate_cves_threaded



class EnhancedCVESearchSystem:
    """
    Enhanced CVE search system with comprehensive data extraction
    """
    
    def __init__(self, tavily_api_key: str):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        self.cve_parser = EnhancedCVEParser()
        self.cwe_fetcher = EnhancedCWEFetcher(self.tavily)
        
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
    ) -> StructuredSearchResults:
        """
        Main search function returning structured results
        """
        print(f"\n{'='*80}")
        print(f"🔍 ENHANCED CVE/CWE SEARCH SYSTEM")
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
        
        # Step 1: LLM analyzes vulnerability
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
        
        # Step 2: Generate search queries
        print("\n🎯 Step 2: Generating search queries...")
        search_queries = self._generate_search_queries(vulnerability_description, analysis, context)
        results.search_strategy = search_queries
        
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
        if results.cwes:
            print(f"  → Searching by CWE IDs...")
            for cwe in results.cwes[:2]:
                cwe_cves = self._search_by_cwe(cwe.cwe_id)
                all_cves.extend(cwe_cves)
                time.sleep(0.5)
        
        # Deduplicate
        unique_cves = self._deduplicate_cves(all_cves)
        print(f"\n📋 Found {len(unique_cves)} unique CVEs")
        
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
        """Use LLM to analyze vulnerability"""
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

        try:
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
                print("  ⚠ Using fallback analysis")
                return self._fallback_analysis(vulnerability)
        
        except Exception as e:
            print(f"  ⚠ Analysis failed: {e}")
            return self._fallback_analysis(vulnerability)
    
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
    
    def _fallback_analysis(self, vulnerability: str) -> Dict[str, Any]:
        """Fallback analysis when LLM fails"""
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
        """Generate search queries"""
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

        try:
            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.3,
                max_output_tokens=500
            )
            
            cleaned = response.strip()
            json_match = re.search(r'\[[^\[\]]*(?:\{[^{}]*\}[^\[\]]*)*\]', cleaned, re.DOTALL)
            
            if json_match:
                queries = json.loads(json_match.group().strip())
                if isinstance(queries, list):
                    for i, q in enumerate(queries, 1):
                        print(f"    {i}. {q.get('query', '')}")
                    return queries
        except Exception as e:
            print(f"  ⚠ Query generation failed: {e}")
        
        # Fallback queries
        return self._generate_fallback_queries(vulnerability, analysis, context)
    
    def _generate_fallback_queries(
        self,
        vulnerability: str,
        analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Generate fallback queries"""
        key_terms = analysis.get("key_terms", [])
        vuln_type = analysis.get("vulnerability_type", "")
        
        queries = []
        
        if vuln_type and key_terms:
            queries.append({
                "query": f"{vuln_type} {' '.join(key_terms[:2])}",
                "rationale": "Type + key terms"
            })
        
        if key_terms:
            queries.append({
                "query": " ".join(key_terms[:4]),
                "rationale": "Main keywords"
            })
        
        if vuln_type:
            queries.append({
                "query": vuln_type,
                "rationale": "Vulnerability type"
            })
        
        queries.append({
            "query": vulnerability[:50].strip(),
            "rationale": "Original description"
        })
        
        if context and context.get("Operating System"):
            os_name = context["Operating System"]
            if key_terms:
                queries.append({
                    "query": f"{os_name} {key_terms[0]}",
                    "rationale": "OS + keyword"
                })
        
        print(f"  ⚠ Using fallback queries:")
        for i, q in enumerate(queries[:5], 1):
            print(f"    {i}. {q['query']}")
        
        return queries[:5]
    
    def _search_nist_api(self, query: str) -> List[EnhancedCVEInfo]:
        """Search NIST NVD API"""
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
            
        except Exception as e:
            print(f"    ❌ NIST search failed: {e}")
            return []
    
    def _search_web_for_cves(
        self,
        vulnerability: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[EnhancedCVEInfo]:
        """Search web for CVEs"""
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
            
            print(f"    ✓ Found {len(cve_ids)} CVE IDs from web")
            
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
    
    def _get_cve_by_id(self, cve_id: str) -> Optional[EnhancedCVEInfo]:
        """Get CVE by ID"""
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
            print(f"    ⚠ Failed to fetch {cve_id}: {e}")
        
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
            print(f"  ❌ Validation failed: {e}")
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