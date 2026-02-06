import re
import json
from threading import Lock
from datetime import datetime
from tavily import TavilyClient
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from config.api_key_manager import generate_content_with_fallback


@dataclass
class ValidationResult:
    """Result of CVE validation"""
    cve_id: str
    is_relevant: bool
    relevance_score: float  # 0.0 to 1.0
    reasoning: str
    validation_method: str
    context_match_score: float
    vulnerability_type_match: bool
    platform_match: bool
    recency_score: float
    confidence: float


class ThreadedCVEValidator:
    """
    Fast threaded CVE validation system with robust fallback mechanisms
    """
    
    def __init__(self, tavily_api_key: str, max_workers: int = 8):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        self.max_workers = max_workers
        self.print_lock = Lock()
        
        # Comprehensive vulnerability keyword mappings
        self.vulnerability_patterns = {
            "ssl/tls": ["ssl", "tls", "certificate", "crypto", "openssl", "x.509", "handshake"],
            "authentication": ["authentication", "auth", "login", "credential", "password", "oauth", "saml"],
            "injection": ["injection", "sql", "xss", "cross-site", "ldap", "command injection"],
            "overflow": ["overflow", "buffer", "heap", "stack", "memory corruption"],
            "rce": ["remote code", "execute", "rce", "arbitrary code", "code execution"],
            "dos": ["denial of service", "dos", "ddos", "crash", "resource exhaustion"],
            "privilege": ["privilege", "escalation", "elevation", "root", "admin"],
            "path_traversal": ["path traversal", "directory traversal", "file inclusion"],
            "deserialization": ["deserialization", "unserialize", "pickle"],
            "xxe": ["xxe", "xml external entity", "xml injection"],
            "csrf": ["csrf", "cross-site request forgery"],
            "information_disclosure": ["information disclosure", "leak", "exposure", "sensitive data"],
            "race_condition": ["race condition", "time-of-check", "toctou"],
            "bypass": ["bypass", "circumvent", "evade", "filter bypass"]
        }
        
        # Platform/product mappings
        self.platform_patterns = {
            "windows": ["windows", "microsoft", "win32", "win64", "ms", "iis"],
            "linux": ["linux", "ubuntu", "debian", "rhel", "centos", "fedora", "suse"],
            "unix": ["unix", "solaris", "aix", "bsd", "freebsd"],
            "web": ["apache", "nginx", "tomcat", "iis", "http", "web server"],
            "database": ["mysql", "postgresql", "mssql", "oracle", "mongodb", "database"],
            "application": ["wordpress", "drupal", "joomla", "php", "java", "python", "node"],
            "network": ["router", "switch", "firewall", "cisco", "juniper"],
            "container": ["docker", "kubernetes", "container", "k8s"],
            "cloud": ["aws", "azure", "gcp", "cloud", "s3"]
        }
    
    def validate_cve_batch(
        self,
        cves: List[Any],
        vulnerability_description: str,
        context: Optional[Dict[str, Any]] = None,
        analysis: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """
        Validate CVEs using threading for speed with robust fallback
        """
        with self.print_lock:
            print(f"\n{'='*80}")
            print(f"🔍 ADVANCED CVE VALIDATION (With Robust Fallback)")
            print(f"{'='*80}")
            print(f"Validating {len(cves)} CVEs")
            print(f"Query: {vulnerability_description}")
            if context:
                print(f"Context: {json.dumps(context, indent=2)}")
            print(f"{'='*80}\n")
        
        validated_cves = []
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all validation tasks
            future_to_cve = {
                executor.submit(
                    self._validate_single_cve,
                    cve, vulnerability_description, context, analysis, i, len(cves)
                ): cve for i, cve in enumerate(cves, 1)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_cve):
                cve = future_to_cve[future]
                try:
                    validation_result = future.result()
                    
                    # Update CVE with validation results
                    cve.relevance_score = validation_result.relevance_score
                    cve.relevance_reasoning = validation_result.reasoning
                    
                    # Only keep CVEs that pass validation
                    if validation_result.is_relevant:
                        validated_cves.append(cve)
                        
                except Exception as e:
                    with self.print_lock:
                        print(f"  ❌ Error validating {cve.cve_id}: {e}")
        
        with self.print_lock:
            print(f"\n{'='*80}")
            print(f"✅ VALIDATION COMPLETE")
            print(f"{'='*80}")
            print(f"Validated CVEs: {len(validated_cves)}/{len(cves)}")
            print(f"Rejection Rate: {((len(cves) - len(validated_cves)) / len(cves) * 100):.1f}%")
            print(f"{'='*80}\n")
        
        return validated_cves
    
    def _validate_single_cve(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]],
        index: int,
        total: int
    ) -> ValidationResult:
        """
        Validate a single CVE with multi-layered fallback (thread-safe)
        """
        with self.print_lock:
            print(f"\n[{index}/{total}] Validating {cve.cve_id}...")
        
        # Stage 1: Context Matching (fast, no API)
        context_score = self._validate_context_match_advanced(cve, context)
        
        # Stage 2: Vulnerability Type Matching (fast, no API)
        vuln_type_match, vuln_match_score = self._validate_vulnerability_type_advanced(
            cve, vulnerability_description, analysis
        )
        
        # Stage 3: Recency Scoring (fast, no API)
        recency_score = self._calculate_recency_score(cve)
        
        # Stage 4: Severity-based scoring (fast, no API)
        severity_score = self._calculate_severity_score(cve)
        
        # Stage 5: Keyword similarity (fast, no API)
        keyword_score = self._calculate_keyword_similarity(
            cve, vulnerability_description, context
        )
        
        # Early exit for obviously irrelevant CVEs
        if context_score < 0.2 and not vuln_type_match and keyword_score < 0.3:
            with self.print_lock:
                print(f"  📍 Context Match: {context_score:.2f}")
                print(f"  🎯 Vulnerability Type Match: {vuln_type_match} ({vuln_match_score:.2f})")
                print(f"  🔑 Keyword Similarity: {keyword_score:.2f}")
                print(f"  📅 Recency Score: {recency_score:.2f}")
                print(f"  ❌ NOT RELEVANT - Score: 0.25")
                print(f"     Reasoning: Poor context match, wrong vulnerability type, and low keyword similarity")
            
            return ValidationResult(
                cve_id=cve.cve_id,
                is_relevant=False,
                relevance_score=0.25,
                reasoning="Poor context match, wrong vulnerability type, and low keyword similarity",
                validation_method="fast-reject-rule-based",
                context_match_score=context_score,
                vulnerability_type_match=vuln_type_match,
                platform_match=False,
                recency_score=recency_score,
                confidence=0.85
            )
        
        # Stage 6: Try LLM validation (may fail)
        llm_validation = self._validate_with_llm_safe(
            cve, vulnerability_description, context, analysis
        )
        
        # Determine which scoring method to use
        if llm_validation['success']:
            # LLM worked - use it with higher weight
            final_score = self._calculate_final_score_with_llm(
                context_score=context_score,
                vuln_match_score=vuln_match_score,
                llm_score=llm_validation['score'],
                keyword_score=keyword_score,
                severity_score=severity_score,
                recency_score=recency_score
            )
            validation_method = "llm-enhanced"
            confidence = llm_validation.get('confidence', 0.7)
        else:
            # LLM failed - use rule-based fallback
            final_score = self._calculate_final_score_rule_based(
                context_score=context_score,
                vuln_match_score=vuln_match_score,
                keyword_score=keyword_score,
                severity_score=severity_score,
                recency_score=recency_score
            )
            validation_method = "rule-based-fallback"
            confidence = 0.65  # Lower confidence without LLM
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            cve=cve,
            context_score=context_score,
            vuln_type_match=vuln_type_match,
            vuln_match_score=vuln_match_score,
            keyword_score=keyword_score,
            llm_validation=llm_validation,
            final_score=final_score,
            validation_method=validation_method
        )
        
        # Determine if relevant (adjustable threshold)
        threshold = 0.45 if validation_method == "llm-enhanced" else 0.50
        is_relevant = final_score >= threshold
        
        with self.print_lock:
            print(f"  📍 Context Match: {context_score:.2f}")
            print(f"  🎯 Vulnerability Type Match: {vuln_type_match} ({vuln_match_score:.2f})")
            print(f"  🔑 Keyword Similarity: {keyword_score:.2f}")
            print(f"  ⚠️  Severity Score: {severity_score:.2f}")
            
            if llm_validation['success']:
                print(f"  🤖 LLM Validation: {llm_validation['score']:.2f} ✓")
            else:
                print(f"  🤖 LLM Validation: FAILED - Using rule-based fallback")
            
            print(f"  📅 Recency Score: {recency_score:.2f}")
            print(f"  🔧 Method: {validation_method}")
            
            if is_relevant:
                print(f"  ✅ RELEVANT - Score: {final_score:.2f} (confidence: {confidence:.2f})")
                print(f"     Reasoning: {reasoning[:100]}...")
            else:
                print(f"  ❌ NOT RELEVANT - Score: {final_score:.2f}")
                print(f"     Reasoning: {reasoning[:100]}...")
        
        return ValidationResult(
            cve_id=cve.cve_id,
            is_relevant=is_relevant,
            relevance_score=final_score,
            reasoning=reasoning,
            validation_method=validation_method,
            context_match_score=context_score,
            vulnerability_type_match=vuln_type_match,
            platform_match=(context_score > 0.5),
            recency_score=recency_score,
            confidence=confidence
        )
    
    def _validate_context_match_advanced(
        self, 
        cve: Any, 
        context: Optional[Dict[str, Any]]
    ) -> float:
        """Advanced context matching with detailed platform detection"""
        if not context:
            return 0.5
        
        score = 0.0
        affected_products = " ".join(cve.affected_products).lower()
        cve_description = cve.description.lower()
        combined_text = f"{affected_products} {cve_description}"
        
        # Extract context requirements
        os_requirement = context.get("Operating System", "").lower()
        asset_type = context.get("Asset Type", "").lower()
        
        # OS/Platform matching
        if os_requirement:
            for platform, keywords in self.platform_patterns.items():
                if any(req in os_requirement for req in keywords):
                    # Check if CVE matches this platform
                    if any(kw in combined_text for kw in keywords):
                        score += 0.6
                    else:
                        # Penalize if CVE is for a different platform
                        other_platforms = [k for k in self.platform_patterns.keys() if k != platform]
                        for other_platform in other_platforms:
                            if any(kw in combined_text for kw in self.platform_patterns[other_platform]):
                                score -= 0.4
                                break
        
        # Asset type matching
        if asset_type:
            for asset_category, keywords in self.platform_patterns.items():
                if any(asset in asset_type for asset in keywords):
                    if any(kw in combined_text for kw in keywords):
                        score += 0.3
        
        return max(0.0, min(1.0, score))
    
    def _validate_vulnerability_type_advanced(
        self,
        cve: Any,
        vulnerability_description: str,
        analysis: Optional[Dict[str, Any]]
    ) -> tuple[bool, float]:
        """
        Advanced vulnerability type matching with scoring
        Returns: (match_found, match_score)
        """
        vuln_desc = vulnerability_description.lower()
        cve_desc = cve.description.lower()
        
        best_score = 0.0
        match_found = False
        
        # Check each vulnerability pattern
        for vuln_type, keywords in self.vulnerability_patterns.items():
            # Check if query mentions this vulnerability type
            query_matches = sum(1 for k in keywords if k in vuln_desc)
            
            if query_matches > 0:
                # Check if CVE description mentions this vulnerability type
                cve_matches = sum(1 for k in keywords if k in cve_desc)
                
                if cve_matches > 0:
                    # Calculate match score based on keyword overlap
                    match_score = min(1.0, (query_matches + cve_matches) / (len(keywords) * 0.5))
                    best_score = max(best_score, match_score)
                    match_found = True
        
        # If no specific pattern matched, do general keyword matching
        if not match_found:
            query_words = set(vuln_desc.split())
            cve_words = set(cve_desc.split())
            common_words = query_words & cve_words
            
            if len(common_words) > 3:
                match_found = True
                best_score = min(0.7, len(common_words) / 10)
        
        return match_found, best_score
    
    def _calculate_keyword_similarity(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]]
    ) -> float:
        """
        Calculate keyword-based similarity between query and CVE
        """
        # Extract keywords from query
        query_text = vulnerability_description.lower()
        if context:
            query_text += " " + " ".join(str(v).lower() for v in context.values())
        
        # Extract keywords from CVE
        cve_text = f"{cve.description} {' '.join(cve.affected_products)}".lower()
        
        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'and', 'or', 'but'}
        
        query_words = set(w for w in re.findall(r'\w+', query_text) if len(w) > 2 and w not in stop_words)
        cve_words = set(w for w in re.findall(r'\w+', cve_text) if len(w) > 2 and w not in stop_words)
        
        if not query_words:
            return 0.5
        
        # Calculate Jaccard similarity
        intersection = len(query_words & cve_words)
        union = len(query_words | cve_words)
        
        if union == 0:
            return 0.0
        
        jaccard_score = intersection / union
        
        # Boost score for exact product name matches
        for product in cve.affected_products:
            if product.lower() in query_text:
                jaccard_score += 0.2
                break
        
        return min(1.0, jaccard_score)
    
    def _calculate_severity_score(self, cve: Any) -> float:
        """Calculate score based on CVE severity"""
        cvss_score = getattr(cve, 'cvss_score', None)
        
        if cvss_score is None:
            return 0.5
        
        try:
            score = float(cvss_score)
            # Normalize CVSS score (0-10) to 0-1
            # Higher severity = slightly higher relevance
            if score >= 9.0:
                return 0.9
            elif score >= 7.0:
                return 0.7
            elif score >= 4.0:
                return 0.5
            else:
                return 0.3
        except:
            return 0.5
    
    def _validate_with_llm_safe(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        LLM validation with safe error handling
        Returns success flag to enable fallback
        """
        try:
            context_str = ""
            if context:
                context_str = f"\nContext: {context.get('Operating System', '')} {context.get('Asset Type', '')}"
            
            prompt = f"""Evaluate CVE relevance (respond with JSON only):

Query: {vulnerability_description}{context_str}

CVE: {cve.cve_id}
Description: {cve.description[:300]}...
Products: {', '.join(cve.affected_products[:3])}

JSON response:
{{
    "score": 0.0-1.0,
    "reasoning": "brief explanation"
}}

Score 0.0-0.3: Not relevant, Score 0.4-0.6: Partially relevant, Score 0.7-1.0: Highly relevant"""

            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.1,
                max_output_tokens=200
            )
            
            result = self._parse_json_fast(response)
            if result and "score" in result:
                result['success'] = True
                result['confidence'] = 0.75
                return result
            
            # Parsing failed
            return {
                "success": False,
                "score": 0.5,
                "reasoning": "LLM response parsing failed",
                "confidence": 0.3
            }
        
        except Exception as e:
            # LLM completely failed - signal to use fallback
            return {
                "success": False,
                "score": 0.5,
                "reasoning": f"LLM error: {str(e)[:50]}",
                "confidence": 0.2
            }
    
    def _calculate_final_score_with_llm(
        self,
        context_score: float,
        vuln_match_score: float,
        llm_score: float,
        keyword_score: float,
        severity_score: float,
        recency_score: float
    ) -> float:
        """Calculate final score when LLM is available"""
        score = (
            context_score * 0.25 +
            vuln_match_score * 0.20 +
            llm_score * 0.30 +
            keyword_score * 0.15 +
            severity_score * 0.05 +
            recency_score * 0.05
        )
        
        return max(0.0, min(1.0, score))
    
    def _calculate_final_score_rule_based(
        self,
        context_score: float,
        vuln_match_score: float,
        keyword_score: float,
        severity_score: float,
        recency_score: float
    ) -> float:
        """
        Calculate final score using only rule-based methods (no LLM)
        Redistributes LLM weight to other factors
        """
        score = (
            context_score * 0.30 +      # Increased from 0.25
            vuln_match_score * 0.30 +   # Increased from 0.20
            keyword_score * 0.25 +      # Increased from 0.15
            severity_score * 0.10 +     # Increased from 0.05
            recency_score * 0.05        # Same
        )
        
        return max(0.0, min(1.0, score))
    
    def _parse_json_fast(self, response: str) -> Optional[Dict[str, Any]]:
        """Fast JSON parsing with multiple fallback strategies"""
        # Strategy 1: Direct JSON parsing
        try:
            cleaned = response.strip()
            cleaned = re.sub(r'^```json\s*', '', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s*```$', '', cleaned)
            
            result = json.loads(cleaned)
            if isinstance(result, dict) and "score" in result:
                return result
        except:
            pass
        
        # Strategy 2: Regex extraction
        try:
            score_match = re.search(r'"score":\s*([0-9.]+)', response)
            reasoning_match = re.search(r'"reasoning":\s*"([^"]+)"', response)
            
            if score_match:
                return {
                    "score": float(score_match.group(1)),
                    "reasoning": reasoning_match.group(1) if reasoning_match else "Partial parsing",
                    "confidence": 0.5
                }
        except:
            pass
        
        # Strategy 3: Look for score anywhere in response
        try:
            numbers = re.findall(r'\b([0-9]\.[0-9]+)\b', response)
            if numbers:
                score = float(numbers[0])
                if 0.0 <= score <= 1.0:
                    return {
                        "score": score,
                        "reasoning": "Extracted from response",
                        "confidence": 0.3
                    }
        except:
            pass
        
        return None
    
    def _calculate_recency_score(self, cve: Any) -> float:
        """Calculate recency score with better granularity"""
        if not cve.published_date:
            return 0.3
        
        try:
            pub_date = datetime.fromisoformat(cve.published_date.replace('Z', '+00:00'))
            age_years = (datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date).days / 365.25
            
            if age_years < 0.5:
                return 1.0
            elif age_years < 1:
                return 0.9
            elif age_years < 2:
                return 0.8
            elif age_years < 3:
                return 0.7
            elif age_years < 5:
                return 0.5
            elif age_years < 10:
                return 0.3
            else:
                return 0.2
        except:
            return 0.5
    
    def _generate_reasoning(
        self,
        cve: Any,
        context_score: float,
        vuln_type_match: bool,
        vuln_match_score: float,
        keyword_score: float,
        llm_validation: Dict[str, Any],
        final_score: float,
        validation_method: str
    ) -> str:
        """Generate comprehensive reasoning for the validation decision"""
        reasons = []
        
        # LLM reasoning (if available)
        if llm_validation.get("success") and llm_validation.get("reasoning"):
            reasons.append(f"LLM: {llm_validation['reasoning']}")
        elif not llm_validation.get("success"):
            reasons.append("LLM unavailable - using rule-based analysis")
        
        # Context match reasoning
        if context_score > 0.7:
            reasons.append("Strong platform/context match")
        elif context_score > 0.4:
            reasons.append("Moderate platform/context match")
        elif context_score < 0.3:
            reasons.append("Poor platform/context match")
        
        # Vulnerability type reasoning
        if vuln_type_match:
            if vuln_match_score > 0.7:
                reasons.append("Strong vulnerability type match")
            else:
                reasons.append("Vulnerability type matches")
        else:
            reasons.append("Vulnerability type mismatch")
        
        # Keyword similarity reasoning
        if keyword_score > 0.6:
            reasons.append("High keyword similarity")
        elif keyword_score < 0.3:
            reasons.append("Low keyword similarity")
        
        # Add validation method
        reasons.append(f"Method: {validation_method}")
        
        return " | ".join(reasons)


def validate_cves_threaded(
    cves: List[Any],
    vulnerability_description: str,
    context: Optional[Dict[str, Any]] = None,
    analysis: Optional[Dict[str, Any]] = None,
    tavily_api_key: str = None,
    max_workers: int = 8
) -> List[Any]:
    """
    Fast threaded CVE validation with robust fallback system
    """
    if not tavily_api_key:
        import os
        tavily_api_key = os.getenv("TAVILY_API_KEY")
    
    validator = ThreadedCVEValidator(
        tavily_api_key=tavily_api_key,
        max_workers=max_workers
    )
    
    return validator.validate_cve_batch(
        cves=cves,
        vulnerability_description=vulnerability_description,
        context=context,
        analysis=analysis
    )