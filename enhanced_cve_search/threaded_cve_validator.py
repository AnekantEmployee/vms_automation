import re
import json
import numpy as np
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
    semantic_similarity: float  # NEW: Similarity between descriptions


class SemanticSimilarityMatcher:
    """
    Calculate semantic similarity between vulnerability description and CVE description
    Uses simple but effective text similarity algorithms
    """
    
    def __init__(self):
        self.stop_words = {
            'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
            'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'that', 'the',
            'to', 'was', 'will', 'with', 'can', 'could', 'should', 'would',
            'may', 'might', 'must', 'shall', 'this', 'these', 'those', 'such'
        }
    
    def calculate_similarity(
        self,
        vulnerability_desc: str,
        cve_desc: str,
        vulnerability_context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate semantic similarity between two text descriptions
        Returns: float between 0.0 and 1.0
        """
        # Normalize and tokenize
        vuln_tokens = self._normalize_and_tokenize(vulnerability_desc)
        cve_tokens = self._normalize_and_tokenize(cve_desc)
        
        # Add context tokens if available
        if vulnerability_context:
            context_text = " ".join(str(v) for v in vulnerability_context.values() if v)
            context_tokens = self._normalize_and_tokenize(context_text)
            vuln_tokens.extend(context_tokens)
        
        # Calculate multiple similarity metrics
        jaccard = self._jaccard_similarity(vuln_tokens, cve_tokens)
        overlap = self._overlap_coefficient(vuln_tokens, cve_tokens)
        weighted = self._weighted_similarity(vuln_tokens, cve_tokens, vulnerability_desc, cve_desc)
        ngram = self._ngram_similarity(vulnerability_desc.lower(), cve_desc.lower())
        
        # Combine metrics with weights
        combined_score = (
            jaccard * 0.25 +
            overlap * 0.25 +
            weighted * 0.30 +
            ngram * 0.20
        )
        
        return min(1.0, max(0.0, combined_score))
    
    def _normalize_and_tokenize(self, text: str) -> List[str]:
        """Normalize text and extract meaningful tokens"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep alphanumeric and spaces
        text = re.sub(r'[^a-z0-9\s\-]', ' ', text)
        
        # Tokenize
        tokens = text.split()
        
        # Remove stop words and short tokens
        tokens = [
            t for t in tokens
            if len(t) > 2 and t not in self.stop_words
        ]
        
        return tokens
    
    def _jaccard_similarity(self, tokens1: List[str], tokens2: List[str]) -> float:
        """Calculate Jaccard similarity coefficient"""
        set1 = set(tokens1)
        set2 = set(tokens2)
        
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _overlap_coefficient(self, tokens1: List[str], tokens2: List[str]) -> float:
        """Calculate overlap coefficient (Szymkiewicz–Simpson coefficient)"""
        set1 = set(tokens1)
        set2 = set(tokens2)
        
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        min_size = min(len(set1), len(set2))
        
        return intersection / min_size if min_size > 0 else 0.0
    
    def _weighted_similarity(
        self,
        tokens1: List[str],
        tokens2: List[str],
        original_text1: str,
        original_text2: str
    ) -> float:
        """
        Calculate weighted similarity based on term importance
        Security-related terms get higher weight
        """
        # Important security terms get higher weights
        important_terms = {
            'vulnerability', 'exploit', 'attack', 'malicious', 'unauthorized',
            'injection', 'overflow', 'authentication', 'bypass', 'escalation',
            'disclosure', 'exposure', 'remote', 'execute', 'arbitrary',
            'denial', 'service', 'privilege', 'command', 'sql', 'xss',
            'csrf', 'rce', 'dos', 'xxe', 'deserialization', 'traversal',
            'certificate', 'encryption', 'crypto', 'ssl', 'tls', 'deprecated',
            'weak', 'insecure', 'flaw', 'security', 'critical', 'high'
        }
        
        set1 = set(tokens1)
        set2 = set(tokens2)
        intersection = set1.intersection(set2)
        
        if not intersection:
            return 0.0
        
        # Calculate weighted score
        weighted_score = 0.0
        total_weight = 0.0
        
        for token in intersection:
            weight = 2.0 if token in important_terms else 1.0
            weighted_score += weight
            total_weight += weight
        
        # Normalize by total possible weight
        max_possible = len(set1.union(set2)) * 2.0
        
        return weighted_score / max_possible if max_possible > 0 else 0.0
    
    def _ngram_similarity(self, text1: str, text2: str, n: int = 3) -> float:
        """Calculate character n-gram similarity"""
        def get_ngrams(text: str, n: int) -> set:
            text = text.replace(' ', '')
            return set(text[i:i+n] for i in range(len(text) - n + 1))
        
        ngrams1 = get_ngrams(text1, n)
        ngrams2 = get_ngrams(text2, n)
        
        if not ngrams1 or not ngrams2:
            return 0.0
        
        intersection = len(ngrams1.intersection(ngrams2))
        union = len(ngrams1.union(ngrams2))
        
        return intersection / union if union > 0 else 0.0
    
    def extract_key_phrases(self, text: str, max_phrases: int = 10) -> List[str]:
        """Extract key phrases from text for comparison"""
        # Split into potential phrases
        text = text.lower()
        
        # Extract multi-word technical terms
        technical_patterns = [
            r'\b(?:remote|arbitrary|privilege|buffer|memory|command|sql|path|directory)\s+\w+\b',
            r'\b\w+\s+(?:injection|overflow|traversal|escalation|bypass|disclosure|execution)\b',
            r'\b(?:cross-site|denial-of-service|man-in-the-middle)\b',
            r'\b(?:cve|cwe|cvss)-\d+\b'
        ]
        
        phrases = []
        for pattern in technical_patterns:
            matches = re.findall(pattern, text)
            phrases.extend(matches)
        
        return list(set(phrases))[:max_phrases]


class ThreadedCVEValidator:
    """
    Fast threaded CVE validation system with robust fallback mechanisms
    NOW WITH SEMANTIC SIMILARITY MATCHING
    """
    
    def __init__(self, tavily_api_key: str, max_workers: int = 8):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        self.max_workers = max_workers
        self.print_lock = Lock()
        self.similarity_matcher = SemanticSimilarityMatcher()  # NEW
        
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
            print(f"🔍 ADVANCED CVE VALIDATION (With Semantic Similarity)")
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
        NOW WITH SEMANTIC SIMILARITY
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
        
        # *** NEW Stage 6: Semantic Similarity (fast, no API) ***
        semantic_score = self.similarity_matcher.calculate_similarity(
            vulnerability_description,
            cve.description,
            context
        )
        
        # Enhanced early exit with semantic similarity consideration
        if (context_score < 0.2 and not vuln_type_match and 
            keyword_score < 0.3 and semantic_score < 0.25):
            with self.print_lock:
                print(f"  📍 Context Match: {context_score:.2f}")
                print(f"  🎯 Vulnerability Type Match: {vuln_type_match} ({vuln_match_score:.2f})")
                print(f"  🔑 Keyword Similarity: {keyword_score:.2f}")
                print(f"  🧬 Semantic Similarity: {semantic_score:.2f}")  # NEW
                print(f"  📅 Recency Score: {recency_score:.2f}")
                print(f"  ❌ NOT RELEVANT - Score: 0.25")
                print(f"     Reasoning: Poor context match, wrong vulnerability type, low keyword and semantic similarity")
            
            return ValidationResult(
                cve_id=cve.cve_id,
                is_relevant=False,
                relevance_score=0.25,
                reasoning="Poor context match, wrong vulnerability type, low keyword and semantic similarity",
                validation_method="fast-reject-rule-based",
                context_match_score=context_score,
                vulnerability_type_match=vuln_type_match,
                platform_match=False,
                recency_score=recency_score,
                confidence=0.85,
                semantic_similarity=semantic_score  # NEW
            )
        
        # Stage 7: Try LLM validation (may fail)
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
                semantic_score=semantic_score,  # NEW
                severity_score=severity_score,
                recency_score=recency_score
            )
            validation_method = "llm-enhanced"
            confidence = llm_validation.get('confidence', 0.7)
        else:
            # LLM failed - use rule-based fallback WITH SEMANTIC SIMILARITY
            final_score = self._calculate_final_score_rule_based(
                context_score=context_score,
                vuln_match_score=vuln_match_score,
                keyword_score=keyword_score,
                semantic_score=semantic_score,  # NEW
                severity_score=severity_score,
                recency_score=recency_score
            )
            validation_method = "rule-based-fallback"
            confidence = 0.6
        
        # Determine relevance
        is_relevant = final_score >= 0.35  # Threshold for acceptance
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            cve, context_score, vuln_type_match, vuln_match_score,
            keyword_score, semantic_score, llm_validation, final_score, validation_method
        )
        
        # Output validation results
        with self.print_lock:
            print(f"  📍 Context Match: {context_score:.2f}")
            print(f"  🎯 Vulnerability Type Match: {vuln_type_match} ({vuln_match_score:.2f})")
            print(f"  🔑 Keyword Similarity: {keyword_score:.2f}")
            print(f"  🧬 Semantic Similarity: {semantic_score:.2f}")  # NEW
            print(f"  ⚠️  Severity Score: {severity_score:.2f}")
            
            if llm_validation['success']:
                print(f"  🤖 LLM Validation: {llm_validation['score']:.2f}")
            else:
                print(f"  🤖 LLM Validation: FAILED - Using rule-based fallback")
            
            print(f"  📅 Recency Score: {recency_score:.2f}")
            print(f"  🔧 Method: {validation_method}")
            
            status = "✅ RELEVANT" if is_relevant else "❌ NOT RELEVANT"
            print(f"  {status} - Score: {final_score:.2f}")
            print(f"     Reasoning: {reasoning[:120]}...")
        
        return ValidationResult(
            cve_id=cve.cve_id,
            is_relevant=is_relevant,
            relevance_score=final_score,
            reasoning=reasoning,
            validation_method=validation_method,
            context_match_score=context_score,
            vulnerability_type_match=vuln_type_match,
            platform_match=context_score > 0.5,
            recency_score=recency_score,
            confidence=confidence,
            semantic_similarity=semantic_score  # NEW
        )
    
    def _validate_context_match_advanced(
        self,
        cve: Any,
        context: Optional[Dict[str, Any]]
    ) -> float:
        """Advanced context matching with platform detection"""
        if not context:
            return 0.5
        
        cve_text = f"{cve.description} {' '.join(cve.affected_products)}".lower()
        
        score = 0.0
        matches = []
        
        # Check operating system
        if "Operating System" in context and context["Operating System"]:
            os_value = str(context["Operating System"]).lower()
            
            for platform, keywords in self.platform_patterns.items():
                if any(keyword in os_value for keyword in keywords):
                    if any(keyword in cve_text for keyword in keywords):
                        score += 0.6
                        matches.append(f"OS:{platform}")
                        break
        
        # Check other context fields
        for key, value in context.items():
            if key == "Operating System":
                continue
            
            if value and str(value).lower() in cve_text:
                score += 0.3
                matches.append(f"{key}:{value}")
        
        return min(1.0, score)
    
    def _validate_vulnerability_type_advanced(
        self,
        cve: Any,
        vulnerability_description: str,
        analysis: Optional[Dict[str, Any]]
    ) -> tuple:
        """Advanced vulnerability type matching"""
        cve_text = cve.description.lower()
        vuln_text = vulnerability_description.lower()
        
        # Check against all vulnerability patterns
        matched_types = []
        for vuln_type, keywords in self.vulnerability_patterns.items():
            vuln_has_type = any(keyword in vuln_text for keyword in keywords)
            cve_has_type = any(keyword in cve_text for keyword in keywords)
            
            if vuln_has_type and cve_has_type:
                matched_types.append(vuln_type)
        
        if matched_types:
            # Calculate match strength
            match_score = min(1.0, len(matched_types) * 0.5)
            return True, match_score
        
        return False, 0.0
    
    def _calculate_severity_score(self, cve: Any) -> float:
        """Calculate score based on CVSS severity"""
        severity_map = {
            "CRITICAL": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.5,
            "LOW": 0.3
        }
        return severity_map.get(cve.severity.upper(), 0.5)
    
    def _calculate_keyword_similarity(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]]
    ) -> float:
        """Calculate keyword-based similarity"""
        vuln_words = set(re.findall(r'\w+', vulnerability_description.lower()))
        cve_words = set(re.findall(r'\w+', cve.description.lower()))
        
        # Add context words
        if context:
            context_words = set(re.findall(
                r'\w+',
                ' '.join(str(v) for v in context.values() if v).lower()
            ))
            vuln_words.update(context_words)
        
        # Remove common words
        vuln_words = {w for w in vuln_words if len(w) > 3}
        cve_words = {w for w in cve_words if len(w) > 3}
        
        if not vuln_words or not cve_words:
            return 0.0
        
        intersection = len(vuln_words.intersection(cve_words))
        union = len(vuln_words.union(cve_words))
        
        return intersection / union if union > 0 else 0.0
    
    def _validate_with_llm_safe(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validate with LLM but return structured failure if it doesn't work
        """
        try:
            context_str = json.dumps(context) if context else "No context"
            
            prompt = f"""Validate CVE relevance. Return ONLY a JSON object.

Vulnerability Query: {vulnerability_description}
Context: {context_str}

CVE ID: {cve.cve_id}
CVE Description: {cve.description}
Severity: {cve.severity} (CVSS: {cve.score})
Affected Products: {', '.join(cve.affected_products[:5])}

Return ONLY this JSON (no markdown, no explanation):
{{
  "score": <float 0.0-1.0>,
  "reasoning": "<why relevant or not>",
  "confidence": <float 0.0-1.0>
}}"""

            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.1,
                max_output_tokens=200
            )
            
            # Parse response
            result = self._parse_json_fast(response)
            
            if result and 'score' in result:
                result['success'] = True
                result['confidence'] = result.get('confidence', 0.7)
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
        semantic_score: float,  # NEW
        severity_score: float,
        recency_score: float
    ) -> float:
        """Calculate final score when LLM is available - WITH SEMANTIC SIMILARITY"""
        score = (
            context_score * 0.20 +        # Reduced to make room for semantic
            vuln_match_score * 0.15 +     # Reduced
            llm_score * 0.25 +            # Reduced
            keyword_score * 0.10 +        # Reduced
            semantic_score * 0.20 +       # NEW - High weight!
            severity_score * 0.05 +
            recency_score * 0.05
        )
        
        return max(0.0, min(1.0, score))
    
    def _calculate_final_score_rule_based(
        self,
        context_score: float,
        vuln_match_score: float,
        keyword_score: float,
        semantic_score: float,  # NEW
        severity_score: float,
        recency_score: float
    ) -> float:
        """
        Calculate final score using only rule-based methods (no LLM)
        NOW WITH SEMANTIC SIMILARITY AS A KEY FACTOR
        """
        score = (
            context_score * 0.25 +        # Platform/OS match
            vuln_match_score * 0.20 +     # Vulnerability type match
            keyword_score * 0.15 +        # Keyword overlap
            semantic_score * 0.30 +       # NEW - HIGHEST WEIGHT when no LLM!
            severity_score * 0.05 +       # Severity
            recency_score * 0.05          # How recent
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
        semantic_score: float,  # NEW
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
        
        # Semantic similarity reasoning - NEW!
        if semantic_score > 0.7:
            reasons.append("Very high semantic similarity between descriptions")
        elif semantic_score > 0.5:
            reasons.append("Good semantic similarity")
        elif semantic_score > 0.3:
            reasons.append("Moderate semantic similarity")
        else:
            reasons.append("Low semantic similarity")
        
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
    NOW WITH SEMANTIC SIMILARITY MATCHING
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