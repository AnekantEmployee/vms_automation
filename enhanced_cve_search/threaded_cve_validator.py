import re
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tavily import TavilyClient
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
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
    Fast threaded CVE validation system
    """
    
    def __init__(self, tavily_api_key: str, max_workers: int = 8):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        self.max_workers = max_workers
        self.print_lock = Lock()
        
    def validate_cve_batch(
        self,
        cves: List[Any],
        vulnerability_description: str,
        context: Optional[Dict[str, Any]] = None,
        analysis: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """
        Validate CVEs using threading for speed
        """
        with self.print_lock:
            print(f"\n{'='*80}")
            print(f"🔍 ADVANCED CVE VALIDATION")
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
        Validate a single CVE (thread-safe)
        """
        with self.print_lock:
            print(f"\n[{index}/{total}] Validating {cve.cve_id}...")
        
        # Stage 1: Context Matching (fast)
        context_score = self._validate_context_match(cve, context)
        
        # Stage 2: Vulnerability Type Matching (fast)
        vuln_type_match = self._validate_vulnerability_type(
            cve, vulnerability_description, analysis
        )
        
        # Stage 3: Recency Scoring (fast)
        recency_score = self._calculate_recency_score(cve)
        
        # Early exit for obviously irrelevant CVEs
        if context_score < 0.2 and not vuln_type_match:
            with self.print_lock:
                print(f"  📍 Context Match: {context_score:.2f}")
                print(f"  🎯 Vulnerability Type Match: {vuln_type_match}")
                print(f"  📅 Recency Score: {recency_score:.2f}")
                print(f"  ❌ NOT RELEVANT - Score: 0.30")
                print(f"     Reasoning: Poor context match and wrong vulnerability type")
            
            return ValidationResult(
                cve_id=cve.cve_id,
                is_relevant=False,
                relevance_score=0.30,
                reasoning="Poor context match and wrong vulnerability type",
                validation_method="fast-reject",
                context_match_score=context_score,
                vulnerability_type_match=vuln_type_match,
                platform_match=False,
                recency_score=recency_score,
                confidence=0.8
            )
        
        # Stage 4: LLM validation for promising candidates
        llm_validation = self._validate_with_llm(
            cve, vulnerability_description, context, analysis
        )
        
        # Calculate final score
        final_score = self._calculate_final_score(
            context_score=context_score,
            vuln_type_match=vuln_type_match,
            llm_score=llm_validation['score'],
            web_score=None,  # Skip web search for speed
            recency_score=recency_score,
            context=context
        )
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            cve=cve,
            context_score=context_score,
            vuln_type_match=vuln_type_match,
            llm_validation=llm_validation,
            web_verification=None,
            final_score=final_score
        )
        
        # Determine if relevant
        is_relevant = final_score >= 0.5
        
        with self.print_lock:
            print(f"  📍 Context Match: {context_score:.2f}")
            print(f"  🎯 Vulnerability Type Match: {vuln_type_match}")
            print(f"  🤖 LLM Validation: {llm_validation['score']:.2f}")
            print(f"  📅 Recency Score: {recency_score:.2f}")
            
            if is_relevant:
                print(f"  ✅ RELEVANT - Score: {final_score:.2f}")
                print(f"     Reasoning: {reasoning[:100]}...")
            else:
                print(f"  ❌ NOT RELEVANT - Score: {final_score:.2f}")
                print(f"     Reasoning: {reasoning[:100]}...")
        
        return ValidationResult(
            cve_id=cve.cve_id,
            is_relevant=is_relevant,
            relevance_score=final_score,
            reasoning=reasoning,
            validation_method="threaded",
            context_match_score=context_score,
            vulnerability_type_match=vuln_type_match,
            platform_match=(context_score > 0.5),
            recency_score=recency_score,
            confidence=llm_validation.get('confidence', 0.7)
        )
    
    def _validate_context_match(self, cve: Any, context: Optional[Dict[str, Any]]) -> float:
        """Fast context matching"""
        if not context:
            return 0.5
        
        score = 0.0
        os_requirement = context.get("Operating System", "").lower()
        
        # Quick OS check
        if os_requirement:
            affected_products = " ".join(cve.affected_products).lower()
            cve_description = cve.description.lower()
            
            # Windows check
            if "windows" in os_requirement:
                if any(x in affected_products or x in cve_description 
                      for x in ["windows", "microsoft"]):
                    score += 0.5
                elif any(x in affected_products or x in cve_description 
                        for x in ["linux", "ubuntu", "debian"]):
                    score -= 0.3
            
            # Linux check
            elif "linux" in os_requirement or "ubuntu" in os_requirement:
                if any(x in affected_products or x in cve_description 
                      for x in ["linux", "ubuntu", "debian", "rhel"]):
                    score += 0.5
                elif any(x in affected_products or x in cve_description 
                        for x in ["windows", "microsoft"]):
                    score -= 0.3
        
        return max(0.0, min(1.0, score))
    
    def _validate_vulnerability_type(
        self,
        cve: Any,
        vulnerability_description: str,
        analysis: Optional[Dict[str, Any]]
    ) -> bool:
        """Fast vulnerability type matching"""
        vuln_desc = vulnerability_description.lower()
        cve_desc = cve.description.lower()
        
        # Key vulnerability patterns
        patterns = {
            "ssl": ["ssl", "tls", "certificate", "crypto"],
            "auth": ["authentication", "auth", "login"],
            "injection": ["injection", "sql", "xss"],
            "overflow": ["overflow", "buffer"],
            "rce": ["remote code", "execute", "rce"],
        }
        
        for pattern_type, keywords in patterns.items():
            if any(k in vuln_desc for k in keywords):
                return any(k in cve_desc for k in keywords)
        
        return True  # Default to true if can't determine
    
    def _validate_with_llm(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Optimized LLM validation"""
        context_str = ""
        if context:
            context_str = f"\nContext: {context.get('Operating System', '')} {context.get('Asset Type', '')}"
        
        # Shorter, focused prompt for speed
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

        try:
            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.1,
                max_output_tokens=200  # Reduced for speed
            )
            
            result = self._parse_json_fast(response)
            if result and "score" in result:
                return result
            
            return {
                "score": 0.5,
                "reasoning": "LLM parsing failed",
                "confidence": 0.3
            }
        
        except Exception as e:
            return {
                "score": 0.5,
                "reasoning": f"LLM error: {str(e)[:50]}",
                "confidence": 0.2
            }
    
    def _parse_json_fast(self, response: str) -> Optional[Dict[str, Any]]:
        """Fast JSON parsing"""
        try:
            # Clean response
            cleaned = response.strip()
            cleaned = re.sub(r'^```json\s*', '', cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s*```$', '', cleaned)
            
            # Try direct parsing
            result = json.loads(cleaned)
            if isinstance(result, dict) and "score" in result:
                return result
        except:
            pass
        
        # Regex fallback
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
        
        return None
    
    def _calculate_recency_score(self, cve: Any) -> float:
        """Fast recency calculation"""
        if not cve.published_date:
            return 0.3
        
        try:
            pub_date = datetime.fromisoformat(cve.published_date.replace('Z', '+00:00'))
            age_years = (datetime.now() - pub_date).days / 365.25
            
            if age_years < 1:
                return 1.0
            elif age_years < 3:
                return 0.8
            elif age_years < 5:
                return 0.6
            elif age_years < 10:
                return 0.4
            else:
                return 0.2
        except:
            return 0.5
    
    def _calculate_final_score(
        self,
        context_score: float,
        vuln_type_match: bool,
        llm_score: float,
        web_score: Optional[float],
        recency_score: float,
        context: Optional[Dict[str, Any]]
    ) -> float:
        """Fast final score calculation"""
        # Simplified weights for speed
        score = (
            context_score * 0.35 +
            (1.0 if vuln_type_match else 0.0) * 0.25 +
            llm_score * 0.30 +
            recency_score * 0.10
        )
        
        return max(0.0, min(1.0, score))
    
    def _generate_reasoning(
        self,
        cve: Any,
        context_score: float,
        vuln_type_match: bool,
        llm_validation: Dict[str, Any],
        web_verification: Optional[Dict[str, Any]],
        final_score: float
    ) -> str:
        """Fast reasoning generation"""
        reasons = []
        
        if llm_validation.get("reasoning"):
            reasons.append(f"LLM Analysis: {llm_validation['reasoning']}")
        
        if context_score > 0.7:
            reasons.append("Strong context match")
        elif context_score < 0.3:
            reasons.append("Poor context match - may be wrong platform/software")
        
        if vuln_type_match:
            reasons.append("Vulnerability type matches")
        else:
            reasons.append("Vulnerability type does not match")
        
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
    Fast threaded CVE validation
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