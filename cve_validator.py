import re
import json
import time
from datetime import datetime
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
    context_match_score: float  # How well does it match the context (OS, software, etc.)
    vulnerability_type_match: bool
    platform_match: bool
    recency_score: float  # Higher for more recent CVEs
    confidence: float  # Confidence in the validation


class AdvancedCVEValidator:
    """
    Advanced CVE validation system with multiple validation strategies
    """
    
    def __init__(self, tavily_api_key: str):
        self.tavily = TavilyClient(api_key=tavily_api_key)
        
    def validate_cve_batch(
        self,
        cves: List[Any],
        vulnerability_description: str,
        context: Optional[Dict[str, Any]] = None,
        analysis: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """
        Validate a batch of CVEs with intelligent relevance checking
        
        Args:
            cves: List of CVEInfo objects
            vulnerability_description: Original vulnerability query
            context: Context information (OS, software, etc.)
            analysis: Vulnerability analysis from LLM
            
        Returns:
            List of validated CVEInfo objects with updated relevance scores
        """
        print(f"\n{'='*80}")
        print(f"🔍 ADVANCED CVE VALIDATION")
        print(f"{'='*80}")
        print(f"Validating {len(cves)} CVEs")
        print(f"Query: {vulnerability_description}")
        if context:
            print(f"Context: {json.dumps(context, indent=2)}")
        print(f"{'='*80}\n")
        
        validated_cves = []
        
        for i, cve in enumerate(cves, 1):
            print(f"\n[{i}/{len(cves)}] Validating {cve.cve_id}...")
            
            # Multi-stage validation
            validation_result = self._validate_single_cve(
                cve=cve,
                vulnerability_description=vulnerability_description,
                context=context,
                analysis=analysis
            )
            
            # Update CVE with validation results
            cve.relevance_score = validation_result.relevance_score
            cve.relevance_reasoning = validation_result.reasoning
            
            # Only keep CVEs that pass validation
            if validation_result.is_relevant:
                validated_cves.append(cve)
                print(f"  ✅ RELEVANT - Score: {validation_result.relevance_score:.2f}")
                print(f"     Reasoning: {validation_result.reasoning[:100]}...")
            else:
                print(f"  ❌ NOT RELEVANT - Score: {validation_result.relevance_score:.2f}")
                print(f"     Reasoning: {validation_result.reasoning[:100]}...")
            
            time.sleep(0.5)  # Rate limiting
        
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
        analysis: Optional[Dict[str, Any]]
    ) -> ValidationResult:
        """
        Validate a single CVE using multiple validation methods
        """
        # Stage 1: Platform/Context Matching
        context_score = self._validate_context_match(cve, context)
        print(f"  📍 Context Match: {context_score:.2f}")
        
        # Stage 2: Vulnerability Type Matching
        vuln_type_match = self._validate_vulnerability_type(
            cve, vulnerability_description, analysis
        )
        print(f"  🎯 Vulnerability Type Match: {vuln_type_match}")
        
        # Stage 3: LLM-based Deep Analysis
        llm_validation = self._validate_with_llm(
            cve, vulnerability_description, context, analysis
        )
        print(f"  🤖 LLM Validation: {llm_validation['score']:.2f}")
        
        # Stage 4: Web Search Verification (for borderline cases)
        web_verification = None
        if 0.4 <= llm_validation['score'] <= 0.7:
            print(f"  🌐 Running web verification...")
            web_verification = self._verify_with_web_search(
                cve, vulnerability_description, context
            )
            print(f"  🌐 Web Verification: {web_verification['score']:.2f}")
        
        # Stage 5: Recency Scoring
        recency_score = self._calculate_recency_score(cve)
        print(f"  📅 Recency Score: {recency_score:.2f}")
        
        # Combine all scores with weights
        final_score = self._calculate_final_score(
            context_score=context_score,
            vuln_type_match=vuln_type_match,
            llm_score=llm_validation['score'],
            web_score=web_verification['score'] if web_verification else None,
            recency_score=recency_score,
            context=context
        )
        
        # Generate comprehensive reasoning
        reasoning = self._generate_reasoning(
            cve=cve,
            context_score=context_score,
            vuln_type_match=vuln_type_match,
            llm_validation=llm_validation,
            web_verification=web_verification,
            final_score=final_score
        )
        
        # Determine if relevant (threshold: 0.5)
        is_relevant = final_score >= 0.5
        
        return ValidationResult(
            cve_id=cve.cve_id,
            is_relevant=is_relevant,
            relevance_score=final_score,
            reasoning=reasoning,
            validation_method="multi-stage",
            context_match_score=context_score,
            vulnerability_type_match=vuln_type_match,
            platform_match=(context_score > 0.5),
            recency_score=recency_score,
            confidence=llm_validation.get('confidence', 0.7)
        )
    
    def _validate_context_match(
        self,
        cve: Any,
        context: Optional[Dict[str, Any]]
    ) -> float:
        """
        Validate if CVE matches the context (OS, software, version, etc.)
        Returns score 0.0 to 1.0
        """
        if not context:
            return 0.5  # Neutral if no context
        
        score = 0.0
        matches = []
        mismatches = []
        
        # Extract context requirements
        os_requirement = context.get("Operating System", "").lower()
        software_requirement = context.get("Service", context.get("Component", context.get("Framework", ""))).lower()
        
        # Check affected products
        affected_products = " ".join(cve.affected_products).lower()
        cve_description = cve.description.lower()
        
        # OS Matching
        if os_requirement:
            os_keywords = self._extract_os_keywords(os_requirement)
            os_match = any(keyword in affected_products or keyword in cve_description 
                          for keyword in os_keywords)
            
            if os_match:
                score += 0.5
                matches.append(f"OS match: {os_requirement}")
            else:
                # Check if it's a different OS (penalty)
                conflicting_os = self._detect_conflicting_os(
                    os_requirement, affected_products, cve_description
                )
                if conflicting_os:
                    score -= 0.3
                    mismatches.append(f"Wrong OS: {conflicting_os} (expected {os_requirement})")
        
        # Software/Component Matching
        if software_requirement:
            software_keywords = software_requirement.split()
            software_match = any(keyword in affected_products or keyword in cve_description 
                                for keyword in software_keywords if len(keyword) > 2)
            
            if software_match:
                score += 0.5
                matches.append(f"Software match: {software_requirement}")
            else:
                score -= 0.1
                mismatches.append(f"Software not found: {software_requirement}")
        
        # Normalize score to 0-1 range
        score = max(0.0, min(1.0, score))
        
        return score
    
    def _extract_os_keywords(self, os_string: str) -> List[str]:
        """Extract OS-specific keywords for matching"""
        os_string = os_string.lower()
        keywords = []
        
        # Windows variants
        if "windows" in os_string:
            keywords.extend(["windows", "microsoft"])
            if "server" in os_string:
                keywords.append("server")
            if "10" in os_string:
                keywords.append("windows_10")
            if "11" in os_string:
                keywords.append("windows_11")
            if "2019" in os_string:
                keywords.extend(["windows_server_2019", "2019"])
            if "2022" in os_string:
                keywords.extend(["windows_server_2022", "2022"])
        
        # Linux variants
        elif "linux" in os_string:
            keywords.append("linux")
            if "ubuntu" in os_string:
                keywords.extend(["ubuntu", "canonical"])
            if "debian" in os_string:
                keywords.append("debian")
            if "rhel" in os_string or "red hat" in os_string:
                keywords.extend(["rhel", "red_hat", "redhat"])
            if "centos" in os_string:
                keywords.append("centos")
        
        # macOS
        elif "mac" in os_string or "darwin" in os_string:
            keywords.extend(["macos", "darwin", "apple"])
        
        return keywords
    
    def _detect_conflicting_os(
        self,
        expected_os: str,
        affected_products: str,
        description: str
    ) -> Optional[str]:
        """Detect if CVE is for a different OS than expected"""
        expected_os = expected_os.lower()
        
        # Define OS families
        windows_indicators = ["windows", "microsoft", "win32", "nt"]
        linux_indicators = ["linux", "ubuntu", "debian", "rhel", "centos", "fedora"]
        mac_indicators = ["macos", "darwin", "osx"]
        
        # Determine expected OS family
        if any(x in expected_os for x in windows_indicators):
            expected_family = "windows"
            conflicting_families = linux_indicators + mac_indicators
        elif any(x in expected_os for x in linux_indicators):
            expected_family = "linux"
            conflicting_families = windows_indicators + mac_indicators
        elif any(x in expected_os for x in mac_indicators):
            expected_family = "mac"
            conflicting_families = windows_indicators + linux_indicators
        else:
            return None
        
        # Check for conflicting OS
        combined_text = affected_products + " " + description
        for indicator in conflicting_families:
            if indicator in combined_text:
                return indicator
        
        return None
    
    def _validate_vulnerability_type(
        self,
        cve: Any,
        vulnerability_description: str,
        analysis: Optional[Dict[str, Any]]
    ) -> bool:
        """
        Check if CVE vulnerability type matches the query
        """
        vuln_desc = vulnerability_description.lower()
        cve_desc = cve.description.lower()
        
        # Extract key vulnerability types
        vuln_types = {
            "sql injection": ["sql injection", "sqli", "sql inject"],
            "xss": ["cross-site scripting", "xss", "cross site scripting"],
            "buffer overflow": ["buffer overflow", "heap overflow", "stack overflow"],
            "authentication": ["authentication", "auth bypass", "login"],
            "certificate": ["certificate", "ssl", "tls", "crypto"],
            "rce": ["remote code execution", "rce", "execute arbitrary", "execute code"],
            "privilege escalation": ["privilege escalation", "escalation of privilege"],
            "path traversal": ["path traversal", "directory traversal"],
            "csrf": ["csrf", "cross-site request forgery"],
            "deserialization": ["deserialization", "deserialize"],
        }
        
        # Identify query vulnerability type
        query_type = None
        for vtype, keywords in vuln_types.items():
            if any(keyword in vuln_desc for keyword in keywords):
                query_type = vtype
                break
        
        if not query_type:
            return True  # Can't determine type, neutral
        
        # Check if CVE matches
        cve_keywords = vuln_types[query_type]
        return any(keyword in cve_desc for keyword in cve_keywords)
    
    def _validate_with_llm(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]],
        analysis: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Deep LLM-based validation with detailed reasoning
        """
        context_str = ""
        if context:
            context_str = f"\n\nContext Requirements:\n{json.dumps(context, indent=2)}"
        
        analysis_str = ""
        if analysis:
            analysis_str = f"\n\nVulnerability Analysis:\n{json.dumps(analysis, indent=2)}"
        
        prompt = f"""You are a cybersecurity expert evaluating if a CVE is relevant to a vulnerability query.

VULNERABILITY QUERY: {vulnerability_description}{context_str}{analysis_str}

CVE TO EVALUATE:
- CVE ID: {cve.cve_id}
- Description: {cve.description}
- Severity: {cve.severity} (CVSS: {cve.cvss_score})
- CWE IDs: {', '.join(cve.cwe_ids[:5]) if cve.cwe_ids else 'None'}
- Affected Products: {', '.join(cve.affected_products[:5]) if cve.affected_products else 'None'}
- Published: {cve.published_date[:10] if cve.published_date else 'Unknown'}

Evaluate this CVE based on:
1. Does it match the vulnerability TYPE described in the query?
2. Does it match the PLATFORM/OS in the context?
3. Does it match the SOFTWARE/COMPONENT in the context?
4. Is it a close match or just tangentially related?

Provide your evaluation in JSON format:
{{
    "is_relevant": true/false,
    "score": 0.0-1.0,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation",
    "match_type": "exact/close/weak/none",
    "platform_match": true/false,
    "vulnerability_type_match": true/false
}}

Be strict in your evaluation:
- Score 0.0-0.3: Not relevant or wrong platform/type
- Score 0.4-0.6: Partially relevant, missing context match
- Score 0.7-0.9: Highly relevant, good match
- Score 1.0: Perfect match

Return ONLY valid JSON, no additional text."""

        try:
            response = generate_content_with_fallback(
                prompt=prompt,
                temperature=0.1,
                max_output_tokens=800  # Increased token limit
            )
            
            # Robust JSON parsing
            result = self._parse_json_robust(response)
            
            if result and "score" in result:
                return result
            else:
                print(f"    ⚠ Could not parse LLM response")
                return {
                    "is_relevant": True,
                    "score": 0.5,
                    "confidence": 0.3,
                    "reasoning": "LLM response parsing failed",
                    "match_type": "unknown"
                }
        
        except Exception as e:
            print(f"    ⚠ LLM validation failed: {e}")
            return {
                "is_relevant": True,
                "score": 0.5,
                "confidence": 0.2,
                "reasoning": f"LLM validation error: {str(e)}",
                "match_type": "unknown"
            }
    
    def _parse_json_robust(self, response: str) -> Optional[Dict[str, Any]]:
        """Robust JSON parsing that handles partial/truncated responses"""
        
        # Clean response
        cleaned = response.strip()
        
        # Remove markdown code blocks
        cleaned = re.sub(r'^```json\s*', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'\s*```$', '', cleaned)
        cleaned = re.sub(r'^```\s*', '', cleaned)
        
        # Try standard JSON parsing first
        try:
            result = json.loads(cleaned)
            if isinstance(result, dict) and "score" in result:
                return result
        except json.JSONDecodeError:
            pass
        
        # Try to fix common JSON issues
        try:
            # Add missing closing braces if needed
            if cleaned.count('{') > cleaned.count('}'):
                cleaned += '}' * (cleaned.count('{') - cleaned.count('}'))
            
            # Try parsing again
            result = json.loads(cleaned)
            if isinstance(result, dict) and "score" in result:
                return result
        except json.JSONDecodeError:
            pass
        
        # If all else fails, try to extract key values with regex
        try:
            score_match = re.search(r'"score"\s*:\s*([0-9.]+)', cleaned)
            relevant_match = re.search(r'"is_relevant"\s*:\s*(true|false)', cleaned)
            reasoning_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', cleaned)
            
            if score_match:
                return {
                    "score": float(score_match.group(1)),
                    "is_relevant": relevant_match.group(1) == "true" if relevant_match else True,
                    "reasoning": reasoning_match.group(1) if reasoning_match else "Partial JSON parsing",
                    "confidence": 0.5,
                    "match_type": "partial"
                }
        except Exception:
            pass
        
        return None
    
    def _verify_with_web_search(
        self,
        cve: Any,
        vulnerability_description: str,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Verify CVE relevance using web search for additional context
        """
        try:
            # Build search query
            search_query = f"{cve.cve_id} {vulnerability_description[:50]}"
            if context and context.get("Operating System"):
                search_query += f" {context['Operating System']}"
            
            # Search
            results = self.tavily.search(
                query=search_query,
                search_depth="basic",
                max_results=3
            )
            
            # Analyze search results
            found_relevant = False
            relevance_indicators = 0
            
            for result in results.get("results", []):
                content = result.get("content", "").lower() + result.get("title", "").lower()
                
                # Check for relevance indicators
                if cve.cve_id.lower() in content:
                    relevance_indicators += 1
                
                # Check for context matches
                if context:
                    if context.get("Operating System", "").lower() in content:
                        relevance_indicators += 1
                    if context.get("Service", "").lower() in content:
                        relevance_indicators += 1
            
            score = min(1.0, relevance_indicators * 0.25)
            
            return {
                "score": score,
                "found_relevant": relevance_indicators > 0,
                "indicators_found": relevance_indicators
            }
        
        except Exception as e:
            print(f"    ⚠ Web verification failed: {e}")
            return {"score": 0.5, "found_relevant": False, "indicators_found": 0}
    
    def _calculate_recency_score(self, cve: Any) -> float:
        """
        Calculate recency score - prefer newer CVEs
        """
        if not cve.published_date:
            return 0.3
        
        try:
            # Parse publication date
            pub_date = datetime.fromisoformat(cve.published_date.replace('Z', '+00:00'))
            now = datetime.now()
            
            # Calculate age in years
            age_years = (now - pub_date).days / 365.25
            
            # Scoring:
            # 0-1 years: 1.0
            # 1-3 years: 0.8
            # 3-5 years: 0.6
            # 5-10 years: 0.4
            # 10+ years: 0.2
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
        
        except Exception:
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
        """
        Calculate final relevance score with weighted combination
        """
        # Define weights
        weights = {
            "context": 0.30,
            "vuln_type": 0.25,
            "llm": 0.30,
            "recency": 0.10,
            "web": 0.05
        }
        
        # If context is provided, increase its weight
        if context:
            weights["context"] = 0.35
            weights["llm"] = 0.25
        
        # Calculate weighted score
        score = 0.0
        
        # Context score
        score += context_score * weights["context"]
        
        # Vulnerability type match
        score += (1.0 if vuln_type_match else 0.0) * weights["vuln_type"]
        
        # LLM score
        score += llm_score * weights["llm"]
        
        # Recency score
        score += recency_score * weights["recency"]
        
        # Web verification (if available)
        if web_score is not None:
            score += web_score * weights["web"]
        
        # Normalize to 0-1
        score = max(0.0, min(1.0, score))
        
        return score
    
    def _generate_reasoning(
        self,
        cve: Any,
        context_score: float,
        vuln_type_match: bool,
        llm_validation: Dict[str, Any],
        web_verification: Optional[Dict[str, Any]],
        final_score: float
    ) -> str:
        """
        Generate comprehensive reasoning for the validation decision
        """
        reasons = []
        
        # LLM reasoning
        if llm_validation.get("reasoning"):
            reasons.append(f"LLM Analysis: {llm_validation['reasoning']}")
        
        # Context match
        if context_score > 0.7:
            reasons.append("Strong context match (OS/platform/software)")
        elif context_score < 0.3:
            reasons.append("Poor context match - may be wrong platform/software")
        
        # Vulnerability type
        if vuln_type_match:
            reasons.append("Vulnerability type matches query")
        else:
            reasons.append("Vulnerability type does not match query")
        
        # Web verification
        if web_verification and web_verification.get("found_relevant"):
            reasons.append(f"Web verification confirms relevance ({web_verification['indicators_found']} indicators)")
        
        # Final assessment
        if final_score >= 0.8:
            reasons.append("HIGH CONFIDENCE - Strong match")
        elif final_score >= 0.6:
            reasons.append("MEDIUM CONFIDENCE - Good match")
        elif final_score >= 0.4:
            reasons.append("LOW CONFIDENCE - Weak match")
        else:
            reasons.append("VERY LOW CONFIDENCE - Likely not relevant")
        
        return " | ".join(reasons)


def validate_cves_advanced(
    cves: List[Any],
    vulnerability_description: str,
    context: Optional[Dict[str, Any]] = None,
    analysis: Optional[Dict[str, Any]] = None,
    tavily_api_key: str = None
) -> List[Any]:
    """
    Convenience function to validate CVEs using the advanced validator
    
    Args:
        cves: List of CVEInfo objects
        vulnerability_description: Original vulnerability query
        context: Context information
        analysis: Vulnerability analysis
        tavily_api_key: Tavily API key
        
    Returns:
        List of validated CVEInfo objects
    """
    if not tavily_api_key:
        import os
        tavily_api_key = os.getenv("TAVILY_API_KEY")
    
    validator = AdvancedCVEValidator(tavily_api_key=tavily_api_key)
    
    return validator.validate_cve_batch(
        cves=cves,
        vulnerability_description=vulnerability_description,
        context=context,
        analysis=analysis
    )