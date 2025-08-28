import json
import asyncio
import time
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Dict, Any, List
from tavily import AsyncTavilyClient
from langchain.schema import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

@dataclass
class RemediationResult:
    remediation_guide: str
    priority: str
    estimated_effort: str
    references: List[str]
    additional_resources: List[str]
    immediate_actions: List[str]
    detailed_steps: List[str]
    verification_steps: List[str]
    rollback_plan: List[str]

class RateLimitedRemediationAgent:
    """Rate-limited remediation agent with intelligent batching and fallbacks"""
    
    def __init__(self):
        # Use gemini-1.5-flash which has higher free tier limits (15 RPM vs 15 RPM for 2.0)
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",  # Better free tier limits
            temperature=0.4,
            max_tokens=1000,
            timeout=30
        )
        self.tavily_client = AsyncTavilyClient()
        
        # Rate limiting tracking
        self.request_timestamps = []
        self.max_requests_per_minute = 12  # Conservative limit for free tier
        self.request_interval = 5  # Minimum seconds between requests
        self.last_request_time = 0
        
        # Caching for efficiency
        self.search_cache = {}
        self.remediation_cache = {}
    
    async def _rate_limited_llm_call(self, messages: List, max_retries: int = 3) -> str:
        """Make rate-limited LLM calls with exponential backoff"""
        
        for attempt in range(max_retries):
            try:
                # Check rate limits
                current_time = time.time()
                
                # Remove timestamps older than 1 minute
                self.request_timestamps = [
                    ts for ts in self.request_timestamps 
                    if current_time - ts < 60
                ]
                
                # Wait if we've hit the rate limit
                if len(self.request_timestamps) >= self.max_requests_per_minute:
                    wait_time = 60 - (current_time - self.request_timestamps[0]) + 1
                    print(f"Rate limit reached. Waiting {wait_time:.1f} seconds...")
                    await asyncio.sleep(wait_time)
                
                # Ensure minimum interval between requests
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.request_interval:
                    wait_time = self.request_interval - time_since_last
                    await asyncio.sleep(wait_time)
                
                # Make the request
                response = await self.llm.ainvoke(messages)
                
                # Update tracking
                self.request_timestamps.append(time.time())
                self.last_request_time = time.time()
                
                return response.content
                
            except Exception as e:
                if "429" in str(e) or "ResourceExhausted" in str(e):
                    # Exponential backoff for rate limit errors
                    wait_time = min(2 ** attempt * 10, 120)  # Max 2 minutes
                    print(f"Rate limit hit (attempt {attempt + 1}). Waiting {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    print(f"LLM call error (attempt {attempt + 1}): {e}")
                    if attempt == max_retries - 1:
                        raise e
                    await asyncio.sleep(2 ** attempt)  # Regular exponential backoff
        
        raise Exception("Max retries exceeded for LLM call")
    
    async def _cached_search(self, query: str) -> Dict:
        """Cached Tavily search to avoid duplicate searches"""
        if query in self.search_cache:
            return self.search_cache[query]
        
        try:
            result = await self.tavily_client.search(
                query=query,
                search_depth="basic",  # Use basic to be faster
                max_results=2,  # Reduce results to speed up
                include_raw_content=False
            )
            self.search_cache[query] = result
            return result
        except Exception as e:
            print(f"Search error for '{query}': {e}")
            return {"results": []}
    
    async def _search_comprehensive_remediation_info(self, cve_id: str, vulnerability_title: str, cve_description: str) -> Dict[str, Any]:
        """Optimized search with reduced API calls"""
        search_results = {
            "patch_info": [],
            "vendor_advisories": [],
            "general_info": []
        }
        
        if not cve_id or cve_id == "N/A":
            return search_results
        
        try:
            # Reduced to 2 focused searches instead of 4
            search_queries = [
                f"{cve_id} patch fix remediation",
                f"{cve_id} security advisory mitigation"
            ]
            
            # Execute searches with delay to avoid overwhelming Tavily
            for i, query in enumerate(search_queries):
                if i > 0:
                    await asyncio.sleep(1)  # Small delay between searches
                
                result = await self._cached_search(query)
                
                category = "patch_info" if i == 0 else "vendor_advisories"
                
                for item in result.get('results', []):
                    processed_result = {
                        'title': item.get('title', ''),
                        'content': item.get('content', ''),
                        'url': item.get('url', ''),
                        'score': item.get('score', 0)
                    }
                    search_results[category].append(processed_result)
            
            return search_results
            
        except Exception as e:
            print(f"Comprehensive search error: {e}")
            return search_results
    
    async def generate_remediation(self, vulnerability_data: Dict, cve_info: Dict) -> RemediationResult:
        """Generate remediation with intelligent rate limiting and caching"""
        
        # Create cache key
        cache_key = f"{cve_info.get('cve_id', 'unknown')}_{vulnerability_data.get('title', 'unknown')}"
        
        if cache_key in self.remediation_cache:
            print(f"Using cached remediation for {cve_info.get('cve_id', 'unknown')}")
            return self.remediation_cache[cache_key]
        
        try:
            cve_id = cve_info.get('cve_id', 'Unknown')
            cve_description = cve_info.get('description', '')
            vulnerability_title = vulnerability_data.get('title', 'Unknown')
            
            # Reduced external research to minimize API calls
            if cve_id != "Unknown" and cve_id != "N/A":
                research_data = await self._search_comprehensive_remediation_info(
                    cve_id, vulnerability_title, cve_description
                )
            else:
                research_data = {"patch_info": [], "vendor_advisories": [], "general_info": []}
            
            # Build optimized context
            context_prompt = self._build_optimized_context(
                vulnerability_data, cve_info, research_data
            )
            
            # Generate remediation with rate limiting
            remediation_response = await self._generate_smart_remediation(context_prompt)
            
            # Parse and cache result
            result = self._parse_remediation_response(remediation_response, research_data)
            self.remediation_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            print(f"Remediation generation error: {e}")
            return self._create_fallback_remediation(vulnerability_data, cve_info)

    def _build_optimized_context(self, vuln_data: Dict, cve_info: Dict, research_data: Dict) -> str:
        """Build context optimized for shorter prompts to reduce token usage"""
        
        # Compact research context
        research_summary = ""
        
        if research_data.get('patch_info'):
            patches = research_data['patch_info'][:1]  # Only use top result
            if patches:
                research_summary += f"Patch Info: {patches[0]['title']} - {patches[0]['content'][:150]}\n"
        
        if research_data.get('vendor_advisories'):
            advisories = research_data['vendor_advisories'][:1]  # Only use top result
            if advisories:
                research_summary += f"Advisory: {advisories[0]['title']} - {advisories[0]['content'][:150]}\n"
        
        return f"""CVE: {cve_info.get('cve_id', 'Unknown')}
    Title: {vuln_data.get('title', 'Unknown')}
    CVSS: {cve_info.get('score', 'N/A')} | Severity: {cve_info.get('severity', 'Unknown')}
    OS: {vuln_data.get('os', 'Unknown')} | Category: {vuln_data.get('category', 'Unknown')}

    Description: {cve_info.get('description', 'No description')[:200]}

    Research: {research_summary[:300] if research_summary else 'Limited research available'}

    Generate JSON response:
    {{
        "remediation_guide": "Brief but specific remediation overview",
        "priority": "Critical/High/Medium/Low",
        "estimated_effort": "Time estimate with reasoning",
        "immediate_actions": ["Action 1", "Action 2", "Action 3"],
        "detailed_steps": ["Step 1", "Step 2", "Step 3"],
        "verification_steps": ["Verify 1", "Verify 2", "Verify 3"],
        "rollback_plan": ["Rollback 1", "Rollback 2", "Rollback 3"]
    }}"""
        

    async def _generate_smart_remediation(self, context_prompt: str) -> str:
        """Generate remediation with smart fallbacks"""
        
        system_message = """You are a cybersecurity expert. Generate specific, actionable remediation guidance based on the provided data. Be concise but comprehensive. Focus on practical steps."""
        
        try:
            # Try LLM generation with rate limiting
            response = await self._rate_limited_llm_call([
                SystemMessage(content=system_message),
                HumanMessage(content=context_prompt)
            ])
            return response
            
        except Exception as e:
            print(f"LLM generation failed: {e}")
            # Fallback to template-based generation
            return self._generate_template_based_remediation(context_prompt)
    
    def _generate_template_based_remediation(self, context: str) -> str:
        """Fallback template-based remediation when LLM fails"""
        
        # Extract key info from context
        lines = context.split('\n')
        cve_id = "Unknown"
        severity = "Medium"
        
        for line in lines:
            if "CVE:" in line:
                cve_id = line.split("CVE:")[-1].strip()
            elif "Severity:" in line:
                severity = line.split("Severity:")[-1].strip().split()[0]
        
        return f"""{{
    "remediation_guide": "Apply security updates for {cve_id}. Review vendor advisories and apply recommended patches.",
    "priority": "{severity}",
    "estimated_effort": "2-4 hours depending on system complexity",
    "immediate_actions": [
        "Check for available security patches",
        "Review vendor security advisories", 
        "Assess system exposure and impact"
    ],
    "detailed_steps": [
        "Identify all systems affected by {cve_id}",
        "Download and test patches in staging environment",
        "Schedule maintenance window for patch deployment",
        "Apply patches following vendor recommendations"
    ],
    "verification_steps": [
        "Verify patch installation completed successfully",
        "Run vulnerability scanner to confirm remediation",
        "Test system functionality post-patch application"
    ],
    "rollback_plan": [
        "Maintain complete system backups before patching",
        "Document all configuration changes made",
        "Test rollback procedures in staging environment"
    ]
}}"""
    
    def _parse_remediation_response(self, response: str, research_data: Dict) -> RemediationResult:
        """Parse response with improved error handling"""
        try:
            # Try to extract JSON
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_content = response[json_start:json_end]
                parsed = json.loads(json_content)
                
                # Extract URLs from research
                all_urls = []
                for category in research_data.values():
                    for item in category:
                        if item.get('url'):
                            all_urls.append(item['url'])
                
                return RemediationResult(
                    remediation_guide=parsed.get('remediation_guide', 'Remediation required'),
                    priority=parsed.get('priority', 'Medium'),
                    estimated_effort=parsed.get('estimated_effort', 'Assessment required'),
                    references=all_urls[:3],
                    additional_resources=self._get_standard_resources(),
                    immediate_actions=parsed.get('immediate_actions', [])[:3],
                    detailed_steps=parsed.get('detailed_steps', [])[:5],
                    verification_steps=parsed.get('verification_steps', [])[:3],
                    rollback_plan=parsed.get('rollback_plan', [])[:3]
                )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"JSON parsing error: {e}")
        
        # Fallback parsing
        return self._parse_unstructured_response(response, research_data)
    
    def _parse_unstructured_response(self, response: str, research_data: Dict) -> RemediationResult:
        """Parse unstructured response"""
        all_urls = []
        for category in research_data.values():
            for item in category:
                if item.get('url'):
                    all_urls.append(item['url'])
        
        return RemediationResult(
            remediation_guide=response[:300] + "..." if len(response) > 300 else response,
            priority=self._extract_priority_from_text(response),
            estimated_effort="2-4 hours based on complexity",
            references=all_urls[:3],
            additional_resources=self._get_standard_resources(),
            immediate_actions=self._extract_actions_from_text(response)[:3],
            detailed_steps=["Apply available patches", "Review security configurations", "Monitor systems"],
            verification_steps=["Verify patch installation", "Run security scan", "Test functionality"],
            rollback_plan=["Create backups", "Document changes", "Test rollback"]
        )
    
    def _extract_priority_from_text(self, text: str) -> str:
        text_lower = text.lower()
        if 'critical' in text_lower:
            return 'Critical'
        elif 'high' in text_lower:
            return 'High'
        elif 'low' in text_lower:
            return 'Low'
        return 'Medium'
    
    def _extract_actions_from_text(self, text: str) -> List[str]:
        lines = text.split('\n')
        actions = []
        
        for line in lines:
            line = line.strip()
            if (line.startswith(('1.', '2.', '3.', '-', '•')) or 
                any(keyword in line.lower() for keyword in ['update', 'patch', 'install', 'configure'])):
                actions.append(line[:80])
                
        return actions[:3] if actions else ["Review advisories", "Apply patches", "Monitor systems"]
    
    def _get_standard_resources(self) -> List[str]:
        return [
            "https://nvd.nist.gov/",
            "https://cve.mitre.org/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        ]
    
    def _create_fallback_remediation(self, vuln_data: Dict, cve_info: Dict) -> RemediationResult:
        cve_id = cve_info.get('cve_id', 'Unknown')
        
        return RemediationResult(
            remediation_guide=f"Security remediation required for {cve_id}. Apply vendor-recommended patches and security updates.",
            priority="Medium",
            estimated_effort="2-4 hours depending on system complexity",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id != "Unknown" else [],
            additional_resources=self._get_standard_resources(),
            immediate_actions=[
                "Check vendor security advisories",
                "Assess system exposure and impact",
                "Plan remediation maintenance window"
            ],
            detailed_steps=[
                "Identify all affected systems and versions",
                "Download and verify security patches",
                "Test patches in staging environment",
                "Apply patches during maintenance window"
            ],
            verification_steps=[
                "Verify successful patch installation",
                "Run vulnerability scan to confirm fix",
                "Test system functionality post-patch"
            ],
            rollback_plan=[
                "Maintain complete system backups",
                "Document all changes made",
                "Test rollback procedure thoroughly"
            ]
        )

# Initialize rate-limited agent
rate_limited_remediation_agent = RateLimitedRemediationAgent()

async def get_enhanced_remediation_data(result: Dict[str, Any], cve: Any = None) -> Dict[str, str]:
    """Get remediation data with rate limiting and intelligent fallbacks"""
    try:
        # Prepare data
        original_data = result.get("original_data", {})
        
        vulnerability_data = {
            "title": original_data.get("Title", "Unknown"),
            "qid": original_data.get("QID", "N/A"),
            "severity": original_data.get("Severity", "Unknown"),
            "os": original_data.get("OS", "Unknown"),
            "category": original_data.get("Category", "Unknown"),
            "port": original_data.get("Port", "N/A"),
            "protocol": original_data.get("Protocol", "N/A"),
        }
        
        cve_info = {}
        if cve:
            cve_info = {
                "cve_id": getattr(cve, "cve_id", "Unknown"),
                "score": getattr(cve, "score", 0),
                "severity": getattr(cve, "severity", "Unknown"),
                "description": getattr(cve, "description", "No description available")
            }
        else:
            cve_info = {
                "cve_id": "N/A",
                "score": 0,
                "severity": "Unknown", 
                "description": "No CVE information available"
            }
        
        # Generate with rate limiting
        remediation_result = await rate_limited_remediation_agent.generate_remediation(
            vulnerability_data, cve_info
        )
        
        return {
            "Remediation Guide": remediation_result.remediation_guide,
            "Remediation Priority": remediation_result.priority,
            "Estimated Effort": remediation_result.estimated_effort,
            "Reference Links": "; ".join(remediation_result.references),
            "Additional Resources": "; ".join(remediation_result.additional_resources),
            "Immediate Actions": "\n".join([f"• {action}" for action in remediation_result.immediate_actions]),
            "Detailed Steps": "\n".join([f"{i+1}. {step}" for i, step in enumerate(remediation_result.detailed_steps)]),
            "Verification Steps": "\n".join([f"• {step}" for step in remediation_result.verification_steps]),
            "Rollback Plan": "\n".join([f"• {step}" for step in remediation_result.rollback_plan]),
        }
        
    except Exception as e:
        print(f"Enhanced remediation error: {e}")
        return {
            "Remediation Guide": f"Manual remediation assessment required for CVE {getattr(cve, 'cve_id', 'Unknown') if cve else 'Unknown'}.",
            "Remediation Priority": "Medium", 
            "Estimated Effort": "Manual assessment required",
            "Reference Links": "",
            "Additional Resources": "https://nvd.nist.gov/",
            "Immediate Actions": "• Review CVE details\n• Check vendor advisories\n• Assess system exposure",
            "Detailed Steps": "1. Analyze vulnerability impact\n2. Check for patches\n3. Plan remediation",
            "Verification Steps": "• Verify fixes applied\n• Test functionality\n• Run vulnerability scan",
            "Rollback Plan": "• Maintain backups\n• Document changes\n• Test rollback"
        }
