import asyncio
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from dataclasses import dataclass
from pydantic import BaseModel, Field
from langchain_tavily import TavilySearch
from langgraph.graph import StateGraph, END
from typing import Dict, Any, List, TypedDict

# Add parent directory to path to import api_key_manager
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import the API key manager for fallback handling
try:
    from config.api_key_manager import get_api_key_manager, generate_content_with_fallback
    HAS_API_KEY_MANAGER = True
except ImportError:
    HAS_API_KEY_MANAGER = False
    print("Warning: API key manager not available, using standard LangChain")

from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

@dataclass
class RiskResult:
    risk_category: str
    risk_score: float
    risk_details: str
    business_impact: str
    remediation_urgency: str
    immediate_actions: List[str]
    exploitation_methods: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'risk_category': self.risk_category,
            'risk_score': self.risk_score,
            'risk_details': self.risk_details,
            'business_impact': self.business_impact,
            'remediation_urgency': self.remediation_urgency,
            'immediate_actions': self.immediate_actions,
            'exploitation_methods': self.exploitation_methods
        }

class SimpleRiskAssessment(BaseModel):
    risk_category: str = Field(description="Risk level: Critical/High/Medium/Low")
    risk_score: float = Field(description="Risk score 0-10")
    business_impact: str = Field(description="Business impact summary")
    remediation_priority: str = Field(description="Remediation urgency")
    key_actions: List[str] = Field(description="Top 3 remediation actions")
    exploitation_methods: str = Field(description="How vulnerability can be exploited")

class RiskAgentState(TypedDict):
    vulnerability_data: Dict[str, Any]
    cve_data: Dict[str, Any]
    risk_assessment: RiskResult
    calculated_risk: Dict[str, Any]
    error: str

class FastVulnerabilityRiskAgent:
    def __init__(self):
        """Initialize with API key manager support"""
        self._setup_llm()
        
        self.tavily_search = TavilySearch(
            max_results=2,
            search_depth="basic",
            include_answer=True
        )
        self.graph = self._build_graph()
        
        # Predefined user-friendly action templates
        self.action_templates = {
            'authentication': [
                "Enable HTTPS/SSL encryption for login forms",
                "Implement secure password transmission protocols",
                "Deploy multi-factor authentication (MFA)"
            ],
            'ssl_tls': [
                "Update SSL/TLS certificates to latest version",
                "Configure secure cipher suites",
                "Enable HSTS (HTTP Strict Transport Security)"
            ],
            'plaintext': [
                "Enable password encryption in transit",
                "Configure secure communication protocols",
                "Implement data encryption at rest"
            ],
            'web_server': [
                "Secure web server configuration",
                "Enable access logging and monitoring",
                "Configure proper authentication mechanisms"
            ],
            'pci_compliance': [
                "Address PCI DSS compliance requirements immediately",
                "Implement secure payment processing",
                "Enable comprehensive audit logging"
            ],
            'default': [
                "Apply latest security patches and updates",
                "Review and harden system configurations",
                "Enable security monitoring and alerting"
            ]
        }
    
    def _setup_llm(self):
        """Setup LLM with API key manager fallback"""
        if HAS_API_KEY_MANAGER:
            # Use API key manager for automatic rotation
            manager = get_api_key_manager()
            api_key = manager.get_next_available_key()
            
            if not api_key:
                raise ValueError("No working Gemini API keys available")
            
            self.llm = ChatGoogleGenerativeAI(
                model=os.getenv("MODEL_NAME", "gemini-2.5-flash"),
                temperature=0.3,
                max_tokens=800,
                api_key=api_key
            )
            self.api_key_manager = manager
        else:
            # Fallback to standard initialization
            self.llm = ChatGoogleGenerativeAI(
                model=os.getenv("MODEL_NAME", "gemini-2.5-flash"),
                temperature=0.3,
                max_tokens=800
            )
            self.api_key_manager = None
    
    def _retry_llm_call_with_fallback(self, func, *args, **kwargs):
        """Retry LLM call with API key rotation on failure"""
        if not self.api_key_manager:
            # No API key manager, just try once
            return func(*args, **kwargs)
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                error_str = str(e).lower()
                is_quota_error = any(code in error_str for code in [
                    "429", "quota", "rate limit", "resource_exhausted"
                ])
                
                if is_quota_error and attempt < max_attempts - 1:
                    print(f"LLM call failed with quota error, rotating API key (attempt {attempt + 1}/{max_attempts})")
                    # Get next API key
                    new_key = self.api_key_manager.get_next_available_key()
                    if new_key:
                        # Recreate LLM with new key
                        self.llm = ChatGoogleGenerativeAI(
                            model=os.getenv("MODEL_NAME", "gemini-2.5-flash"),
                            temperature=0.3,
                            max_tokens=800,
                            api_key=new_key
                        )
                        continue
                
                # If not a quota error or last attempt, raise
                if attempt == max_attempts - 1:
                    raise
    
    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(RiskAgentState)
        workflow.add_node("calculate_risk", self.calculate_risk)
        workflow.add_node("generate_assessment", self.generate_assessment)
        workflow.set_entry_point("calculate_risk")
        workflow.add_edge("calculate_risk", "generate_assessment")
        workflow.add_edge("generate_assessment", END)
        return workflow.compile()
    
    async def calculate_risk(self, state: RiskAgentState) -> RiskAgentState:
        try:
            vuln_data = state["vulnerability_data"]
            cve_data = state.get("cve_data", {})
            severity = int(vuln_data.get('Severity', 3))
            cvss_score = float(cve_data.get('score', 0)) if cve_data.get('score') else 0
            trurisk_score = self._safe_float(vuln_data.get('TruRisk Score'))
            acs_score = self._safe_float(vuln_data.get('ACS'))
            is_pci = vuln_data.get('PCI Vuln', 'no').lower() == 'yes'
            times_detected = int(vuln_data.get('Times Detected', 1))
            detection_age = self._calculate_age(vuln_data.get('First Detected', ''))
            
            risk_score = self._fast_risk_score(
                severity, cvss_score, trurisk_score, acs_score, 
                detection_age, times_detected, is_pci
            )
            risk_category = self._get_risk_category(risk_score, severity, is_pci, acs_score)
            
            state["calculated_risk"] = {
                "risk_score": risk_score,
                "risk_category": risk_category,
                "severity": severity,
                "is_pci": is_pci,
                "acs_score": acs_score,
                "detection_age": detection_age,
                "times_detected": times_detected,
                "cvss_score": cvss_score
            }
            return state
        except Exception as e:
            state["error"] = f"Risk calculation error: {str(e)}"
            state["calculated_risk"] = {"risk_score": 5.0, "risk_category": "Medium", "is_pci": False}
            return state

    async def generate_assessment(self, state: RiskAgentState) -> RiskAgentState:
        try:
            vuln_data = state["vulnerability_data"]
            calculated_risk = state.get("calculated_risk", {})
            cve_data = state.get("cve_data", {})
            
            risk_details = await self._generate_risk_details(vuln_data, calculated_risk, cve_data)
            immediate_actions = self._generate_user_friendly_actions(vuln_data, calculated_risk)
            business_impact = self._generate_business_impact(vuln_data, calculated_risk, cve_data)
            exploitation_methods = await self._generate_exploitation_methods(vuln_data, cve_data)
            
            state["risk_assessment"] = RiskResult(
                risk_category=calculated_risk.get('risk_category', 'Medium'),
                risk_score=calculated_risk.get('risk_score', 5.0),
                risk_details=risk_details,
                business_impact=business_impact,
                remediation_urgency=self._get_urgency(calculated_risk.get('risk_category', 'Medium')),
                immediate_actions=immediate_actions,
                exploitation_methods=exploitation_methods
            )
            return state
        except Exception as e:
            print(f"LLM risk details generation error: {str(e)}")
            state["error"] = f"Assessment generation error: {str(e)}"
            calculated_risk = state.get("calculated_risk", {})
            vuln_data = state["vulnerability_data"]
            cve_data = state.get("cve_data", {})
            
            # Fallback assessment
            state["risk_assessment"] = RiskResult(
                risk_category=calculated_risk.get('risk_category', 'Medium'),
                risk_score=calculated_risk.get('risk_score', 5.0),
                risk_details=self._generate_fallback_risk_details(vuln_data, calculated_risk),
                business_impact=self._generate_business_impact(vuln_data, calculated_risk, cve_data),
                remediation_urgency=self._get_urgency(calculated_risk.get('risk_category', 'Medium')),
                immediate_actions=self._generate_user_friendly_actions(vuln_data, calculated_risk),
                exploitation_methods="Manual assessment required for exploitation details."
            )
            return state
    
    def _safe_float(self, value: Any) -> float:
        try:
            if value is None or value == '' or value == 'nan':
                return 0.0
            return float(value)
        except:
            return 0.0
    
    def _calculate_age(self, first_detected: str) -> int:
        try:
            if not first_detected or first_detected == 'nan':
                return 0
            detect_date = datetime.strptime(first_detected, "%d-%m-%Y %H:%M")
            return (datetime.now() - detect_date).days
        except:
            return 0
    
    def _fast_risk_score(self, severity: int, cvss: float, trurisk: float, 
                        acs: float, age: int, times_detected: int, is_pci: bool) -> float:
        base_score = severity * 2.0
        if cvss > 0:
            base_score = max(base_score, cvss)
        if trurisk > 0:
            base_score = max(base_score, min(trurisk / 100, 10))
        if acs >= 8:
            base_score = min(base_score + 2, 10)
        if age > 30:
            base_score = min(base_score + 0.5, 10)
        if times_detected > 5:
            base_score = min(base_score + 0.5, 10)
        if is_pci:
            base_score = min(base_score + 1.5, 10)
        return round(base_score, 1)
    
    def _get_risk_category(self, score: float, severity: int, is_pci: bool, acs: float) -> str:
        if is_pci and severity >= 3:
            return "Critical"
        if acs >= 8 and score >= 7:
            return "Critical"
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def _get_urgency(self, category: str) -> str:
        urgency_map = {
            "Critical": "🚨 Immediate Action Required (24 hours)",
            "High": "⚡ High Priority (72 hours)", 
            "Medium": "📅 Standard Priority (2 weeks)",
            "Low": "🔄 Low Priority (next maintenance cycle)"
        }
        return urgency_map.get(category, "📅 Standard Priority")
    
    async def _generate_risk_details(self, vuln_data: Dict, calculated_risk: Dict, cve_data: Dict) -> str:
        """Generate risk details with API key rotation support"""
        try:
            if HAS_API_KEY_MANAGER:
                # Use generate_content_with_fallback for automatic key rotation
                prompt = f"""
Analyze this security vulnerability and provide a concise risk assessment (max 150 words):

Vulnerability: {vuln_data.get('Title', 'Unknown')}
CVE: {cve_data.get('cve_id', 'N/A')}
Severity: {calculated_risk.get('risk_category', 'Unknown')} (Score: {calculated_risk.get('risk_score', 0)})
PCI Impact: {'Yes' if calculated_risk.get('is_pci') else 'No'}
Age: {calculated_risk.get('detection_age', 0)} days
Times Detected: {calculated_risk.get('times_detected', 1)}

Provide specific risk details focusing on:
1. Attack surface and exposure
2. Potential security impact
3. Compliance implications if PCI-related
"""
                response = generate_content_with_fallback(
                    prompt,
                    generation_config={'temperature': 0.3, 'max_output_tokens': 300}
                )
                return response.strip()
            else:
                # Use LLM with retry logic
                def _llm_call():
                    messages = [{"role": "user", "content": prompt}]
                    response = self.llm.invoke(messages)
                    return response.content.strip()
                
                return self._retry_llm_call_with_fallback(_llm_call)
                
        except Exception as e:
            print(f"LLM risk details generation error: {e}")
            return self._generate_fallback_risk_details(vuln_data, calculated_risk)
    
    def _generate_fallback_risk_details(self, vuln_data: Dict, calculated_risk: Dict) -> str:
        """Fallback risk details without LLM"""
        title = vuln_data.get('Title', 'Unknown')
        category = calculated_risk.get('risk_category', 'Medium')
        is_pci = calculated_risk.get('is_pci', False)
        age = calculated_risk.get('detection_age', 0)
        
        risk_parts = []
        risk_parts.append(f"{category} severity vulnerability: {title}.")
        
        if is_pci:
            risk_parts.append("PCI DSS compliance impact requires immediate remediation.")
        
        if age > 30:
            risk_parts.append(f"Vulnerability has been present for {age} days, increasing exposure risk.")
        
        risk_parts.append("Immediate security assessment and remediation recommended.")
        
        return " ".join(risk_parts)
    
    def _generate_user_friendly_actions(self, vuln_data: Dict, calculated_risk: Dict) -> List[str]:
        """Generate user-friendly immediate actions"""
        title = vuln_data.get('Title', '').lower()
        is_pci = calculated_risk.get('is_pci', False)
        
        if 'authentication' in title or 'login' in title:
            template = 'authentication'
        elif 'ssl' in title or 'tls' in title:
            template = 'ssl_tls'
        elif 'plaintext' in title or 'plain-text' in title:
            template = 'plaintext'
        elif 'web' in vuln_data.get('Category', '').lower():
            template = 'web_server'
        elif is_pci:
            template = 'pci_compliance'
        else:
            template = 'default'
        
        actions = self.action_templates.get(template, self.action_templates['default'])
        
        # Add emoji formatting
        formatted_actions = []
        emojis = ["🔒", "⚙️", "📊"]
        for i, action in enumerate(actions[:3]):
            emoji = emojis[i] if i < len(emojis) else "•"
            formatted_actions.append(f"{emoji} Step {i+1}: {action}")
        
        return formatted_actions
    
    def _generate_business_impact(self, vuln_data: Dict, calculated_risk: Dict, cve_data: Dict = None) -> str:
        """Generate business impact assessment"""
        category = calculated_risk.get('risk_category', 'Medium')
        is_pci = calculated_risk.get('is_pci', False)
        title = vuln_data.get('Title', 'Unknown')
        
        impact_parts = []
        
        # Base impact by category
        if category == 'Critical':
            impact_parts.append("Critical business risk requiring immediate attention.")
        elif category == 'High':
            impact_parts.append("High business risk requiring urgent remediation.")
        else:
            impact_parts.append(f"{category} business risk requiring planned remediation.")
        
        # PCI compliance impact
        if is_pci:
            impact_parts.append("PCI DSS compliance violation - potential for audit failures and penalties.")
        
        # Specific impacts based on vulnerability type
        if 'authentication' in title.lower() or 'login' in title.lower():
            impact_parts.append("Credential theft risk exposing user accounts and sensitive data.")
        elif 'plaintext' in title.lower():
            impact_parts.append("Data interception risk during transmission.")
        elif 'ssl' in title.lower() or 'tls' in title.lower():
            impact_parts.append("Encryption weakness allowing man-in-the-middle attacks.")
        
        return " ".join(impact_parts)
    
    async def _generate_exploitation_methods(self, vuln_data: Dict, cve_data: Dict) -> str:
        """Generate exploitation methods with API key rotation support"""
        try:
            if not cve_data or not cve_data.get('description'):
                return "Exploitation details require further investigation."
            
            if HAS_API_KEY_MANAGER:
                # Use generate_content_with_fallback for automatic key rotation
                prompt = f"""
Based on this CVE description, explain how an attacker could exploit this vulnerability (max 100 words):

CVE: {cve_data.get('cve_id', 'Unknown')}
Description: {cve_data.get('description', '')[:500]}

Provide specific exploitation methods focusing on:
1. Attack vector and prerequisites
2. Exploitation steps
3. Potential attacker gains
"""
                response = generate_content_with_fallback(
                    prompt,
                    generation_config={'temperature': 0.2, 'max_output_tokens': 200}
                )
                return response.strip()
            else:
                # Use LLM with retry logic
                def _llm_call():
                    messages = [{"role": "user", "content": prompt}]
                    response = self.llm.invoke(messages)
                    return response.content.strip()
                
                return self._retry_llm_call_with_fallback(_llm_call)
                
        except Exception as e:
            print(f"Exploitation methods generation error: {e}")
            return "Manual security assessment required to determine specific exploitation methods."
    
    async def assess_risk(self, vulnerability_data: Dict[str, Any], 
                         cve_data: Dict[str, Any] = None) -> RiskResult:
        
        initial_state = RiskAgentState(
            vulnerability_data=vulnerability_data,
            cve_data=cve_data or {},
            risk_assessment=None,
            calculated_risk={},
            error=""
        )
        
        try:
            result = await self.graph.ainvoke(initial_state)
            
            if result.get("error"):
                print(f"Assessment warning: {result['error']}")
            
            return result.get("risk_assessment")
            
        except Exception as e:
            print(f"Risk assessment error: {e}")
            
            # Fast fallback assessment
            severity = int(vulnerability_data.get('Severity', 3))
            is_pci = vulnerability_data.get('PCI Vuln', 'no').lower() == 'yes'
            
            category = "Critical" if is_pci and severity >= 3 else ("High" if severity >= 4 else "Medium")
            score = 8.0 if is_pci and severity >= 3 else (7.0 if severity >= 4 else 5.0)
            
            calculated_risk = {
                'risk_category': category,
                'is_pci': is_pci,
                'detection_age': 0,
                'times_detected': 1,
                'risk_score': score
            }
            
            return RiskResult(
                risk_category=category,
                risk_score=score,
                risk_details=self._generate_fallback_risk_details(vulnerability_data, calculated_risk),
                business_impact=self._generate_business_impact(vulnerability_data, calculated_risk, cve_data),
                remediation_urgency=self._get_urgency(category),
                immediate_actions=self._generate_user_friendly_actions(vulnerability_data, calculated_risk),
                exploitation_methods="Manual assessment required."
            )


# Initialize the agent
fast_risk_agent = FastVulnerabilityRiskAgent()

async def get_vulnerability_risk_assessment(original_data: Dict[str, Any], cve: Dict[str, Any] = None) -> RiskResult:
    """Get vulnerability risk assessment with API key rotation"""
    results = await fast_risk_agent.assess_risk(original_data, cve_data=cve)
    results_dict = results.to_dict()
    del results_dict['risk_score']
    return results_dict