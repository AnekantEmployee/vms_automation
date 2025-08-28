import asyncio
from datetime import datetime
from dotenv import load_dotenv
from dataclasses import dataclass
from pydantic import BaseModel, Field
from langchain_tavily import TavilySearch
from langgraph.graph import StateGraph, END
from typing import Dict, Any, List, TypedDict
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

class SimpleRiskAssessment(BaseModel):
    risk_category: str = Field(description="Risk level: Critical/High/Medium/Low")
    risk_score: float = Field(description="Risk score 0-10")
    business_impact: str = Field(description="Business impact summary")
    remediation_priority: str = Field(description="Remediation urgency")
    key_actions: List[str] = Field(description="Top 3 remediation actions")

@dataclass
class RiskResult:
    risk_category: str
    risk_score: float
    risk_details: str
    business_impact: str
    remediation_urgency: str
    immediate_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'risk_category': self.risk_category,
            'risk_score': self.risk_score,
            'risk_details': self.risk_details,
            'business_impact': self.business_impact,
            'remediation_urgency': self.remediation_urgency,
            'immediate_actions': self.immediate_actions
        }

class RiskAgentState(TypedDict):
    vulnerability_data: Dict[str, Any]
    cve_data: Dict[str, Any]
    risk_assessment: RiskResult
    calculated_risk: Dict[str, Any]
    error: str

class FastVulnerabilityRiskAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",  # Faster model
            temperature=0.3,
            max_tokens=800  # Reduced for faster response
        )
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
            state["risk_assessment"] = RiskResult(
                risk_category=calculated_risk.get('risk_category', 'Medium'),
                risk_score=calculated_risk.get('risk_score', 5.0),
                risk_details=risk_details,
                business_impact=business_impact,
                remediation_urgency=self._get_urgency(calculated_risk.get('risk_category', 'Medium')),
                immediate_actions=immediate_actions
            )
            return state
        except Exception as e:
            state["error"] = f"Assessment generation error: {str(e)}"
            calculated_risk = state.get("calculated_risk", {})
            vuln_data = state["vulnerability_data"]
            cve_data = state.get("cve_data", {})
            risk_details = await self._generate_risk_details(vuln_data, calculated_risk, cve_data)
            state["risk_assessment"] = RiskResult(
                risk_category=calculated_risk.get('risk_category', 'Medium'),
                risk_score=calculated_risk.get('risk_score', 5.0),
                risk_details=risk_details,
                business_impact="Potential security exposure requiring immediate attention",
                remediation_urgency=self._get_urgency(calculated_risk.get('risk_category', 'Medium')),
                immediate_actions=self._generate_user_friendly_actions(vuln_data, calculated_risk)
            )
            return state

    async def _search_cve_context(self, cve_data: Dict) -> str:
        if not cve_data:
            return ""
        cve_id = cve_data.get('cve_id', '')
        if not cve_id:
            return ""
        try:
            search_query = f"{cve_id} vulnerability impact business risk remediation"
            search_results = await self.tavily_search.ainvoke({"query": search_query})
            context_info = []
            for result in search_results:
                if isinstance(result, dict):
                    content = result.get('content', '')
                    if content and len(content) > 50:
                        context_info.append(content[:300])
            return " ".join(context_info[:2])
        except Exception as e:
            print(f"Tavily search error for {cve_id}: {e}")
            return ""

    async def _generate_risk_details(self, vuln_data: Dict, calculated_risk: Dict, cve_data: Dict = None) -> str:
        try:
            context = {
                "vulnerability_title": vuln_data.get('Title', 'Unknown'),
                "asset": vuln_data.get('DNS', vuln_data.get('IP', 'Unknown asset')),
                "risk_category": calculated_risk.get('risk_category', 'Medium'),
                "detection_age": calculated_risk.get('detection_age', 0),
                "is_pci": calculated_risk.get('is_pci', False)
            }
            if cve_data:
                context.update({
                    "cve_id": cve_data.get('cve_id', ''),
                    "cve_description": cve_data.get('description', ''),
                    "cvss_score": cve_data.get('score', 0),
                    "severity": cve_data.get('severity', 'UNKNOWN'),
                    "cwe_info": cve_data.get('cwe_info', []),
                    "vector_string": cve_data.get('vector_string', '')
                })
            try:
                external_context = await self._search_cve_context(cve_data)
            except Exception as e:
                print(f"External context error: {e}")
                external_context = ""
            prompt = f"""
            Generate a clear, professional risk assessment summary for this vulnerability:

            Vulnerability Context:
            - Title: {context['vulnerability_title']}
            - Asset: {context['asset']}
            - Risk Category: {context['risk_category']}
            - Days Since Detection: {context['detection_age']}
            - PCI Compliance Impact: {context['is_pci']}

            CVE Details:
            - CVE ID: {context.get('cve_id', 'N/A')}
            - CVSS Score: {context.get('cvss_score', 'N/A')}
            - Severity: {context.get('severity', 'N/A')}
            - Description: {context.get('cve_description', 'N/A')[:200]}
            - CWE Categories: {context.get('cwe_info', [])}

            External Research Context:
            {external_context[:400] if external_context else 'No additional context available'}

            Generate a 2-3 sentence risk summary that:
            1. Explains the specific security risk in business terms
            2. Mentions the CVE ID and key technical details
            3. Emphasizes the urgency based on the risk category
            4. Avoids generic language - be specific to this vulnerability type

            Keep it professional, actionable, and under 150 words.
            """
            response = self.llm.invoke(prompt)
            return response.content.strip()
        except Exception as e:
            print(f"LLM risk details generation error: {e}")
            asset = vuln_data.get('DNS', vuln_data.get('IP', 'Unknown asset'))
            category = calculated_risk.get('risk_category', 'Medium')
            cve_id = cve_data.get('cve_id', 'Unknown CVE') if cve_data else 'vulnerability'
            return f"{category} risk vulnerability on {asset} related to {cve_id}. This security gap requires prompt remediation to maintain system integrity."

    def _generate_business_impact(self, vuln_data: Dict, calculated_risk: Dict, cve_data: Dict = None) -> str:
        """Generate LLM-powered business impact assessment with external research"""
        try:
            vulnerability_title = vuln_data.get('Title', 'Unknown vulnerability')
            risk_category = calculated_risk.get('risk_category', 'Medium')
            is_pci = calculated_risk.get('is_pci', False)
            asset_info = vuln_data.get('DNS', vuln_data.get('IP', 'Unknown asset'))
            cve_context = ""
            if cve_data:
                cve_id = cve_data.get('cve_id', '')
                cvss_score = cve_data.get('score', 0)
                cve_description = cve_data.get('description', '')
                affected_products = cve_data.get('affected_products', [])
                
                # Get external research about this CVE's business impact
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # If loop is already running, create a task
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(asyncio.run, self._search_business_impact_context(cve_id, vulnerability_title))
                            external_research = future.result(timeout=10)
                    else:
                        external_research = loop.run_until_complete(self._search_business_impact_context(cve_id, vulnerability_title))
                except Exception as e:
                    print(f"External research error: {e}")
                    external_research = ""
                
                cve_context = f"""
                CVE Details:
                - CVE ID: {cve_id}
                - CVSS Score: {cvss_score}/10
                - Description: {cve_description[:300]}
                - Affected Products: {', '.join(affected_products[:2])}
                
                External Research:
                {external_research[:500] if external_research else 'Limited external context available'}
                """
            
            # Create comprehensive prompt for LLM
            prompt = f"""
            You are a cybersecurity risk analyst. Generate a specific, actionable business impact assessment for this vulnerability.
            
            Vulnerability Information:
            - Title: {vulnerability_title}
            - Asset: {asset_info}
            - Risk Category: {risk_category}
            - PCI Compliance Impact: {'Yes - Critical for payment processing' if is_pci else 'No'}
            
            {cve_context}
            
            Generate a business impact statement that:
            1. Starts with "Risk of" 
            2. Identifies specific, measurable business consequences (avoid generic terms like "data breach")
            3. Considers financial, operational, regulatory, and reputational impacts
            4. Is relevant to the specific vulnerability type and affected systems
            5. Mentions compliance implications if PCI is involved
            6. Uses concrete business language that executives would understand
            7. Limits to 2-3 specific, high-impact consequences
            
            Examples of good business impacts:
            - "Risk of unauthorized access to payment processing systems leading to PCI DSS compliance violations ($50K-$500K fines), customer payment data exposure resulting in mandatory breach notification costs, and potential suspension of merchant processing capabilities."
            - "Risk of service disruption to critical monitoring infrastructure causing inability to detect security incidents, loss of operational visibility leading to extended MTTR, and potential SLA violations with downstream service impacts."
            
            Keep the response under 200 words and focus on the most severe, realistic business consequences.
            """
            
            # Generate business impact using LLM
            response = self.llm.invoke(prompt)
            business_impact = response.content.strip()
            
            # Ensure it starts with "Risk of" and clean up any formatting
            if not business_impact.lower().startswith('risk of'):
                business_impact = f"Risk of {business_impact.lower()}"
            
            # Remove any quotes or extra formatting
            business_impact = business_impact.replace('"', '').replace('*', '').strip()
            
            return business_impact
            
        except Exception as e:
            print(f"LLM business impact generation error: {e}")
            
            # Enhanced fallback based on available data
            if cve_data:
                cve_id = cve_data.get('cve_id', 'this vulnerability')
                cvss_score = cve_data.get('score', 0)
                if cvss_score >= 9.0:
                    severity_impact = "critical system compromise and immediate business disruption"
                elif cvss_score >= 7.0:
                    severity_impact = "significant security exposure and potential service disruption"
                else:
                    severity_impact = "moderate security risk and operational impact"
            else:
                severity_impact = "security vulnerabilities and potential business disruption"
            
            pci_impact = " including PCI compliance violations and potential regulatory fines" if calculated_risk.get('is_pci', False) else ""
            
            return f"Risk of {severity_impact}{pci_impact}, leading to potential financial losses and reputational damage."

    async def _search_business_impact_context(self, cve_id: str, vulnerability_title: str) -> str:
        """Search for business impact context using Tavily"""
        if not cve_id and not vulnerability_title:
            return ""
        
        try:
            # Create targeted search query for business impact
            if cve_id:
                search_query = f"{cve_id} business impact financial cost compliance regulatory"
            else:
                search_query = f"{vulnerability_title} cybersecurity business impact financial losses"
            
            search_results = await self.tavily_search.ainvoke({"query": search_query})
            
            # Extract business-relevant information
            business_context = []
            keywords = [
                'business impact', 'financial', 'cost', 'compliance', 'regulatory', 
                'fine', 'penalty', 'revenue', 'operational', 'customer', 'reputation',
                'pci', 'gdpr', 'sox', 'hipaa', 'downtime', 'sla'
            ]
            
            for result in search_results:
                if isinstance(result, dict):
                    content = result.get('content', '').lower()
                    url = result.get('url', '')
                    
                    # Prioritize authoritative sources
                    if any(domain in url for domain in ['nist.gov', 'cisa.gov', 'nvd.nist.gov', 'sec.gov']):
                        weight = 2
                    else:
                        weight = 1
                    
                    # Extract sentences containing business impact keywords
                    sentences = content.split('. ')
                    relevant_sentences = []
                    
                    for sentence in sentences:
                        keyword_count = sum(1 for keyword in keywords if keyword in sentence)
                        if keyword_count >= 2:  # Sentence must contain at least 2 business keywords
                            relevant_sentences.append(sentence.strip())
                    
                    if relevant_sentences:
                        # Take top sentences based on weight
                        business_context.extend(relevant_sentences[:2 * weight])
            
            # Combine and limit the context
            combined_context = '. '.join(business_context[:3])  # Top 3 most relevant pieces
            return combined_context[:600]  # Limit length
            
        except Exception as e:
            print(f"Tavily business impact search error: {e}")
            return ""
    
    def _generate_user_friendly_actions(self, vuln_data: Dict, calculated_risk: Dict) -> List[str]:
        """Generate clear, actionable remediation steps"""
        title = vuln_data.get('Title', '').lower()
        is_pci = calculated_risk.get('is_pci', False)
        category = calculated_risk.get('risk_category', 'Medium')
        
        actions = []
        
        # Match vulnerability type to appropriate actions
        if 'plaintext' in title or 'plain-text' in title:
            if 'authentication' in title or 'login' in title or 'form' in title:
                actions.extend(self.action_templates['authentication'])
            else:
                actions.extend(self.action_templates['plaintext'])
        elif 'ssl' in title or 'tls' in title or 'certificate' in title:
            actions.extend(self.action_templates['ssl_tls'])
        elif 'web' in title or 'server' in title:
            actions.extend(self.action_templates['web_server'])
        else:
            actions.extend(self.action_templates['default'])
        
        # Add PCI-specific actions if needed
        if is_pci and len(actions) < 3:
            actions.insert(0, self.action_templates['pci_compliance'][0])
        
        # Prioritize based on risk category
        if category == 'Critical':
            actions.insert(0, "⚠️ URGENT: Isolate affected system until patched")
        
        # Ensure exactly 3 actions and make them more user-friendly
        final_actions = []
        for i, action in enumerate(actions[:3]):
            if i < 3:
                # Add step numbers and emojis for clarity
                emoji = "🔒" if i == 0 else ("⚙️" if i == 1 else "📊")
                final_actions.append(f"{emoji} Step {i+1}: {action}")
        
        # Fill remaining slots if needed
        while len(final_actions) < 3:
            remaining_actions = [
                "🔄 Step 2: Verify security configurations are properly implemented",
                "📋 Step 3: Schedule regular security monitoring and validation"
            ]
            for action in remaining_actions:
                if action not in final_actions and len(final_actions) < 3:
                    final_actions.append(action)
        
        return final_actions[:3]
    
    def _safe_float(self, value) -> float:
        try:
            if value is None or str(value).lower() in ['nan', 'n/a', '']:
                return 0.0
            return float(value)
        except:
            return 0.0
    
    def _calculate_age(self, first_detected: str) -> int:
        try:
            if not first_detected or first_detected.lower() == 'nan':
                return 0
            date = datetime.strptime(first_detected.split()[0], "%m-%d-%Y")
            return (datetime.now() - date).days
        except:
            return 0
    
    def _fast_risk_score(self, severity: int, cvss: float, trurisk: float, 
                        acs: float, age: int, detections: int, is_pci: bool) -> float:
        
        base = (severity / 5.0) * 4.0
        cvss_factor = (cvss / 10.0) * 3.0 if cvss > 0 else 0
        acs_factor = (min(acs, 10) / 10.0) * 2.0 if acs > 0 else 0
        persistence = min(detections / 3, 0.5) + min(age / 180, 0.5)
        pci_boost = 1.5 if is_pci and base >= 3.0 else 0
        
        score = base + cvss_factor + acs_factor + persistence + pci_boost
        return min(max(score, 0), 10)
    
    def _get_risk_category(self, score: float, severity: int, is_pci: bool, acs: float) -> str:
        if is_pci and (score >= 6.0 or severity >= 4):
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
                'times_detected': 1
            }
            
            return RiskResult(
                risk_category=category,
                risk_score=score,
                risk_details=self._generate_risk_details(vulnerability_data, calculated_risk),
                business_impact=self._generate_business_impact(vulnerability_data, calculated_risk),
                remediation_urgency=self._get_urgency(category),
                immediate_actions=self._generate_user_friendly_actions(vulnerability_data, calculated_risk)
            )


# Initialize the agent
fast_risk_agent = FastVulnerabilityRiskAgent()

async def get_vulnerability_risk_assessment(original_data: Dict[str, Any], cve: Dict[str, Any] = None) -> RiskResult:
    results = await fast_risk_agent.assess_risk(original_data, cve_data=cve)
    results = results.to_dict()
    del results['risk_score']
    return results

cve_data = {
  "cve_id": "CVE-2021-41090",
  "description": "Grafana Agent is a telemetry collector for sending metrics, logs, and trace data to the opinionated Grafana observability stack. Prior to versions 0.20.1 and 0.21.2, inline secrets defined within a metrics instance config are exposed in plaintext over two endpoints: metrics instance configs defined in the base YAML file are exposed at `/-/config` and metrics instance configs defined for the scraping service are exposed at `/agent/api/v1/configs/:key`. Inline secrets will be exposed to anyone being able to reach these endpoints. If HTTPS with client authentication is not configured, these endpoints are accessible to unauthenticated users. Secrets found in these sections are used for delivering metrics to a Prometheus Remote Write system, authenticating against a system for discovering Prometheus targets, and authenticating against a system for collecting metrics. This does not apply for non-inlined secrets, such as `*_file` based secrets. This issue is patched in Grafana Agent versions 0.20.1 and 0.21.2. A few workarounds are available. Users who cannot upgrade should use non-inline secrets where possible. Users may also desire to restrict API access to Grafana Agent with some combination of restricting the network interfaces Grafana Agent listens on through `http_listen_address` in the `server` block, configuring Grafana Agent to use HTTPS with client authentication, and/or using firewall rules to restrict external access to Grafana Agent's API.",
     "severity": "MEDIUM",
  "published_date": "2021-12-08T17:15:11.093",
  "modified_date": "2024-11-21T06:25:26.367",
  "score": 6.5,
  "source": "NIST NVD",
  "vuln_status": "Unknown",
  "cwe_info": [
    "CWE-200",
    "CWE-312"
  ],
  "affected_products": [
    "cpe:2.3:a:grafana:agent:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:grafana:agent:*:*:*:*:*:*:*:*"
  ],
  "references": [
    "https://github.com/grafana/agent/commit/af7fb01e31fe2d389e5f1c36b399ddc46b412b21",
    "https://github.com/grafana/agent/pull/1152",
    "https://github.com/grafana/agent/releases/tag/v0.20.1",
    "https://github.com/grafana/agent/releases/tag/v0.21.2",
    "https://github.com/grafana/agent/security/advisories/GHSA-9c4x-5hgq-q3wh",
    "https://security.netapp.com/advisory/ntap-20211229-0004/",
    "https://github.com/grafana/agent/commit/af7fb01e31fe2d389e5f1c36b399ddc46b412b21",
    "https://github.com/grafana/agent/pull/1152",
    "https://github.com/grafana/agent/releases/tag/v0.20.1",
    "https://github.com/grafana/agent/releases/tag/v0.21.2",
    "https://github.com/grafana/agent/security/advisories/GHSA-9c4x-5hgq-q3wh",
           "https://security.netapp.com/advisory/ntap-20211229-0004/"
  ],
  "exploitability_score": 0.0,
  "impact_score": 0.0,
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
  "cvss_version": "3.1",
  "confidence_score": 7.0
}
original_data = {
 "IP": "10.6.16.50",
 "Network": "Yash_Internal",
 "DNS": "apps.example.com",
 "NetBIOS": "nan",
 "QG Host ID": "nan",
 "IP Interfaces": "nan",
 "Tracking Method": "IP",
 "OS": "EulerOS / Ubuntu / Fedora / Tiny Core Linux / Linux 3.x / IBM / FortiSOAR / F5 Networks Big-IP",
 "IP Status": "host scanned, found vuln",
 "QID": "86728",
 "Title": "Web Server Uses Plain-Text Form Based Authentication",
 "Vuln Status": "Active",
 "Type": "Vuln",
 "Severity": "3","Port": "8000",
 "Protocol": "tcp",
 "FQDN": "nan",
 "SSL": "nan",
 "First Detected": "07-01-2025 05:19",
 "Last Detected": "08-01-2025 05:18",
 "Times Detected": "2",
 "Date Last Fixed": "nan",
 "First Reopened": "nan",
 "Last Reopened": "nan",
 "Times Reopened": "nan",
 "CVE ID": "nan",
 "Vendor Reference": "nan",
 "Bugtraq ID": "nan",
 "Threat": "The Web server uses plain-text form based authentication. A web page exists on the target host which uses an HTML login form. This data is sent from the client to the server in plain-text.",
 "Impact": "An attacker with access to the network traffic to and from the target host may be able to obtain login credentials for other users by sniffing the network traffic.",
 "Solution": "Please contact the vendor of the hardware/software for a possible fix for the issue. For custom applications, ensure that data sent via HTML login forms is encrypted before being sent from the client to the host.",
 "Exploitability": "nan",
 "Associated Malware": "nan",
  "Results": "GET /OA_HTML/AppsLocalLogin.jsp HTTP/1.1\nHost: apps.example.com:8000\nConnection: Keep-Alive\n\n<form id=login>\n<div id=UsernameBox class=\"control_box min_margin\">\n<label for=\"usernameField\" message=FND_SSO_USER_NAME>User Name</label>\n<input tabindex=0 type=\"text\" id=\"usernameField\" name=\"usernameField\" class=\"inp\" value=\"\" message=FND_SSO_USER_NAME >\n\n</div>\n\n<div class=\"control_box min_margin\" id=logoutLink style='display:none'><a tabindex=0 name=logout message=FND_SSO_NOTSAME_USER onclick='confirmLogout()'> Not the same user?</a></div>\n<div class=\"control_box min_margin\">\n<label for=\"passwordField\" message=FND_SSO_PASSWORD>Password</label>\n<input tabindex=0 class=\"inp\" type=\"password\" id=\"passwordField\" name=\"passwordField\" value=\"\" message=FND_SSO_PASSWORD >\n</div>\n</form>#",
 "PCI Vuln": "yes",
 "Ticket State": "nan",
 "Instance": "nan",
 "Category": "Web server",
 "Associated Ags": "Linux Device",
 "Host ID": "24544681",
 "Asset ID": "65832486",
 "QDS": "30",
 "ARS": "861",
 "ACS": "5",
 "TruRisk Score": "861"
}

if __name__ == "__main__":
    print(asyncio.run(get_vulnerability_risk_assessment(original_data, cve=cve_data)))