from typing import Dict, Any, List, TypedDict, Optional
from dataclasses import dataclass
import asyncio
from datetime import datetime
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.schema import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field
from dotenv import load_dotenv

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
    
class RiskAgentState(TypedDict):
    vulnerability_data: Dict[str, Any]
    cve_data: Dict[str, Any]
    risk_assessment: RiskResult
    calculated_risk: Dict[str, Any]
    error: str

class FastVulnerabilityRiskAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            temperature=0.1,
            max_tokens=800
        )
        self.graph = self._build_graph()
    
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
                "detection_age": detection_age
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
            
            prompt = f"""
            Vulnerability Risk Assessment:
            
            Asset: {vuln_data.get('DNS', vuln_data.get('IP', 'Unknown'))}
            Title: {vuln_data.get('Title', 'Unknown')}
            Severity: {vuln_data.get('Severity', 'N/A')}
            CVE: {vuln_data.get('CVE ID', 'N/A')}
            PCI Impact: {vuln_data.get('PCI Vuln', 'No')}
            Asset Critical Score: {vuln_data.get('ACS', 'N/A')}
            Detection Age: {calculated_risk.get('detection_age', 0)} days
            
            Calculated Risk: {calculated_risk.get('risk_category', 'Medium')} ({calculated_risk.get('risk_score', 5.0)}/10)
            
            Provide brief assessment:
            1. Business impact in 1-2 sentences
            2. Top 3 immediate remediation actions
            
            Keep response concise and actionable.
            """
            
            response = await self.llm.ainvoke([
                SystemMessage(content="You are a cybersecurity analyst. Provide concise, actionable risk assessments."),
                HumanMessage(content=prompt)
            ])
            
            state["risk_assessment"] = RiskResult(
                risk_category=calculated_risk.get('risk_category', 'Medium'),
                risk_score=calculated_risk.get('risk_score', 5.0),
                risk_details=self._extract_business_impact(response.content),
                business_impact=self._extract_business_impact(response.content),
                remediation_urgency=self._get_urgency(calculated_risk.get('risk_category', 'Medium')),
                immediate_actions=self._extract_actions(response.content, vuln_data)
            )
            
            return state
            
        except Exception as e:
            state["error"] = f"Assessment generation error: {str(e)}"
            calculated_risk = state.get("calculated_risk", {})
            
            state["risk_assessment"] = RiskResult(
                risk_category=calculated_risk.get('risk_category', 'Medium'),
                risk_score=calculated_risk.get('risk_score', 5.0),
                risk_details=f"Risk assessment for {vuln_data.get('Title', 'vulnerability')} requires immediate attention",
                business_impact="Potential security exposure requiring remediation",
                remediation_urgency=self._get_urgency(calculated_risk.get('risk_category', 'Medium')),
                immediate_actions=self._get_default_actions(vuln_data)
            )
            return state
    
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
            "Critical": "Immediate (24 hours)",
            "High": "High Priority (72 hours)", 
            "Medium": "Standard (2 weeks)",
            "Low": "Low Priority (next cycle)"
        }
        return urgency_map.get(category, "Standard Priority")
    
    def _extract_business_impact(self, response: str) -> str:
        lines = response.split('\n')
        impact_lines = [line for line in lines if 'impact' in line.lower() or 'business' in line.lower()]
        return impact_lines[0].strip() if impact_lines else "Security vulnerability requiring remediation"
    
    def _extract_actions(self, response: str, vuln_data: Dict) -> List[str]:
        try:
            lines = [line.strip() for line in response.split('\n') if line.strip()]
            actions = [line for line in lines if any(word in line.lower() for word in ['implement', 'deploy', 'configure', 'update', 'patch', 'install', 'enable', 'disable', 'remove'])]
            
            clean_actions = []
            for action in actions[:5]:
                if len(action) > 20 and len(action) < 100:
                    clean_actions.append(action.replace('*', '').replace('-', '').strip())
                    
            return clean_actions[:3] if clean_actions else self._get_default_actions(vuln_data)
        except:
            return self._get_default_actions(vuln_data)
    
    def _get_default_actions(self, vuln_data: Dict) -> List[str]:
        title = vuln_data.get('Title', '').lower()
        is_pci = vuln_data.get('PCI Vuln', 'no').lower() == 'yes'
        
        actions = []
        
        if 'authentication' in title or 'login' in title:
            actions.append("Implement secure authentication mechanisms with encryption")
        if 'ssl' in title or 'tls' in title or 'certificate' in title:
            actions.append("Update SSL/TLS certificates and configuration")
        if 'plaintext' in title or 'password' in title:
            actions.append("Enable password encryption and secure transmission")
        if is_pci:
            actions.append("Address PCI DSS compliance requirements immediately")
        if 'web' in title or 'http' in title:
            actions.append("Secure web server configuration and access controls")
        
        while len(actions) < 3:
            if len(actions) == 0:
                actions.append("Apply security patches and updates immediately")
            elif len(actions) == 1:
                actions.append("Review and harden system configuration settings")
            else:
                actions.append("Implement continuous monitoring and validation")
        
        return actions[:3]
    
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
            
            severity = int(vulnerability_data.get('Severity', 3))
            is_pci = vulnerability_data.get('PCI Vuln', 'no').lower() == 'yes'
            
            category = "Critical" if is_pci and severity >= 3 else ("High" if severity >= 4 else "Medium")
            score = 8.0 if is_pci and severity >= 3 else (7.0 if severity >= 4 else 5.0)
            
            return RiskResult(
                risk_category=category,
                risk_score=score,
                risk_details=f"Security vulnerability requiring {category.lower()} priority attention",
                business_impact="Potential security exposure" + (" with compliance impact" if is_pci else ""),
                remediation_urgency=self._get_urgency(category),
                immediate_actions=self._get_default_actions(vulnerability_data)
            )

fast_risk_agent = FastVulnerabilityRiskAgent()

async def get_vulnerability_risk_assessment(original_data: Dict[str, Any], cve_data: Dict[str, Any] = None) -> RiskResult:
    return await fast_risk_agent.assess_risk(original_data, cve_data)


# Usage example:
cve_data =  {
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
  "Severity": "3",
  "Port": "8000",
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

async def main():
    # Now you can use await
    
    risk_assessment = await get_vulnerability_risk_assessment(original_data, cve_data)
    print(risk_assessment)


# Run the async function
if __name__ == "__main__":
    asyncio.run(main())