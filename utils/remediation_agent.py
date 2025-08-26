from typing import Dict, Any, List, TypedDict
from dataclasses import dataclass
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.schema import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from tavily import TavilyClient
from pydantic import BaseModel, Field
from langchain.output_parsers import PydanticOutputParser
from .export_utils import clean_value
from dotenv import load_dotenv
import streamlit as st

load_dotenv()

# Pydantic models for structured output
class ImmediateActions(BaseModel):
    actions: List[str] = Field(description="List of immediate actions to take")

class DetailedSteps(BaseModel):
    steps: List[str] = Field(description="Detailed step-by-step remediation instructions")

class VerificationSteps(BaseModel):
    steps: List[str] = Field(description="Steps to verify the remediation was successful")

class RollbackPlan(BaseModel):
    plan: List[str] = Field(description="Rollback plan if remediation causes issues")

class RemediationGuide(BaseModel):
    remediation_guide: str = Field(description="Comprehensive remediation guide text")
    priority: str = Field(description="Priority level: Critical/High/Medium/Low")
    estimated_effort: str = Field(description="Estimated time required for remediation")
    immediate_actions: List[str] = Field(description="List of immediate actions to take")
    detailed_steps: List[str] = Field(description="Detailed step-by-step instructions")
    verification_steps: List[str] = Field(description="Steps to verify the fix")
    additional_measures: List[str] = Field(description="Additional security measures")
    rollback_plan: List[str] = Field(description="Rollback plan if needed")
    references: List[str] = Field(description="Reference URLs and resources")

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

class AgentState(TypedDict):
    vulnerability_data: Dict[str, Any]
    cve_info: Dict[str, Any]
    remediation_result: RemediationResult
    search_results: List[Dict[str, Any]]
    error: str

class VulnerabilityRemediationAgent:
    """LangGraph agent for generating vulnerability remediation guides per CVE"""
    
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            temperature=0.1
        )
        self.tavily_client = TavilyClient()
        
        # Initialize output parsers
        self.remediation_parser = PydanticOutputParser(pydantic_object=RemediationGuide)
        
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("analyze_vulnerability", self.analyze_vulnerability)
        workflow.add_node("search_remediation_info", self.search_remediation_info)
        workflow.add_node("generate_remediation_guide", self.generate_remediation_guide)
        workflow.add_node("validate_and_enhance", self.validate_and_enhance)
        
        # Add edges
        workflow.set_entry_point("analyze_vulnerability")
        workflow.add_edge("analyze_vulnerability", "search_remediation_info")
        workflow.add_edge("search_remediation_info", "generate_remediation_guide")
        workflow.add_edge("generate_remediation_guide", "validate_and_enhance")
        workflow.add_edge("validate_and_enhance", END)
        
        return workflow.compile()
    
    async def analyze_vulnerability(self, state: AgentState) -> AgentState:
        """Analyze vulnerability data to understand the context for specific CVE"""
        try:
            vuln_data = state["vulnerability_data"]
            cve_info = state["cve_info"]
            
            analysis_prompt = f"""
            Analyze this CVE vulnerability for remediation planning:
            
            CVE ID: {cve_info.get('cve_id', 'Unknown')}
            CVSS Score: {cve_info.get('score', 'N/A')}
            CVE Severity: {cve_info.get('severity', 'Unknown')}
            Description: {cve_info.get('description', '')[:500]}...
            
            Vulnerability Context:
            Title: {vuln_data.get('title', 'Unknown')}
            QID: {vuln_data.get('qid', 'N/A')}
            Base Severity: {vuln_data.get('severity', 'Unknown')}
            OS: {vuln_data.get('os', 'Unknown')}
            Category: {vuln_data.get('category', 'Unknown')}
            Port: {vuln_data.get('port', 'N/A')}
            Protocol: {vuln_data.get('protocol', 'N/A')}
            
            Provide a brief analysis focusing on:
            1. Root cause analysis for this specific CVE
            2. Attack vectors and exploitation methods
            3. Potential business impact
            4. Remediation complexity and dependencies
            5. Affected components and systems
            """
            
            response = await self.llm.ainvoke([
                SystemMessage(content="You are a cybersecurity expert specializing in CVE analysis and remediation."),
                HumanMessage(content=analysis_prompt)
            ])
            
            state["cve_analysis"] = response.content
            return state
            
        except Exception as e:
            state["error"] = f"Analysis error: {str(e)}"
            return state
    
    async def search_remediation_info(self, state: AgentState) -> AgentState:
        """Search for CVE-specific remediation information"""
        try:
            cve_info = state["cve_info"]
            
            # Construct CVE-specific search queries
            search_queries = []
            
            if cve_info.get('cve_id'):
                search_queries.extend([
                    f"{cve_info['cve_id']} remediation guide",
                    f"{cve_info['cve_id']} patch fix steps",
                    f"{cve_info['cve_id']} mitigation techniques",
                    f"{cve_info['cve_id']} workaround solutions"
                ])
            
            # Add OS-specific queries
            vuln_data = state["vulnerability_data"]
            if vuln_data.get('os'):
                search_queries.append(f"{cve_info.get('cve_id', '')} {vuln_data['os']} fix")
            
            all_results = []
            
            for query in search_queries[:5]:  # Limit to 5 searches
                try:
                    results = self.tavily_client.search(
                        query=query,
                        search_depth="advanced",
                        max_results=3
                    )
                    all_results.extend(results.get('results', []))
                except Exception as search_error:
                    print(f"Search error for query '{query}': {search_error}")
            
            state["search_results"] = all_results
            return state
            
        except Exception as e:
            state["error"] = f"Search error: {str(e)}"
            state["search_results"] = []
            return state
    
    async def generate_remediation_guide(self, state: AgentState) -> AgentState:
        """Generate comprehensive remediation guide for specific CVE"""
        try:
            vuln_data = state["vulnerability_data"]
            cve_info = state["cve_info"]
            search_results = state.get("search_results", [])
            analysis = state.get("cve_analysis", "")
            
            # Prepare search context
            search_context = ""
            references = []
            
            for result in search_results:
                search_context += f"Source: {result.get('title', 'Unknown')}\n"
                search_context += f"Content: {result.get('content', '')[:300]}...\n"
                search_context += f"URL: {result.get('url', '')}\n\n"
                
                if result.get('url'):
                    references.append(result['url'])
            
            # Get format instructions for structured output
            format_instructions = self.remediation_parser.get_format_instructions()
            
            remediation_prompt = f"""
            Generate a comprehensive, step-by-step remediation guide specifically for CVE: {cve_info.get('cve_id', 'Unknown')}
            
            CVE DETAILS:
            CVE ID: {cve_info.get('cve_id', 'Unknown')}
            CVSS Score: {cve_info.get('score', 'N/A')}
            Severity: {cve_info.get('severity', 'N/A')}
            Description: {cve_info.get('description', 'N/A')}
            
            VULNERABILITY CONTEXT:
            Title: {vuln_data.get('title', 'Unknown')}
            QID: {vuln_data.get('qid', 'N/A')}
            Base Severity: {vuln_data.get('severity', 'Unknown')}
            Operating System: {vuln_data.get('os', 'Unknown')}
            Category: {vuln_data.get('category', 'Unknown')}
            Port: {vuln_data.get('port', 'N/A')}
            Protocol: {vuln_data.get('protocol', 'N/A')}
            
            ANALYSIS:
            {analysis}
            
            SEARCH RESULTS:
            {search_context}
            
            Please provide a detailed, actionable remediation guide with specific steps.
            
            {format_instructions}
            """
            
            response = await self.llm.ainvoke([
                SystemMessage(content="You are a senior cybersecurity consultant. Provide specific, actionable remediation guidance for CVEs. Focus on step-by-step instructions."),
                HumanMessage(content=remediation_prompt)
            ])
            
            # Parse structured response
            try:
                parsed_response = self.remediation_parser.parse(response.content)
                
                state["remediation_result"] = RemediationResult(
                    remediation_guide=parsed_response.remediation_guide,
                    priority=parsed_response.priority,
                    estimated_effort=parsed_response.estimated_effort,
                    references=references[:5] + parsed_response.references,
                    additional_resources=self._get_additional_resources(vuln_data, cve_info),
                    immediate_actions=parsed_response.immediate_actions,
                    detailed_steps=parsed_response.detailed_steps,
                    verification_steps=parsed_response.verification_steps,
                    rollback_plan=parsed_response.rollback_plan
                )
                
            except Exception as parse_error:
                print(f"Parser error: {parse_error}, falling back to unstructured")
                # Fallback if parsing fails
                state["remediation_result"] = RemediationResult(
                    remediation_guide=response.content,
                    priority=self._determine_priority(vuln_data, cve_info),
                    estimated_effort=self._estimate_effort(vuln_data, cve_info),
                    references=references[:5],
                    additional_resources=self._get_additional_resources(vuln_data, cve_info),
                    immediate_actions=["1. Isolate affected systems", "2. Apply available patches", "3. Monitor for exploitation"],
                    detailed_steps=["Refer to vendor documentation for specific patch application steps"],
                    verification_steps=["Verify patch installation", "Test system functionality", "Run vulnerability scan"],
                    rollback_plan=["Have backup ready", "Test in staging first", "Document rollback procedure"]
                )
            
            return state
            
        except Exception as e:
            state["error"] = f"Generation error: {str(e)}"
            # Provide fallback remediation
            state["remediation_result"] = RemediationResult(
                remediation_guide=f"Manual remediation required for CVE {cve_info.get('cve_id', 'Unknown')}. Consult vendor documentation.",
                priority=self._determine_priority(vuln_data, cve_info),
                estimated_effort=self._estimate_effort(vuln_data, cve_info),
                references=[],
                additional_resources=self._get_additional_resources(vuln_data, cve_info),
                immediate_actions=["1. Review CVE details", "2. Check for available patches", "3. Assess impact"],
                detailed_steps=["Check vendor security advisories", "Apply recommended patches", "Test changes"],
                verification_steps=["Verify patch installation", "Test functionality", "Rescan for vulnerabilities"],
                rollback_plan=["Maintain backups", "Document changes", "Test rollback procedure"]
            )
            return state
    
    async def validate_and_enhance(self, state: AgentState) -> AgentState:
        """Final validation and enhancement of remediation guide"""
        try:
            remediation = state["remediation_result"]
            vuln_data = state["vulnerability_data"]
            cve_info = state["cve_info"]
            
            # Enhance with OS-specific commands
            os = vuln_data.get("os", "").lower()
            if "ubuntu" in os or "debian" in os:
                # Add Linux-specific commands
                if not any("apt-get" in step for step in remediation.detailed_steps):
                    remediation.detailed_steps.insert(0, "Update package lists: sudo apt-get update")
                    remediation.detailed_steps.insert(1, f"Upgrade affected packages: sudo apt-get upgrade <package-name>")
            
            elif "windows" in os:
                # Add Windows-specific commands
                if not any("windows update" in step.lower() for step in remediation.detailed_steps):
                    remediation.detailed_steps.insert(0, "Check for Windows updates: Start → Settings → Update & Security → Windows Update")
            
            # Add CVE-specific reference
            if cve_info.get('cve_id'):
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_info['cve_id']}"
                if nvd_url not in remediation.references:
                    remediation.references.insert(0, nvd_url)
            
            return state
            
        except Exception as e:
            state["error"] = f"Validation error: {str(e)}"
            return state
    
    def _determine_priority(self, vuln_data: Dict, cve_info: Dict) -> str:
        """Determine priority based on CVSS score and severity"""
        cvss_score = float(cve_info.get("score", 0))
        
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def _estimate_effort(self, vuln_data: Dict, cve_info: Dict) -> str:
        """Estimate remediation effort based on CVSS and complexity"""
        cvss_score = float(cve_info.get("score", 0))
        
        if cvss_score >= 9.0:
            return "4-8 hours (Urgent)"
        elif cvss_score >= 7.0:
            return "2-4 hours (High Priority)"
        elif cvss_score >= 4.0:
            return "1-2 hours (Medium Priority)"
        else:
            return "1-2 hours (Low Priority)"
    
    def _get_additional_resources(self, vuln_data: Dict, cve_info: Dict) -> List[str]:
        """Get additional security resources"""
        resources = [
            "https://nvd.nist.gov/",
            "https://cve.mitre.org/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        ]
        
        if cve_info.get("cve_id"):
            resources.append(f"https://nvd.nist.gov/vuln/detail/{cve_info['cve_id']}")
        
        # OS-specific resources
        os = vuln_data.get("os", "").lower()
        if "ubuntu" in os:
            resources.append("https://ubuntu.com/security/notices")
        elif "windows" in os:
            resources.append("https://msrc.microsoft.com/update-guide/")
        elif "red hat" in os or "rhel" in os:
            resources.append("https://access.redhat.com/security/security-updates/")
        
        return resources
    
    async def generate_remediation(self, vulnerability_data: Dict, cve_info: Dict) -> RemediationResult:
        """Main method to generate remediation guide for specific CVE"""
        initial_state = AgentState(
            vulnerability_data=vulnerability_data,
            cve_info=cve_info,
            remediation_result=None,
            search_results=[],
            error=""
        )
        
        final_state = await self.graph.ainvoke(initial_state)
        
        if final_state.get("error"):
            print(f"Agent error: {final_state['error']}")
        
        return final_state.get("remediation_result") or RemediationResult(
            remediation_guide=f"Unable to generate remediation guide for CVE {cve_info.get('cve_id', 'Unknown')}",
            priority="Medium",
            estimated_effort="Manual assessment required",
            references=[],
            additional_resources=self._get_additional_resources(vulnerability_data, cve_info),
            immediate_actions=["1. Review CVE details", "2. Check vendor advisories"],
            detailed_steps=["Consult vendor documentation for specific remediation steps"],
            verification_steps=["Verify remediation through testing and scanning"],
            rollback_plan=["Maintain system backups", "Test changes in staging first"]
        )

# Initialize the agent
remediation_agent = VulnerabilityRemediationAgent()

async def get_enhanced_remediation_data(result: Dict[str, Any], cve: Any = None) -> Dict[str, str]:
    """Get enhanced remediation data for a specific CVE in vulnerability result"""
    try:
        # Prepare vulnerability data
        original_data = result.get("original_data", {})
        
        vulnerability_data = {
            "title": clean_value(original_data.get("Title")),
            "qid": clean_value(original_data.get("QID")),
            "severity": clean_value(original_data.get("Severity")),
            "os": clean_value(original_data.get("OS")),
            "category": clean_value(original_data.get("Category")),
            "port": clean_value(original_data.get("Port")),
            "protocol": clean_value(original_data.get("Protocol")),
            "solution": clean_value(original_data.get("Solution"))
        }
        
        # Prepare CVE info
        cve_info = {}
        if cve:
            cve_info = {
                "cve_id": getattr(cve, "cve_id", ""),
                "score": getattr(cve, "score", 0),
                "severity": getattr(cve, "severity", ""),
                "description": getattr(cve, "description", "")
            }
        else:
            # Fallback if no CVE provided
            cve_info = {
                "cve_id": "N/A",
                "score": 0,
                "severity": "Unknown",
                "description": "No CVE information available"
            }
        
        # Generate remediation using the agent
        remediation_result = await remediation_agent.generate_remediation(
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
        print(f"Error generating remediation data: {e}")
        return {
            "Remediation Guide": f"Please refer to vendor documentation for CVE {getattr(cve, 'cve_id', 'Unknown') if cve else 'Unknown'} remediation steps.",
            "Remediation Priority": "Medium",
            "Estimated Effort": "Manual assessment required",
            "Reference Links": "",
            "Additional Resources": "https://nvd.nist.gov/",
            "Immediate Actions": "• Isolate affected systems\n• Check for available patches\n• Monitor for exploitation attempts",
            "Detailed Steps": "1. Consult vendor security advisories\n2. Apply recommended patches\n3. Test changes in staging environment",
            "Verification Steps": "• Verify patch installation\n• Test system functionality\n• Run vulnerability scan to confirm fix",
            "Rollback Plan": "• Maintain system backups\n• Document all changes\n• Test rollback procedure",
        }