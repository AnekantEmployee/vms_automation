import asyncio
import time
import json
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from dataclasses import dataclass
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from config.api_key_manager import generate_content_with_fallback

# Pydantic models for output parsing
class RemediationOutput(BaseModel):
    remediation_guide: str = Field(description="Specific remediation guidance for the vulnerability")
    business_context: str = Field(description="Business impact and importance")
    technical_details: str = Field(description="Key technical considerations")
    timeline_recommendation: str = Field(description="Recommended timeline for remediation")
    immediate_actions: List[str] = Field(description="3 immediate actions to take", max_items=3)
    detailed_steps: List[str] = Field(description="Detailed step-by-step remediation process", max_items=6)

class RiskAssessmentOutput(BaseModel):
    risk_category: str = Field(description="Risk level: Critical/High/Medium/Low")
    risk_score: float = Field(description="Risk score 0-10", ge=0, le=10)
    business_impact: str = Field(description="Specific business impact description")
    remediation_urgency: str = Field(description="Timeline for remediation")

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

class ImprovedRemediationAgent:
    """Improved agent with API key rotation and fallback strategies"""
    
    def __init__(self):
        # Enhanced caching to minimize API calls
        self.remediation_cache = {}
        self.template_cache = {}
        

    
    def _generate_category_specific_template(self, vuln_data: Dict, cve_info: Dict) -> RemediationResult:
        """Generate category-specific template without API calls"""
        
        category = vuln_data.get('category', '').lower()
        title = vuln_data.get('title', '').lower()
        cve_id = cve_info.get('cve_id', 'Unknown')
        severity = cve_info.get('severity', 'Medium')
        is_pci = vuln_data.get('PCI Vuln', 'no').lower() == 'yes'
        
        # Determine template based on vulnerability characteristics
        if 'plaintext' in title or 'plain-text' in title:
            if 'authentication' in title or 'login' in title:
                template_key = 'plaintext_auth'
            else:
                template_key = 'plaintext_data'
        elif 'ssl' in title or 'tls' in title:
            template_key = 'ssl_tls'
        elif 'web' in category:
            template_key = 'web_server'
        elif 'grafana' in title:
            template_key = 'grafana_secrets'
        else:
            template_key = 'generic'
        
        templates = {
            'plaintext_auth': {
                'guide': f"Critical authentication security flaw ({cve_id}): Web server transmits login credentials in plain text. Implement HTTPS encryption immediately to protect user authentication data.",
                'actions': [
                    "Enable HTTPS/SSL encryption for all login forms",
                    "Configure secure authentication protocols",
                    "Implement HTTP Strict Transport Security (HSTS)"
                ],
                'steps': [
                    "Obtain and install valid SSL/TLS certificate",
                    "Configure web server to redirect HTTP to HTTPS",
                    "Update all login forms to use HTTPS endpoints",
                    "Test authentication flow over encrypted connection",
                    "Disable HTTP access to sensitive areas"
                ]
            },
            'plaintext_data': {
                'guide': f"Data transmission security vulnerability ({cve_id}): Sensitive data transmitted without encryption. Enable secure protocols to protect data integrity and confidentiality.",
                'actions': [
                    "Enable data encryption in transit (HTTPS/TLS)",
                    "Configure secure data transmission protocols", 
                    "Implement end-to-end encryption for sensitive data"
                ],
                'steps': [
                    "Identify all data transmission points",
                    "Configure TLS encryption for data channels",
                    "Update application code to use secure protocols",
                    "Verify encryption is working correctly",
                    "Monitor for unencrypted data transmission"
                ]
            },
            'ssl_tls': {
                'guide': f"SSL/TLS configuration vulnerability ({cve_id}): Weak or misconfigured encryption. Update SSL/TLS settings to current security standards.",
                'actions': [
                    "Update SSL/TLS certificates to latest version",
                    "Configure strong cipher suites and protocols",
                    "Disable weak encryption methods"
                ],
                'steps': [
                    "Audit current SSL/TLS configuration",
                    "Generate new certificates with strong encryption",
                    "Update cipher suite configuration",
                    "Test SSL configuration with security tools",
                    "Monitor certificate expiration dates"
                ]
            },
            'grafana_secrets': {
                'guide': f"Grafana Agent secret exposure ({cve_id}): Configuration endpoints expose sensitive credentials in plaintext. Upgrade to patched version and implement access controls.",
                'actions': [
                    "Upgrade Grafana Agent to version 0.20.1 or 0.21.2+",
                    "Implement HTTPS with client authentication",
                    "Use file-based secrets instead of inline secrets"
                ],
                'steps': [
                    "Backup current Grafana Agent configuration",
                    "Download Grafana Agent v0.20.1+ or v0.21.2+",
                    "Migrate inline secrets to external secret files",
                    "Configure HTTPS with client authentication",
                    "Restrict network access to configuration endpoints",
                    "Verify secrets are no longer exposed via API endpoints"
                ]
            },
            'web_server': {
                'guide': f"Web server security vulnerability ({cve_id}): Server configuration exposes security risks. Apply security hardening and patches.",
                'actions': [
                    "Apply web server security patches",
                    "Harden web server configuration",
                    "Enable security headers and protections"
                ],
                'steps': [
                    "Review web server version and available updates",
                    "Apply latest security patches",
                    "Configure security headers (HSTS, CSP, etc.)",
                    "Disable unnecessary services and modules",
                    "Implement access logging and monitoring"
                ]
            },
            'generic': {
                'guide': f"Security vulnerability identified ({cve_id}): Apply vendor patches and security controls to address identified risk.",
                'actions': [
                    "Apply vendor security patches immediately",
                    "Review and harden system configuration",
                    "Enable security monitoring and alerting"
                ],
                'steps': [
                    "Check vendor advisories for security patches",
                    "Test patches in staging environment",
                    "Apply patches during maintenance window",
                    "Verify patch installation success",
                    "Monitor system for proper functionality"
                ]
            }
        }
        
        template = templates.get(template_key, templates['generic'])
        
        # Adjust priority for PCI compliance
        if is_pci:
            priority = "Critical"
            urgency_boost = " (PCI Compliance Critical)"
        else:
            priority = severity if severity in ["Critical", "High", "Medium", "Low"] else "Medium"
            urgency_boost = ""
        
        # Build references
        references = []
        if cve_id != "Unknown":
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        
        return RemediationResult(
            remediation_guide=template['guide'] + urgency_boost,
            priority=priority,
            estimated_effort="2-6 hours depending on system complexity and testing requirements",
            references=references,
            additional_resources=[
                "https://nvd.nist.gov/",
                "https://cve.mitre.org/",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            ],
            immediate_actions=template['actions'],
            detailed_steps=template['steps'],
            verification_steps=[
                "Verify remediation has been applied successfully",
                "Run vulnerability scanner to confirm fix",
                "Test critical system functionality",
                "Document remediation for compliance audit"
            ],
            rollback_plan=[
                "Maintain complete system backups before changes",
                "Document all configuration modifications",
                "Test rollback procedures in staging environment",
                "Keep previous configurations for quick restoration"
            ]
        )
    
    async def generate_remediation(self, vulnerability_data: Dict, cve_info: Dict) -> RemediationResult:
        """Generate remediation with smart fallback strategy"""
        
        # Create cache key
        cache_key = f"{cve_info.get('cve_id', 'unknown')}_{vulnerability_data.get('QID', 'unknown')}"
        
        if cache_key in self.remediation_cache:
            print(f"Using cached remediation for {cve_info.get('cve_id', 'unknown')}")
            return self.remediation_cache[cache_key]
        
        # First, try to use our smart template system
        template_result = self._generate_category_specific_template(vulnerability_data, cve_info)
        
        # Only use LLM if it's a critical vulnerability
        if self._should_use_llm(vulnerability_data, cve_info):
            try:
                print("Attempting LLM enhancement...")
                enhanced_result = await self._enhance_with_llm(template_result, vulnerability_data, cve_info)
                self.remediation_cache[cache_key] = enhanced_result
                return enhanced_result
                
            except Exception as e:
                print(f"LLM enhancement failed, using template: {e}")
                self.remediation_cache[cache_key] = template_result
                return template_result
        else:
            print("Using template-based remediation (preserving API quota)")
            self.remediation_cache[cache_key] = template_result
            return template_result
    
    def _should_use_llm(self, vuln_data: Dict, cve_info: Dict) -> bool:
        """Determine if LLM enhancement is worth the API cost"""
        
        # Only use LLM for high-value cases
        severity = cve_info.get('severity', 'Medium')
        is_pci = vuln_data.get('PCI Vuln', 'no').lower() == 'yes'
        cve_score = float(cve_info.get('score', 0))
        
        # Use LLM for critical cases only
        return severity == 'Critical' or is_pci or cve_score >= 8.0
    
    async def _enhance_with_llm(self, template_result: RemediationResult, 
                               vuln_data: Dict, cve_info: Dict) -> RemediationResult:
        """Enhance template with LLM-generated insights using API key rotation"""
        
        context = f"""
Vulnerability Details:
- Title: {vuln_data.get('Title', 'Unknown')}
- CVE ID: {cve_info.get('cve_id', 'Unknown')}
- Severity: {cve_info.get('severity', 'Unknown')} (Score: {cve_info.get('score', 'N/A')})
- PCI Impact: {vuln_data.get('PCI Vuln', 'no')}
- Asset: {vuln_data.get('DNS', vuln_data.get('IP', 'Unknown'))}
- Current Assessment: {template_result.remediation_guide}

Enhance this security remediation with specific, actionable guidance.
Provide enhanced remediation guidance for this vulnerability.
Focus on actionable, specific technical steps and business context.

Return a JSON object with these fields:
- remediation_guide: Enhanced remediation guidance
- immediate_actions: List of 3 immediate actions
- detailed_steps: List of detailed remediation steps
"""
        
        try:
            response = generate_content_with_fallback(
                context,
                generation_config={
                    'temperature': 0.3,
                    'max_output_tokens': 1000
                }
            )
            
            # Try to parse JSON response
            try:
                import json
                parsed_data = json.loads(response)
                template_result.remediation_guide = parsed_data.get('remediation_guide', template_result.remediation_guide)
                template_result.immediate_actions = parsed_data.get('immediate_actions', template_result.immediate_actions)
                template_result.detailed_steps = parsed_data.get('detailed_steps', template_result.detailed_steps)
            except:
                # If JSON parsing fails, use the response as remediation guide
                template_result.remediation_guide = response[:500] + "..."
            
            return template_result
            
        except Exception as e:
            print(f"LLM enhancement failed: {e}")
            return template_result


# Usage with error handling
async def get_enhanced_remediation_data(result: Dict[str, Any], cve: Any = None) -> Dict[str, str]:
    """Get remediation data with improved error handling"""
    
    agent = ImprovedRemediationAgent()
    
    try:
        # Prepare data
        original_data = result.get("original_data", {})
        vulnerability_data = {
            "Title": original_data.get("Title", "Unknown"),
            "QID": original_data.get("QID", "N/A"),
            "Severity": original_data.get("Severity", "Unknown"),
            "category": original_data.get("Category", "Unknown"),
            "PCI Vuln": original_data.get("PCI Vuln", "no"),
            "IP": original_data.get("IP", "Unknown"),
            "DNS": original_data.get("DNS", "Unknown")
        }
        
        if cve and hasattr(cve, 'cve_id'):
            cve_info = {
                "cve_id": getattr(cve, "cve_id", "Unknown"),
                "score": getattr(cve, "score", 0),
                "severity": getattr(cve, "severity", "Unknown"),
                "description": getattr(cve, "description", "")
            }
        else:
            cve_info = {
                "cve_id": "N/A",
                "score": 0,
                "severity": vulnerability_data.get("Severity", "Unknown"),
                "description": "No CVE information available"
            }
        
        # Generate remediation
        remediation_result = await agent.generate_remediation(vulnerability_data, cve_info)
        
        # Format response
        return {
            "Remediation Guide": remediation_result.remediation_guide,
            "Remediation Priority": remediation_result.priority,
            "Estimated Effort": remediation_result.estimated_effort,
            "Reference Links": "; ".join(remediation_result.references) if remediation_result.references else "Check vendor advisories",
            "Additional Resources": "; ".join(remediation_result.additional_resources),
            "Immediate Actions": "\n".join([f"• {action}" for action in remediation_result.immediate_actions]),
            "Detailed Steps": "\n".join([f"{i+1}. {step}" for i, step in enumerate(remediation_result.detailed_steps)]),
            "Verification Steps": "\n".join([f"• {step}" for step in remediation_result.verification_steps]),
            "Rollback Plan": "\n".join([f"• {step}" for step in remediation_result.rollback_plan])
        }
        
    except Exception as e:
        print(f"Remediation generation failed: {e}")
        
        # Ultimate fallback
        cve_id = getattr(cve, 'cve_id', 'Unknown') if cve else 'Unknown'
        title = original_data.get("Title", "Unknown vulnerability")
        is_pci = original_data.get("PCI Vuln", "no").lower() == 'yes'
        
        priority = "Critical" if is_pci else "High"
        
        return {
            "Remediation Guide": f"Security remediation required for {title} ({cve_id}). Apply vendor patches and implement security controls.",
            "Remediation Priority": priority,
            "Estimated Effort": "2-4 hours for assessment and remediation",
            "Reference Links": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "Unknown" else "Check vendor advisories",
            "Additional Resources": "https://nvd.nist.gov/; https://cve.mitre.org/",
            "Immediate Actions": "• Review vulnerability impact\n• Apply security patches\n• Test remediation",
            "Detailed Steps": "1. Assess vulnerability scope\n2. Apply recommended patches\n3. Verify remediation success\n4. Monitor for reoccurrence",
            "Verification Steps": "• Confirm patches applied\n• Run security scan\n• Test functionality",
            "Rollback Plan": "• Maintain system backups\n• Document changes\n• Test rollback procedures"
        }
