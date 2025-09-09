import re
import json
from ppt import main
from collections import defaultdict

def create_remediation_slide(vulnerabilities, summary):
    """
    Create dynamic remediation strategy slide using actual vulnerability data
    """
    # Initialize counters
    remediation_stats = {
        'immediate': 0,
        'high_priority': 0, 
        'standard': 0,
        'low_priority': 0
    }
    
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0, 
        'MEDIUM': 0,
        'LOW': 0,
        'UNKNOWN': 0
    }
    
    pci_impact_count = 0
    config_hardening_count = 0
    
    # Process vulnerabilities to extract dynamic counts
    for vuln in vulnerabilities:
        # Count PCI compliance issues
        if vuln.get('original_data', {}).get('PCI Vuln') == "yes":
            pci_impact_count += 1
            
        # Count configuration & hardening issues
        category = vuln.get('original_data', {}).get('Category', '')
        if any(term in category.lower() for term in ['ssh', 'ssl', 'config', 'certificate']):
            config_hardening_count += 1
            
        # Count severity levels from CVE data
        for severity, count in vuln.get('severity_summary', {}).items():
            if severity in severity_counts:
                severity_counts[severity] += count
        
        # Count remediation urgency levels
        for risk_data in vuln.get('risk_assessment_data', []):
            urgency = risk_data.get('risk_assessment', {}).get('remediation_urgency', '')
            
            if 'Immediate Action Required' in urgency or '24 hours' in urgency:
                remediation_stats['immediate'] += 1
            elif 'High Priority' in urgency or '72 hours' in urgency:
                remediation_stats['high_priority'] += 1
            elif 'Standard Priority' in urgency or '2 weeks' in urgency:
                remediation_stats['standard'] += 1
            elif 'Low Priority' in urgency or 'maintenance cycle' in urgency:
                remediation_stats['low_priority'] += 1

    # Calculate totals
    total_vulnerabilities = len(vulnerabilities)
    total_remediations = summary.get('total_remediations_generated', 0)
    critical_items = remediation_stats['immediate'] + remediation_stats['high_priority']
    
    # Build dynamic slide data
    slide6_data = {
        "title": "Strategic Remediation Plan",
        "stage1_title": "Phase 1: Critical Response (0-30 days)",
        "stage2_title": "Phase 2: Systematic Remediation (30-90 days)",
        "stage1_table": {
            "columns": ["Priority", "Description", "Count", "Target SLA", "Resources", "Status"],
            "rows": [
                ["P0", "Immediate Action Required", 
                 str(remediation_stats['immediate']), 
                 "24-48 hours", "Security Team", 
                 "In Progress" if remediation_stats['immediate'] > 0 else "N/A"],
                 
                ["P1", "Critical Business Risk", 
                 str(remediation_stats['high_priority']), 
                 "72 hours", "IT + Security", 
                 "Planned" if remediation_stats['high_priority'] > 0 else "N/A"],
                 
                ["P2", "High Impact Vulnerabilities", 
                 str(severity_counts['HIGH']), 
                 "7-14 days", "IT Team", 
                 "Scheduled" if severity_counts['HIGH'] > 0 else "N/A"],
                 
                ["P3", "PCI Compliance Issues", 
                 str(pci_impact_count), 
                 "14-30 days", "Compliance Team", 
                 "Queued" if pci_impact_count > 0 else "N/A"]
            ]
        },
        "stage2_table": {
            "columns": ["Priority", "Description", "Count", "Target SLA", "Resources", "Status"],
            "rows": [
                ["P4", "Medium Risk Items", 
                 str(remediation_stats['standard']), 
                 "30-60 days", "IT Team", 
                 "Planned" if remediation_stats['standard'] > 0 else "Future"],
                 
                ["P5", "Configuration Hardening", 
                 str(config_hardening_count), 
                 "60-90 days", "System Admins", 
                 "Planned" if config_hardening_count > 0 else "Future"],
                 
                ["P6", "Process Improvements", 
                 str(remediation_stats['low_priority']) if remediation_stats['low_priority'] > 0 else "TBD", 
                 "Ongoing", "All Teams", "Future"],
                 
                ["P7", "Security Awareness", 
                 "TBD", "Quarterly", "HR + Security", "Future"]
            ]
        },
        "footnote": f"**Total remediation items: {total_vulnerabilities} | " +
                   f"Estimated effort: {total_remediations} action items | " +
                   f"Critical items requiring immediate attention: {critical_items}**"
    }
    
    return slide6_data, remediation_stats

# ====== SLIDE 7: Dynamic Critical Actions (Timeline Removed + CVE Regex) ======
def create_dynamic_critical_actions(vulnerabilities):
    """Create dynamic critical actions with regex CVE extraction and no timeline"""
    
    critical_actions = []
    
    # Regex pattern to extract CVE IDs (e.g., CVE-2023-12345)
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    
    for vuln in vulnerabilities:
        severity_summary = vuln.get('severity_summary', {})
        
        # Only process vulnerabilities with critical severity
        if severity_summary.get('CRITICAL', 0) > 0:
            original = vuln.get('original_data', {})
            remediation_data = vuln.get('remediation_data', [])
            risk_data = vuln.get('risk_assessment_data', [])
            
            # Extract comprehensive asset information
            ip = original.get('IP', 'Unknown IP')
            hostname = original.get('Hostname', original.get('Asset', 'Unknown Host'))
            port = original.get('Port', 'N/A')
            service = original.get('Service', 'N/A')
            network = original.get('Network', 'Unknown Network')
            
            # Extract vulnerability details
            title = original.get('Title', 'Unknown Vulnerability')
            vuln_status = original.get('Vuln Status', 'Active')
            
            # Extract CVE IDs using regex from multiple string fields
            cve_ids = set()
            
            # Search in risk assessment data (convert to string first)
            for risk in risk_data:
                risk_assessment_str = str(risk.get('risk_assessment', {}))
                cves_found = cve_pattern.findall(risk_assessment_str)
                cve_ids.update(cves_found)
            
            # Search in original data fields that might contain CVE strings
            search_fields = ['CVE', 'Description', 'Title', 'Synopsis', 'Plugin Output']
            for field in search_fields:
                field_data = str(original.get(field, ''))
                if field_data and field_data != 'None':
                    cves_found = cve_pattern.findall(field_data)
                    cve_ids.update(cves_found)
            
            # Search in remediation data strings
            for remediation in remediation_data:
                remediation_str = str(remediation.get('remediation', {}))
                cves_found = cve_pattern.findall(remediation_str)
                cve_ids.update(cves_found)
            
            # Format CVE string (sorted and comma-separated)
            cve_str = ", ".join(sorted(cve_ids, key=lambda x: x.upper())) if cve_ids else "No CVE Found"
            
            # Get highest CVSS score if available
            highest_cvss = vuln.get('highest_score', 'N/A')
            if highest_cvss != 'N/A' and str(highest_cvss) != '0':
                cve_str += f" (CVSS: {highest_cvss})"
            
            # Extract remediation information
            effort = "Unknown"
            patch_available = "Unknown"
            if remediation_data:
                remediation = remediation_data[0].get('remediation', {})
                effort = remediation.get('Estimated Effort', 'Unknown')
                patch_available = remediation.get('Patch Available', 'Unknown')
                
                # Enhance remediation details
                if patch_available.lower() == 'yes':
                    effort += " | Patch Available"
            
            # Extract compliance and business impact
            pci_impact = original.get('PCI Vuln', 'No')
            exploitability = original.get('Exploitability', 'Unknown')
            
            # Build business context flags
            business_flags = []
            if pci_impact.lower() == 'yes':
                business_flags.append("PCI Impact")
            if exploitability.lower() not in ['unknown', 'nan', 'none']:
                business_flags.append("Exploitable")
            if vuln_status.lower() == 'new':
                business_flags.append("NEW")
            
            business_context = " | ".join(business_flags) if business_flags else "Standard Risk"
            
            # Format comprehensive asset identifier
            asset_info = f"{ip}"
            if hostname not in ['Unknown Host', ip, '']:
                asset_info += f" ({hostname})"
            if port != 'N/A':
                asset_info += f":{port}"
            if service != 'N/A':
                asset_info += f" [{service}]"
            
            # Add network context
            asset_full = f"{asset_info} | {network}"
            
            # Create concise vulnerability description
            vuln_desc = title[:60] + "..." if len(title) > 60 else title
            
            # Create dynamic row (9 columns - timeline removed)
            row = [
                asset_full,
                vuln_desc,
                str(severity_summary.get('CRITICAL', 0)),
                str(severity_summary.get('HIGH', 0)), 
                str(severity_summary.get('MEDIUM', 0)),
                str(severity_summary.get('LOW', 0)),
                cve_str,
                business_context
            ]
            
            critical_actions.append(row)
    
    # Sort by critical count (highest first), then by CVSS score
    critical_actions.sort(key=lambda x: (
        int(x[2]) if x[2].isdigit() else 0,  # Critical count
        float(re.search(r'CVSS: (\d+\.?\d*)', x[6]).group(1)) if re.search(r'CVSS: (\d+\.?\d*)', x[6]) else 0.0  # CVSS score
    ), reverse=True)
    
    return critical_actions

# Create HIGH vulnerability actions using the same dynamic approach as slide7
def create_dynamic_high_actions(vulnerabilities):
    """Create dynamic high severity actions with comprehensive vulnerability context"""
    
    import re
    
    high_actions = []
    
    # Regex pattern to extract CVE IDs
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    
    for vuln in vulnerabilities:
        severity_summary = vuln.get('severity_summary', {})
        
        # Only process vulnerabilities with HIGH severity
        if severity_summary.get('HIGH', 0) > 0:
            original = vuln.get('original_data', {})
            remediation_data = vuln.get('remediation_data', [])
            risk_data = vuln.get('risk_assessment_data', [])
            
            # Extract comprehensive asset information
            ip = original.get('IP', 'Unknown IP')
            hostname = original.get('Hostname', original.get('Asset', 'Unknown Host'))
            port = original.get('Port', 'N/A')
            service = original.get('Service', 'N/A')
            network = original.get('Network', 'Unknown Network')
            
            # Extract vulnerability details
            title = original.get('Title', 'Unknown Vulnerability')
            vuln_status = original.get('Vuln Status', 'Active')
            
            # Extract CVE IDs using regex from multiple string fields
            cve_ids = set()
            
            # Search in risk assessment data
            for risk in risk_data:
                risk_assessment_str = str(risk.get('risk_assessment', {}))
                cves_found = cve_pattern.findall(risk_assessment_str)
                cve_ids.update(cves_found)
            
            # Search in original data fields
            search_fields = ['CVE', 'Description', 'Title', 'Synopsis', 'Plugin Output']
            for field in search_fields:
                field_data = str(original.get(field, ''))
                if field_data and field_data != 'None':
                    cves_found = cve_pattern.findall(field_data)
                    cve_ids.update(cves_found)
            
            # Search in remediation data
            for remediation in remediation_data:
                remediation_str = str(remediation.get('remediation', {}))
                cves_found = cve_pattern.findall(remediation_str)
                cve_ids.update(cves_found)
            
            # Format CVE string
            cve_str = ", ".join(sorted(cve_ids, key=lambda x: x.upper())) if cve_ids else "No CVE Found"
            
            # Get CVSS score if available
            highest_cvss = vuln.get('highest_score', 'N/A')
            if highest_cvss != 'N/A' and str(highest_cvss) != '0':
                cve_str += f" (CVSS: {highest_cvss})"
            
            # Extract remediation information
            effort = "Unknown"
            patch_available = "Unknown"
            if remediation_data:
                remediation = remediation_data[0].get('remediation', {})
                effort = remediation.get('Estimated Effort', 'Unknown')
                patch_available = remediation.get('Patch Available', 'Unknown')
                
                if patch_available.lower() == 'yes':
                    effort += " | Patch Available"
            
            # Extract compliance and business impact
            pci_impact = original.get('PCI Vuln', 'No')
            exploitability = original.get('Exploitability', 'Unknown')
            
            # Build business context flags
            business_flags = []
            if pci_impact.lower() == 'yes':
                business_flags.append("PCI Impact")
            if exploitability.lower() not in ['unknown', 'nan', 'none']:
                business_flags.append("Exploitable")
            if vuln_status.lower() == 'new':
                business_flags.append("NEW")
            
            business_context = " | ".join(business_flags) if business_flags else "Standard Risk"
            
            # Format asset identifier
            asset_info = f"{ip}"
            if hostname not in ['Unknown Host', ip, '']:
                asset_info += f" ({hostname})"
            if port != 'N/A':
                asset_info += f":{port}"
            if service != 'N/A':
                asset_info += f" [{service}]"
            
            asset_full = f"{asset_info} | {network}"
            
            # Create vulnerability description
            vuln_desc = title[:60] + "..." if len(title) > 60 else title
            
            # Create dynamic row (8 columns - same as slide7)
            row = [
                asset_full,                                    # Asset & Network Location
                vuln_desc,                                     # Vulnerability Description
                str(severity_summary.get('CRITICAL', 0)),     # Critical
                str(severity_summary.get('HIGH', 0)),         # High
                str(severity_summary.get('MEDIUM', 0)),       # Medium
                str(severity_summary.get('LOW', 0)),          # Low
                cve_str,                                       # CVE IDs & CVSS Score
                business_context                               # Business Impact Context
            ]
            
            high_actions.append(row)
    
    # Sort by high count (highest first), then by CVSS score
    high_actions.sort(key=lambda x: (
        int(x[3]) if x[3].isdigit() else 0,  # High count
        float(re.search(r'CVSS: (\d+\.?\d*)', x[6]).group(1)) if re.search(r'CVSS: (\d+\.?\d*)', x[6]) else 0.0
    ), reverse=True)
    
    return high_actions


def create_enhanced_slide9_data(vulnerabilities, pci_impact_count):
    """Create comprehensive business impact and compliance analysis"""
    
    # Extract PCI vulnerabilities
    pci_vulns = []
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        if original.get('PCI Vuln', '').lower() == 'yes':
            pci_vulns.append([
                original.get('IP', ''),
                original.get('Title', '')[:60] + "..." if len(original.get('Title', '')) > 60 else original.get('Title', '')
            ])
    
    # Enhanced business impact analysis with additional categories
    business_impact_categories = [
        # Compliance & Regulatory
        ['PCI DSS Compliance Issues', str(pci_impact_count)],
        ['SOX Compliance Impact', str(len([v for v in vulnerabilities if 'sox' in str(v.get('original_data', {})).lower()]))],
        ['GDPR Data Privacy Risk', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Title', '').lower() for term in ['data leak', 'privacy', 'gdpr'])]))],
        
        # Critical Business Systems
        ['Critical Business Systems', str(len([v for v in vulnerabilities if v.get('severity_summary', {}).get('CRITICAL', 0) > 0]))],
        ['High-Value Assets', str(len([v for v in vulnerabilities if v.get('severity_summary', {}).get('HIGH', 0) > 0]))],
        ['Public-Facing Assets', str(len([v for v in vulnerabilities if v.get('original_data', {}).get('SSL', '').lower() in ['ssl', 'over ssl']]))],
        
        # Infrastructure & Operations
        ['Legacy Systems (EOL)', str(len([v for v in vulnerabilities if 'eol' in v.get('original_data', {}).get('Title', '').lower()]))],
        ['Unpatched Critical Systems', str(len([v for v in vulnerabilities if v.get('remediation_data') and any('open' in str(r).lower() for r in v.get('remediation_data', []))]))],
        ['Remote Access Vulnerabilities', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Title', '').lower() for term in ['remote', 'rdp', 'ssh', 'vpn'])]))],
        
        # Security Threats
        ['Ransomware Attack Vectors', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Description', '').lower() for term in ['ransomware', 'file encryption', 'crypto'])]))],
        ['Privilege Escalation Risks', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Title', '').lower() for term in ['privilege', 'escalation', 'elevation'])]))],
        ['Data Exfiltration Risks', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Description', '').lower() for term in ['data leak', 'information disclosure', 'sensitive data'])]))],
        
        # Network & Access
        ['Network Segmentation Issues', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Title', '').lower() for term in ['network', 'firewall', 'acl'])]))],
        ['Authentication Weaknesses', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Title', '').lower() for term in ['authentication', 'password', 'credential'])]))],
        ['Encryption Vulnerabilities', str(len([v for v in vulnerabilities if any(term in v.get('original_data', {}).get('Title', '').lower() for term in ['ssl', 'tls', 'certificate', 'encryption'])]))],
    ]
    
    # Network segment analysis
    network_risk_analysis = []
    networks = set()
    for vuln in vulnerabilities:
        network = vuln.get('original_data', {}).get('Network', 'Unknown')
        if network != 'Unknown':
            networks.add(network)
    
    for network in sorted(networks):
        network_vulns = [v for v in vulnerabilities if v.get('original_data', {}).get('Network') == network]
        critical_count = len([v for v in network_vulns if v.get('severity_summary', {}).get('CRITICAL', 0) > 0])
        high_count = len([v for v in network_vulns if v.get('severity_summary', {}).get('HIGH', 0) > 0])
        
        if critical_count > 0 or high_count > 0:  # Only include networks with critical/high vulns
            network_risk_analysis.append([
                network,
                f"Critical: {critical_count}, High: {high_count}"
            ])
    
    # CVE intelligence summary
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    all_cves = set()
    
    for vuln in vulnerabilities:
        # Search in multiple fields for CVEs
        search_fields = [
            str(vuln.get('original_data', {})),
            str(vuln.get('risk_assessment_data', [])),
            str(vuln.get('remediation_data', []))
        ]
        
        for field_data in search_fields:
            cves_found = cve_pattern.findall(field_data)
            all_cves.update(cves_found)
    
    cve_summary = [
        ['Total Unique CVEs Identified', str(len(all_cves))],
        ['High CVSS Score CVEs (>7.0)', str(len([v for v in vulnerabilities if v.get('highest_score', 0) > 7.0]))],
        ['Recently Published CVEs (2023+)', str(len([cve for cve in all_cves if '2023' in cve or '2024' in cve or '2025' in cve]))],
        ['Zero-Day Vulnerabilities', str(len([v for v in vulnerabilities if 'zero' in v.get('original_data', {}).get('Title', '').lower()]))],
    ]

    slide9_data = {
        'title': 'Business Impact & Compliance Analysis - Comprehensive Assessment',
        'subtitle': f'Risk Analysis Across {len(business_impact_categories)} Categories | {len(all_cves)} Unique CVEs Identified',
        'tables': [
            {
                'title': 'Business Impact Categories',
                'columns': ['Impact Category', 'Affected Count'],
                'rows': business_impact_categories
            },
            {
                'title': 'Network Segment Risk Analysis',
                'columns': ['Network Segment', 'Critical & High Risk Summary'],
                'rows': network_risk_analysis[:8] if network_risk_analysis else [['No high-risk network segments identified', 'N/A']]
            },
            {
                'title': 'CVE Intelligence Summary',
                'columns': ['CVE Metric', 'Count'],
                'rows': cve_summary
            },
            {
                'title': 'PCI Compliance Detailed Impact',
                'columns': ['Asset IP', 'PCI-Related Vulnerability'],
                'rows': pci_vulns[:10] if pci_vulns else [['No PCI-related vulnerabilities', 'N/A']]
            }
        ]
    }
    
    return slide9_data

# SLIDE 10: Executive Summary & Strategic Roadmap
def create_enhanced_slide10_data(vulnerabilities, severity_counts, remediation_stats):
    """Create comprehensive executive summary and strategic roadmap"""
    
    # Calculate key metrics from actual data
    total_vulns = len(vulnerabilities)
    critical_high_count = severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
    
    # Calculate remediation coverage
    total_with_remediation = sum(1 for v in vulnerabilities if v.get('remediation_data'))
    remediation_coverage = f"{(total_with_remediation / total_vulns * 100):.1f}%" if total_vulns > 0 else "0%"
    
    # Calculate average CVSS score
    cvss_scores = [v.get('highest_score', 0) for v in vulnerabilities if v.get('highest_score', 0) > 0]
    avg_cvss = f"{sum(cvss_scores) / len(cvss_scores):.1f}" if cvss_scores else "N/A"
    
    # Identify top risk areas
    risk_areas = []
    ssl_count = sum(1 for v in vulnerabilities if 'ssl' in v.get('original_data', {}).get('Title', '').lower())
    if ssl_count > 0:
        risk_areas.append(f"SSL/TLS Issues ({ssl_count})")
    
    ssh_count = sum(1 for v in vulnerabilities if 'ssh' in v.get('original_data', {}).get('Title', '').lower())
    if ssh_count > 0:
        risk_areas.append(f"SSH Configuration ({ssh_count})")
    
    os_count = sum(1 for v in vulnerabilities if any(os in v.get('original_data', {}).get('OS', '').lower() for os in ['ubuntu', 'linux', 'windows']))
    if os_count > 0:
        risk_areas.append(f"OS Vulnerabilities ({os_count})")

    slide10_data = {
        'title': 'Executive Summary & Strategic Security Roadmap',
        'subtitle': 'Key Findings, Risk Posture & Recommended Actions',
        'sections': [
            {
                'title': 'Security Posture Assessment',
                'type': 'metrics',
                'columns': ['Security Metric', 'Current Status', 'Target Goal'],
                'rows': [
                    ['Total Vulnerabilities Identified', str(total_vulns), 'Reduce by 50%'],
                    ['Critical & High Severity', str(critical_high_count), 'Zero Critical'],
                    ['Average CVSS Score', avg_cvss, '< 5.0'],
                    ['Remediation Coverage', remediation_coverage, '95%+'],
                    ['Immediate Action Required', str(remediation_stats.get('immediate', 0)), '0'],
                    ['Compliance Gaps (PCI)', str(sum(1 for v in vulnerabilities if v.get('original_data', {}).get('PCI Vuln', '').lower() == 'yes')), '0']
                ]
            },
            {
                'title': 'Risk Intelligence Summary',
                'type': 'insights',
                'columns': ['Risk Category', 'Current Exposure', 'Business Impact'],
                'rows': [
                    ['External Attack Surface', f"{sum(1 for v in vulnerabilities if v.get('original_data', {}).get('SSL', ''))} assets", 'High - Direct exposure'],
                    ['Legacy System Risks', f"{sum(1 for v in vulnerabilities if 'eol' in v.get('original_data', {}).get('Title', '').lower())} systems", 'Medium - Support gaps'],
                    ['Privilege Escalation', f"{sum(1 for v in vulnerabilities if 'privilege' in v.get('original_data', {}).get('Title', '').lower())} vectors", 'High - Admin access'],
                    ['Data Exfiltration Risk', f"{sum(1 for v in vulnerabilities if any(term in v.get('original_data', {}).get('Description', '').lower() for term in ['data', 'information disclosure']))} vulnerabilities", 'Critical - Data loss'],
                    ['Ransomware Vectors', f"{sum(1 for v in vulnerabilities if 'ransomware' in v.get('original_data', {}).get('Description', '').lower())} entry points", 'Critical - Business disruption']
                ]
            }
        ],
        'key_recommendations': [
            'Establish a dedicated Vulnerability Management Office (VMO) for centralized coordination',
            'Implement risk-based prioritization using CVSS scores and business impact assessment',
            'Deploy continuous monitoring with automated alerting for new critical vulnerabilities', 
            'Create cross-functional incident response teams with defined escalation procedures',
            'Integrate vulnerability management with existing ITSM and change management processes',
            'Establish quarterly security posture reviews with executive leadership and board reporting'
        ],
        'success_metrics': [
            'Mean Time to Detect (MTTD): < 4 hours for critical vulnerabilities',
            'Mean Time to Remediate (MTTR): < 72 hours for critical, < 30 days for high',
            'Vulnerability Recurrence Rate: < 5% for previously remediated issues',
            'Security Training Completion: 100% annual completion rate',
            'Compliance Audit Results: Zero critical findings in annual assessments'
        ]
    }
    
    return slide10_data


def transform_vulnerability_data_to_slides(data_json_path: str) -> list:
    """
    Intelligently transform vulnerability JSON data into structured slide format
    Uses actual CVE data, risk assessments, and remediation information
    """
    
    # Load the JSON data
    with open(data_json_path, 'r', encoding='utf-8') as f:
        data_raw = json.load(f)
    
    vulnerabilities = data_raw.get("results", [])
    summary = data_raw.get("summary", {})
    
    # Initialize comprehensive data structures
    slide_data_list = []
    
    # ====== INTELLIGENT DATA ANALYSIS ======
    
    # Asset Analysis
    unique_ips = set()
    network_analysis = defaultdict(set)
    os_analysis = defaultdict(int)
    
    # Vulnerability Categorization (using actual data patterns)
    vuln_categories = {
        'SSL/TLS & Certificates': [],
        'SSH & Cryptography': [],
        'OS & System Updates': [],
        'Web Server & Applications': [],
        'Configuration & Hardening': []
    }
    
    # Risk Analysis
    risk_distribution = defaultdict(int)
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    
    # Business Impact Analysis
    pci_impact_count = 0
    exploitable_vulns = 0
    
    # Process each vulnerability with intelligence
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        
        # Asset tracking
        ip = original.get('IP', '')
        network = original.get('Network', 'Unknown')
        os = original.get('OS', 'Unknown')
        
        if ip:
            unique_ips.add(ip)
            network_analysis[network].add(ip)
            os_analysis[os] += 1
        
        # Intelligent vulnerability categorization using title patterns
        title = original.get('Title', '').lower()
        
        if any(term in title for term in ['ssl', 'certificate', 'tls', 'x.509']):
            vuln_categories['SSL/TLS & Certificates'].append(vuln)
        elif any(term in title for term in ['ssh', 'sha1', 'cryptographic', 'cipher']):
            vuln_categories['SSH & Cryptography'].append(vuln)
        elif any(term in title for term in ['ubuntu', 'linux', 'kernel', 'security notification']):
            vuln_categories['OS & System Updates'].append(vuln)
        elif any(term in title for term in ['web', 'http', 'trace', 'server', 'autocomplete']):
            vuln_categories['Web Server & Applications'].append(vuln)
        else:
            vuln_categories['Configuration & Hardening'].append(vuln)
        
        # Risk analysis using actual severity data
        severity_summary = vuln.get('severity_summary', {})
        for sev, count in severity_summary.items():
            severity_counts[sev] += count
        
        # Risk category from assessment data
        risk_data = vuln.get('risk_assessment_data', [])
        for risk in risk_data:
            risk_cat = risk.get('risk_assessment', {}).get('risk_category', 'Unknown')
            risk_distribution[risk_cat] += 1
        
        # Business impact tracking
        if original.get('PCI Vuln', '').lower() == 'yes':
            pci_impact_count += 1
        
        if original.get('Exploitability', '') != 'nan':
            exploitable_vulns += 1
    
    # ====== SLIDE 1: Executive Summary ======
    slide1_data = {
        'title': 'Enterprise Vulnerability Assessment Report',
        'agenda_points': [
            f'Security scan across {len(unique_ips)} assets in {len(network_analysis)} networks',
            f'Analysis of {len(vulnerabilities)} vulnerabilities with {summary.get("total_cves_found", 0)} CVEs',
            f'Risk prioritization: {severity_counts["CRITICAL"]} Critical, {severity_counts["HIGH"]} High severity',
            f'PCI compliance impact: {pci_impact_count} vulnerabilities affecting compliance',
            'Comprehensive remediation strategy with actionable recommendations'
        ]
    }
    slide_data_list.append(slide1_data)
    
    # ====== SLIDE 2: Scan Overview with Real Metrics ======
    total_critical_high = severity_counts['CRITICAL'] + severity_counts['HIGH']
    
    slide2_data = {
        "title": "Vulnerability Assessment Summary",
        "baseline_status": {
            "title": "Scan Coverage Summary",
            "columns": ["Metric", "Count"],
            "rows": [
                ["Total assets scanned", str(len(unique_ips))],
                ["Networks covered", str(len(network_analysis))],
                ["Total vulnerabilities identified", str(len(vulnerabilities))],
                ["CVEs mapped", str(summary.get("total_cves_found", 0))]
            ],
            "footnote": "* Comprehensive vulnerability assessment completed"
        },
        "baselining_failures": {
            "title": "Risk Priority Distribution",
            "columns": ["Risk Level", "Count"],
            "rows": [
                ["Critical Priority", str(severity_counts['CRITICAL'])],
                ["High Priority", str(severity_counts['HIGH'])],
                ["Medium Priority", str(severity_counts['MEDIUM'])],
                ["Low Priority", str(severity_counts['LOW'])],
                ["PCI Compliance Impact", str(pci_impact_count)]
            ],
            "footnote": "** Risk levels based on CVSS scores and business impact"
        },
        "vulnerability_summary": {
            "columns": ["Vulnerability Category", "Critical", "High", "Medium", "Low", "Info", "Grand Total"],
            "rows": [
                ["SSL/TLS & Certificates", 
                 str(sum(1 for v in vuln_categories['SSL/TLS & Certificates'] if v.get('severity_summary', {}).get('CRITICAL', 0) > 0)),
                 str(sum(1 for v in vuln_categories['SSL/TLS & Certificates'] if v.get('severity_summary', {}).get('HIGH', 0) > 0)),
                 str(sum(1 for v in vuln_categories['SSL/TLS & Certificates'] if v.get('severity_summary', {}).get('MEDIUM', 0) > 0)),
                 str(sum(1 for v in vuln_categories['SSL/TLS & Certificates'] if v.get('severity_summary', {}).get('LOW', 0) > 0)),
                 "",
                 str(len(vuln_categories['SSL/TLS & Certificates']))],
                ["SSH & Cryptography",
                 str(sum(1 for v in vuln_categories['SSH & Cryptography'] if v.get('severity_summary', {}).get('CRITICAL', 0) > 0)),
                 str(sum(1 for v in vuln_categories['SSH & Cryptography'] if v.get('severity_summary', {}).get('HIGH', 0) > 0)),
                 str(sum(1 for v in vuln_categories['SSH & Cryptography'] if v.get('severity_summary', {}).get('MEDIUM', 0) > 0)),
                 "",
                 "",
                 str(len(vuln_categories['SSH & Cryptography']))],
                ["OS & System Updates",
                 "",
                 str(sum(1 for v in vuln_categories['OS & System Updates'] if v.get('severity_summary', {}).get('HIGH', 0) > 0)),
                 str(sum(1 for v in vuln_categories['OS & System Updates'] if v.get('severity_summary', {}).get('MEDIUM', 0) > 0)),
                 "",
                 "",
                 str(len(vuln_categories['OS & System Updates']))],
                ["Web Server & Applications",
                 str(sum(1 for v in vuln_categories['Web Server & Applications'] if v.get('severity_summary', {}).get('CRITICAL', 0) > 0)),
                 str(sum(1 for v in vuln_categories['Web Server & Applications'] if v.get('severity_summary', {}).get('HIGH', 0) > 0)),
                 str(sum(1 for v in vuln_categories['Web Server & Applications'] if v.get('severity_summary', {}).get('MEDIUM', 0) > 0)),
                 "",
                 "",
                 str(len(vuln_categories['Web Server & Applications']))],
                ["Configuration & Hardening",
                 "",
                 str(sum(1 for v in vuln_categories['Configuration & Hardening'] if v.get('severity_summary', {}).get('HIGH', 0) > 0)),
                 str(sum(1 for v in vuln_categories['Configuration & Hardening'] if v.get('severity_summary', {}).get('MEDIUM', 0) > 0)),
                 str(sum(1 for v in vuln_categories['Configuration & Hardening'] if v.get('severity_summary', {}).get('LOW', 0) > 0)),
                 "",
                 str(len(vuln_categories['Configuration & Hardening']))]
            ]
        },
        "legends": [
            {"term": "SSL/TLS & Certificates", "description": "Certificate validation, encryption, and PKI-related vulnerabilities"},
            {"term": "SSH & Cryptography", "description": "SSH configuration, deprecated cryptographic algorithms"},
            {"term": "OS & System Updates", "description": "Operating system and kernel security updates"},
            {"term": "Web Server & Applications", "description": "Web server configuration and application security"},
            {"term": "Configuration & Hardening", "description": "System hardening and security configuration issues"}
        ],
        "timeline": {
            "columns": ["Priority", "CVSS Range", "Remediation SLA", "Business Impact"],
            "rows": [
                ["Critical", "9.0-10.0", "24-48 hours", "Immediate system compromise possible"],
                ["High", "7.0-8.9", "7 days", "Significant security risk"],
                ["Medium", "4.0-6.9", "30 days", "Moderate risk requiring attention"],
                ["Low", "0.1-3.9", "90 days", "Low risk for scheduled maintenance"]
            ]
        },
        "disclaimer": "* SLA based on CVSS scores and business criticality assessment"
    }
    slide_data_list.append(slide2_data)
    
    # ====== SLIDE 3: Critical Risk Analysis ======
    critical_vulns_data = []
    high_vulns_data = []

    for vuln in vulnerabilities:
        severity_summary = vuln.get('severity_summary', {})
        title = vuln.get('original_data', {}).get('Title', 'Unknown')
        cve_results = vuln.get('cve_results', [])
        total_cves = len(cve_results)
        
        # Extract CVE IDs from cve_results
        cve_ids = []
        for cve_result in cve_results:
            if hasattr(cve_result, 'cve_id'):
                cve_ids.append(cve_result.cve_id)
            elif isinstance(cve_result, dict) and 'cve_id' in cve_result:
                cve_ids.append(cve_result['cve_id'])
            elif isinstance(cve_result, str):
                # Handle string representation of CVEResult objects
                if cve_result.startswith('CVE-'):
                    cve_ids.append(cve_result)
                elif 'cve_id=' in cve_result:
                    # Extract CVE ID from string like "CVEResult(cve_id='CVE-2024-4282', ...)"
                    import re
                    match = re.search(r"cve_id='([^']+)'", cve_result)
                    if match:
                        cve_ids.append(match.group(1))
        
        # Join CVE IDs with commas, limit display if too many
        if len(cve_ids) > 3:
            cve_ids_display = ', '.join(cve_ids[:3]) + f' (+{len(cve_ids)-3} more)'
        else:
            cve_ids_display = ', '.join(cve_ids) if cve_ids else 'No CVE IDs'
        
        # Check if has critical vulnerabilities
        if severity_summary.get('CRITICAL', 0) > 0:
            critical_vulns_data.append([
                title,
                cve_ids_display,
                str(total_cves)
            ])
        
        # Check if has high vulnerabilities  
        if severity_summary.get('HIGH', 0) > 0:
            high_vulns_data.append([
                title,
                cve_ids_display,
                str(total_cves)
            ])

    slide3_data = {
        "title": "Critical & High Risk Vulnerability Analysis",
        "subtitle1": f"Critical Severity Vulnerabilities ({len(critical_vulns_data)} identified)",
        "table1": {
            "columns": ["Vulnerability Title", "CVE IDs", "Total CVEs"],
            "rows": critical_vulns_data if critical_vulns_data else [["No critical vulnerabilities identified", "", "0"]]
        },
        "subtitle2": f"High Severity Vulnerabilities ({len(high_vulns_data)} identified)",
        "table2": {
            "columns": ["Vulnerability Title", "CVE IDs", "Total CVEs"],
            "rows": high_vulns_data if high_vulns_data else [["No high severity vulnerabilities identified", "", "0"]]
        },
        "footnote": {
            "Risk": f"Immediate remediation required for {len(critical_vulns_data) + len(high_vulns_data)} vulnerabilities",
            "Impact": f"PCI compliance affected by {sum(1 for v in vulnerabilities if v.get('original_data', {}).get('PCI Vuln') == 'yes')} vulnerabilities"
        }
    }
    slide_data_list.append(slide3_data)
    
    # ====== SLIDE 4: Category-wise Analysis ======
    ssl_analysis = []
    ssh_analysis = []
    
    for vuln in vuln_categories['SSL/TLS & Certificates'][:10]:
        original = vuln.get('original_data', {})
        ip = original.get('IP', 'Unknown')
        severity_summary = vuln.get('severity_summary', {})
        total_severity = sum(severity_summary.values())
        
        ssl_analysis.append([
            f"{ip} - {original.get('Title', '')[:40]}...",
            str(severity_summary.get('CRITICAL', 0)) if severity_summary.get('CRITICAL', 0) > 0 else "",
            str(severity_summary.get('HIGH', 0)) if severity_summary.get('HIGH', 0) > 0 else "",
            str(severity_summary.get('MEDIUM', 0)) if severity_summary.get('MEDIUM', 0) > 0 else "",
            str(severity_summary.get('LOW', 0)) if severity_summary.get('LOW', 0) > 0 else "",
            str(total_severity)
        ])
    
    for vuln in vuln_categories['SSH & Cryptography'][:10]:
        original = vuln.get('original_data', {})
        ip = original.get('IP', 'Unknown')
        severity_summary = vuln.get('severity_summary', {})
        total_severity = sum(severity_summary.values())
        
        ssh_analysis.append([
            f"{ip} - {original.get('Title', '')[:40]}...",
            str(severity_summary.get('CRITICAL', 0)) if severity_summary.get('CRITICAL', 0) > 0 else "",
            str(total_severity)
        ])
    
    slide4_data = {
        "title": "Detailed Category Analysis",
        "subtitle1": "SSL/TLS & Certificate Vulnerabilities",
        "table1": {
            "columns": ["Asset & Vulnerability", "Critical", "High", "Medium", "Low", "Total"],
            "rows": ssl_analysis if ssl_analysis else [["No SSL/TLS vulnerabilities found", "", "", "", "", "0"]]
        },
        "subtitle2": "SSH & Cryptographic Configuration Issues",
        "table2": {
            "columns": ["Asset & Vulnerability", "Critical/High", "Total"],
            "rows": ssh_analysis if ssh_analysis else [["No SSH vulnerabilities found", "", "0"]]
        }
    }
    slide_data_list.append(slide4_data)
    
    # ====== SLIDE 5: Network & Asset Analysis ======
    network_vuln_analysis = []
    for network, ips in network_analysis.items():
        network_vulns = [v for v in vulnerabilities if v.get('original_data', {}).get('Network') == network]
        critical_count = sum(1 for v in network_vulns if v.get('severity_summary', {}).get('CRITICAL', 0) > 0)
        high_count = sum(1 for v in network_vulns if v.get('severity_summary', {}).get('HIGH', 0) > 0)
        medium_count = sum(1 for v in network_vulns if v.get('severity_summary', {}).get('MEDIUM', 0) > 0)
        total_vulns = len(network_vulns)
        
        network_vuln_analysis.append([
            network,
            str(len(ips)),
            str(critical_count),
            str(high_count),
            str(medium_count),
            str(total_vulns)
        ])
    
    slide5_data = {
        "title": "Network Security Analysis",
        "subtitle": "Vulnerability Distribution by Network Segment",
        "table": {
            "columns": ["Network", "Assets", "Critical", "High", "Medium", "Total Vulns"],
            "rows": network_vuln_analysis if network_vuln_analysis else [["No network data available", "0", "0", "0", "0", "0"]]
        }
    }
    slide_data_list.append(slide5_data)
    
    # ====== SLIDE 6: Remediation Strategy (Using actual remediation data) ======
    slide6_data, remediation_stats = create_remediation_slide(vulnerabilities, summary)
    slide_data_list.append(slide6_data)
    
    # Generate dynamic slide7 data
    critical_actions_dynamic = create_dynamic_critical_actions(vulnerabilities)

    slide7_data = {
        "title": "Phase 1: Critical Vulnerability Response Plan - Action Items",
        "subtitle": f"Critical Assets Requiring Immediate Attention ({len(critical_actions_dynamic)} items)",
        "table": {
            "columns": [
                "Asset & Network Location", 
                "Vulnerability Description", 
                "Critical", 
                "High", 
                "Medium", 
                "Low",
                "CVE IDs & CVSS Score",
                "Business Impact Context"
            ],
            "rows": critical_actions_dynamic if critical_actions_dynamic else [
                ["No critical vulnerabilities requiring immediate action"] + [""] * 8
            ]
        }
    }
    slide_data_list.append(slide7_data)

    
    # SLIDE 8: High Priority Actions
    high_actions_dynamic = create_dynamic_high_actions(vulnerabilities)

    slide8_data = {
        "title": "Phase 1: High Priority Remediation Items - Action Plan",
        "subtitle": f"High Priority Assets Requiring Priority Attention ({len(high_actions_dynamic)} items)",
        "table": {
            "columns": [
                "Asset & Network Location", 
                "Vulnerability Description", 
                "Critical", 
                "High", 
                "Medium", 
                "Low",
                "CVE IDs & CVSS Score",
                "Business Impact Context"
            ],
            "rows": high_actions_dynamic if high_actions_dynamic else [
                ["No high priority vulnerabilities requiring immediate action"] + [""] * 7
            ]
        }
    }
    slide_data_list.append(slide8_data)
    
    # SLIDE 9: Business Impact & Compliance
    slide9_data = create_enhanced_slide9_data(vulnerabilities, pci_impact_count)
    slide_data_list.append(slide9_data)
    
    # SLIDE 10: Next Steps & Monitoring
    slide10_data = create_enhanced_slide10_data(vulnerabilities, severity_counts, remediation_stats)
    slide_data_list.append(slide10_data)
    
    return slide_data_list


# Enhanced main function
def generate_ppt_from_vulnerability_data(json_file_path: str, output_filename: str = "Vulnerability_Assessment_Report.pptx"):
    """
    Generate intelligent PowerPoint from vulnerability JSON data
    """
    try:
        slide_data_list = transform_vulnerability_data_to_slides(json_file_path)
        print(f"✅ Successfully generated {len(slide_data_list)} structured slides")
        print(f"📊 Data-driven analysis completed")
        return slide_data_list
    except Exception as e:
        print(f"❌ Error processing vulnerability data: {str(e)}")
        return []

# Example usage
if __name__ == "__main__":
    slide_data = generate_ppt_from_vulnerability_data("data.json")
    
    if slide_data:
        print(f"\n🎯 Generated comprehensive vulnerability assessment with:")
        print(f"   • Dynamic data analysis")
        print(f"   • CVE-based risk scoring")  
        print(f"   • Business impact assessment")
        print(f"   • Actionable remediation plans")
        
        # Call PPT generation
        main(*slide_data[:10])
