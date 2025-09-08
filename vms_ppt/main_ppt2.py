import json
from ppt import main
from collections import defaultdict, Counter

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
        "title": "Vulnerability Assessment Overview",
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
    # Get actual critical and high severity vulnerabilities with CVE data
    critical_vulns_data = []
    high_vulns_data = []
    
    for vuln in vulnerabilities:
        severity_summary = vuln.get('severity_summary', {})
        title = vuln.get('original_data', {}).get('Title', 'Unknown')
        cvss_score = vuln.get('highest_score', 0)
        
        if severity_summary.get('CRITICAL', 0) > 0:
            critical_vulns_data.append([
                title[:60] + "..." if len(title) > 60 else title,
                str(severity_summary.get('CRITICAL', 0)),
                "",
                "",
                str(severity_summary.get('CRITICAL', 0))
            ])
        
        if severity_summary.get('HIGH', 0) > 0:
            high_vulns_data.append([
                title[:60] + "..." if len(title) > 60 else title,
                "",
                str(severity_summary.get('HIGH', 0)),
                "",
                str(severity_summary.get('HIGH', 0))
            ])
    
    slide3_data = {
        "title": "Critical & High Risk Vulnerability Analysis",
        "subtitle1": f"Critical Severity Vulnerabilities ({len(critical_vulns_data)} identified)",
        "table1": {
            "columns": ["Vulnerability Description", "CRITICAL", "HIGH", "MEDIUM", "Total"],
            "rows": critical_vulns_data[:8] if critical_vulns_data else [["No critical vulnerabilities identified", "", "", "", "0"]]
        },
        "subtitle2": f"High Severity Vulnerabilities ({len(high_vulns_data)} identified)",
        "table2": {
            "columns": ["Vulnerability Description", "CRITICAL", "HIGH", "MEDIUM", "Total"],
            "rows": high_vulns_data[:8] if high_vulns_data else [["No high severity vulnerabilities identified", "", "", "", "0"]]
        },
        "footnote": {
            "Risk": f"Immediate remediation required for {total_critical_high} vulnerabilities",
            "Impact": f"PCI compliance affected by {pci_impact_count} vulnerabilities"
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
    remediation_stats = {
        'immediate': 0,
        'high_priority': 0,
        'standard': 0,
        'low_priority': 0
    }
    
    for vuln in vulnerabilities:
        risk_data = vuln.get('risk_assessment_data', [])
        for risk in risk_data:
            urgency = risk.get('risk_assessment', {}).get('remediation_urgency', '')
            if 'Immediate' in urgency or '24 hours' in urgency:
                remediation_stats['immediate'] += 1
            elif 'High Priority' in urgency or '72 hours' in urgency:
                remediation_stats['high_priority'] += 1
            elif 'Standard Priority' in urgency or '2 weeks' in urgency:
                remediation_stats['standard'] += 1
            else:
                remediation_stats['low_priority'] += 1
    
    slide6_data = {
        "title": "Strategic Remediation Plan",
        "stage1_title": "Phase 1: Critical Response (0-30 days)",
        "stage2_title": "Phase 2: Systematic Remediation (30-90 days)",
        "stage1_table": {
            "columns": ["Priority", "Description", "Count", "Target SLA", "Resources", "Status"],
            "rows": [
                ["P0", "Immediate Action Required", str(remediation_stats['immediate']), "24-48 hours", "Security Team", "In Progress"],
                ["P1", "Critical Business Risk", str(remediation_stats['high_priority']), "72 hours", "IT + Security", "Planned"],
                ["P2", "High Impact Vulnerabilities", str(severity_counts['HIGH']), "7-14 days", "IT Team", "Scheduled"],
                ["P3", "PCI Compliance Issues", str(pci_impact_count), "14-30 days", "Compliance Team", "Queued"]
            ]
        },
        "stage2_table": {
            "columns": ["Priority", "Description", "Count", "Target SLA", "Resources", "Status"],
            "rows": [
                ["P4", "Medium Risk Items", str(remediation_stats['standard']), "30-60 days", "IT Team", "Planned"],
                ["P5", "Configuration Hardening", str(len(vuln_categories['Configuration & Hardening'])), "60-90 days", "System Admins", "Planned"],
                ["P6", "Process Improvements", "TBD", "Ongoing", "All Teams", "Future"],
                ["P7", "Security Awareness", "TBD", "Quarterly", "HR + Security", "Future"]
            ]
        },
        "footnote": f"**Total remediation items: {len(vulnerabilities)} | Estimated effort: {summary.get('total_remediations_generated', 0)} action items"
    }
    slide_data_list.append(slide6_data)
    
    
    # SLIDE 7: Critical Actions
    critical_actions = []
    for vuln in vulnerabilities:
        if vuln.get('severity_summary', {}).get('CRITICAL', 0) > 0:
            original = vuln.get('original_data', {})
            remediation_data = vuln.get('remediation_data', [])
            effort = "2-6 hours"  # Default
            if remediation_data:
                effort = remediation_data[0].get('remediation', {}).get('Estimated Effort', '2-6 hours')
            
            critical_actions.append([
                f"{original.get('IP', '')} - {original.get('Title', '')[:50]}...",
                "1",
                "",
                "",
                "",
                effort
            ])
    
    slide7_data = {
        "title": "Phase 1: Critical Vulnerability Response Plan",
        "table": {
            "columns": ["Asset & Vulnerability", "Critical", "High", "Medium", "Low", "Est. Effort"],
            "rows": critical_actions[:15] if critical_actions else [["No critical vulnerabilities requiring immediate action", "", "", "", "", ""]]
        }
    }
    slide_data_list.append(slide7_data)
    
    # SLIDE 8: High Priority Actions
    high_actions = []
    for vuln in vulnerabilities:
        if vuln.get('severity_summary', {}).get('HIGH', 0) > 0:
            original = vuln.get('original_data', {})
            remediation_data = vuln.get('remediation_data', [])
            effort = "2-6 hours"
            if remediation_data:
                effort = remediation_data[0].get('remediation', {}).get('Estimated Effort', '2-6 hours')
            
            high_actions.append([
                f"{original.get('IP', '')} - {original.get('Title', '')[:50]}...",
                "",
                "1",
                "",
                "",
                effort
            ])
    
    slide8_data = {
        "title": "Phase 1: High Priority Remediation Items",
        "table": {
            "columns": ["Asset & Vulnerability", "Critical", "High", "Medium", "Low", "Est. Effort"],
            "rows": high_actions[:15] if high_actions else [["No high priority vulnerabilities identified", "", "", "", "", ""]]
        }
    }
    slide_data_list.append(slide8_data)
    
    # SLIDE 9: Business Impact & Compliance
    pci_vulns = []
    compliance_impact = []
    
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        if original.get('PCI Vuln', '').lower() == 'yes':
            pci_vulns.append([
                original.get('IP', ''),
                original.get('Title', '')[:60] + "..." if len(original.get('Title', '')) > 60 else original.get('Title', '')
            ])
    
    # Business impact analysis
    risk_categories = list(risk_distribution.keys())
    compliance_impact = [
        ['PCI DSS Compliance', str(pci_impact_count)],
        ['Critical Business Systems', str(len([v for v in vulnerabilities if 'Critical' in str(v.get('risk_assessment_data', []))]))],
        ['Public-facing Assets', str(len([v for v in vulnerabilities if v.get('original_data', {}).get('SSL', '') == 'over ssl']))],
        ['Legacy Systems (EOL)', str(len([v for v in vulnerabilities if 'EOL' in v.get('original_data', {}).get('Title', '')]))]
    ]
    
    slide9_data = {
        'title': 'Business Impact & Compliance Analysis',
        'tables': [
            {
                'columns': ['Impact Category', 'Affected Count'],
                'rows': compliance_impact
            },
            {
                'columns': ['Asset IP', 'PCI-Related Vulnerability'],
                'rows': pci_vulns[:10] if pci_vulns else [['No PCI-related vulnerabilities', 'N/A']]
            }
        ]
    }
    slide_data_list.append(slide9_data)
    
    # SLIDE 10: Next Steps & Monitoring
    next_steps = []
    monitoring_items = []
    
    # Generate actionable next steps based on data
    if remediation_stats['immediate'] > 0:
        next_steps.append(['Emergency Response Team Activation', 'Critical', str(remediation_stats['immediate']), '24-48 hours'])
    
    if pci_impact_count > 0:
        next_steps.append(['PCI Compliance Review', 'High', str(pci_impact_count), '7 days'])
    
    if len(vuln_categories['SSL/TLS & Certificates']) > 0:
        next_steps.append(['Certificate Management Audit', 'Medium', str(len(vuln_categories['SSL/TLS & Certificates'])), '14 days'])
    
    next_steps.extend([
        ['Patch Management Process Review', 'Medium', 'Ongoing', '30 days'],
        ['Security Monitoring Enhancement', 'Low', 'Process', '60 days'],
        ['Vulnerability Scanning Automation', 'Low', 'Technology', '90 days']
    ])
    
    slide10_data = {
        'title': 'Implementation Roadmap & Next Steps',
        'table': {
            'columns': ['Action Item', 'Priority', 'Scope', 'Timeline'],
            'rows': next_steps
        }
    }
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
