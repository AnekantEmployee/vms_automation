import json
from ppt import main
from datetime import datetime
from collections import defaultdict

def transform_vulnerability_data_to_slides(data_json_path: str) -> list:
    """
    Transform vulnerability JSON data into slide_data format for PowerPoint generation
    
    Args:
        data_json_path (str): Path to the JSON file containing vulnerability data
    
    Returns:
        list: List of 10 slide data dictionaries formatted for presentation generation
    """
    
    # Load the JSON data
    with open(data_json_path, 'r', encoding='utf-8') as f:
        data_raw = json.load(f)
    
    # Extract results from the JSON structure
    vulnerabilities = data_raw.get("results", [])
    
    # Initialize slide data list
    slide_data_list = []
    
    # SLIDE 1: Title and Agenda (matches original format exactly)
    slide1_data = {
        'title': 'Enterprise Vulnerability & Patch Management',
        'agenda_points': [
            'Overall vulnerability scan status and summary.',
            'Overall vulnerability summary',
            'Prioritization based on Critical & High severity vulnerabilities',
            'Overall Vulnerability Remediation Strategy and action plans.',
            'Detailed remediation recommendations and next steps.'
        ]
    }
    slide_data_list.append(slide1_data)
    
    # SLIDE 2: Key Highlights (matches original slide2_data format exactly)
    # Count vulnerabilities by status and severity
    status_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    total_vulns = len(vulnerabilities)
    
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        status_counts[original.get('Vuln Status', 'Unknown')] += 1
        severity_counts[original.get('Severity', 'Unknown')] += 1
    
    # Count assets (unique IPs)
    unique_ips = set()
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        ip = original.get('IP', '')
        if ip:
            unique_ips.add(ip)
    
    # Create vulnerability summary by category
    # Group vulnerabilities by categories similar to original
    category_counts = {
        'Critical': severity_counts.get('4', 0),
        'High': severity_counts.get('3', 0), 
        'Medium': severity_counts.get('2', 0),
        'Low': severity_counts.get('1', 0)
    }
    
    # Build vulnerability summary rows
    vuln_summary_rows = []
    categories = ['SSL/TLS Issues', 'SSH Configuration', 'OS Vulnerabilities', 'Web Server Issues']
    
    # Categorize vulnerabilities by title patterns
    ssl_count = sum(1 for v in vulnerabilities if 'SSL' in v.get('original_data', {}).get('Title', '') or 'Certificate' in v.get('original_data', {}).get('Title', ''))
    ssh_count = sum(1 for v in vulnerabilities if 'SSH' in v.get('original_data', {}).get('Title', ''))
    os_count = sum(1 for v in vulnerabilities if 'Ubuntu' in v.get('original_data', {}).get('Title', '') or 'Linux' in v.get('original_data', {}).get('Title', ''))
    web_count = sum(1 for v in vulnerabilities if 'HTTP' in v.get('original_data', {}).get('Title', '') or 'Web' in v.get('original_data', {}).get('Title', ''))
    
    vuln_summary_rows = [
        ['SSL/TLS Issues', str(category_counts.get('Critical', 0)), str(category_counts.get('High', 0)), str(category_counts.get('Medium', 0)), str(category_counts.get('Low', 0)), '', str(ssl_count)],
        ['SSH Configuration', '', str(ssh_count), '', '', '', str(ssh_count)],
        ['OS Vulnerabilities', str(severity_counts.get('4', 0)), '', str(severity_counts.get('2', 0)), '', '', str(os_count)],
        ['Web Server Issues', '', str(severity_counts.get('3', 0)), str(severity_counts.get('2', 0)), '', '', str(web_count)]
    ]

    slide2_data = {
        "title": "Key Highlights: Vulnerability Scan Results",
        "baseline_status": {
            "title": "Overall Scan Status",
            "columns": ["Details", "Count"],
            "rows": [
                ["No. of Assets scanned", str(len(unique_ips))]
            ],
            "footnote": "* Based on latest vulnerability scan"
        },
        "baselining_failures": {
            "title": "Vulnerability Status Summary",
            "columns": ["Status", "Count"],
            "rows": [
                ["Active vulnerabilities", str(status_counts.get('Active', 0))],
                ["New vulnerabilities", str(status_counts.get('New', 0))],
                ["Total vulnerabilities", str(total_vulns)]
            ],
            "footnote": "** Current vulnerability status"
        },
        "vulnerability_summary": {
            "columns": ["Vulnerability Categories/ Rating", "Critical", "High", "Medium", "Low", "Info", "Grand Total"],
            "rows": vuln_summary_rows
        },
        "legends": [
            {
                "term": "SSL/TLS Issues",
                "description": "Certificate and encryption related vulnerabilities"
            },
            {
                "term": "SSH Configuration", 
                "description": "SSH protocol and cryptographic configuration issues"
            },
            {
                "term": "OS Vulnerabilities",
                "description": "Operating system and kernel vulnerabilities"
            },
            {
                "term": "Web Server Issues",
                "description": "Web server configuration and protocol vulnerabilities"
            }
        ],
        "timeline": {
            "columns": ["Severity", "CVSS Score", "Timeline", "Description"],
            "rows": [
                ["Critical", "9.0-10.0", "0 - 02 days", "Immediate action required - system compromise possible"],
                ["High", "7.0-8.9", "0 - 07 days", "High risk vulnerabilities requiring prompt remediation"],
                ["Medium", "4.0-6.9", "0 - 30 days", "Medium risk vulnerabilities for scheduled remediation"],
                ["Low", "0.1-3.9", "0 - 90 days", "Low risk vulnerabilities for maintenance windows"]
            ]
        },
        "disclaimer": "* Remediation timeline based on vulnerability severity and business impact"
    }
    slide_data_list.append(slide2_data)
    
    # SLIDE 3: Critical vulnerabilities (matches original slide3_data format)
    critical_vulns = []
    high_vulns = []
    
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        severity = original.get('Severity', '0')
        title = original.get('Title', '')
        
        if severity == '4' and title:  # Critical
            critical_vulns.append([title, "1", "", "", "1"])
        elif severity == '3' and title:  # High
            high_vulns.append([title, "", "1", "", "1"])
    
    # Limit to top 5 each
    critical_vulns = critical_vulns[:5]
    high_vulns = high_vulns[:5]
    
    slide3_data = {
        "title": "Key Highlights: Critical & High Risk Vulnerabilities",
        "subtitle1": "Critical Severity Vulnerabilities",
        "table1": {
            "columns": ["Vulnerability Title", "CRITICAL", "HIGH", "MEDIUM", "Grand Total"],
            "rows": critical_vulns if critical_vulns else [["No Critical vulnerabilities found", "", "", "", ""]]
        },
        "subtitle2": "High Severity Vulnerabilities", 
        "table2": {
            "columns": ["Vulnerability Title", "CRITICAL", "HIGH", "MEDIUM", "Grand Total"],
            "rows": high_vulns if high_vulns else [["No High severity vulnerabilities found", "", "", "", ""]]
        },
        "footnote": {
            "Risk": "System compromise, Data loss, Service disruption",
            "Impact": "Business operations, Compliance violations, Security incidents"
        }
    }
    slide_data_list.append(slide3_data)
    
    # SLIDE 4: Software and configuration vulnerabilities
    software_vulns = []
    config_vulns = []
    
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        title = original.get('Title', '')
        severity = original.get('Severity', '0')
        
        # Categorize software vs configuration
        if any(term in title.lower() for term in ['software', 'update', 'application', 'browser']):
            row = [title, 
                  "1" if severity == '4' else "",
                  "1" if severity == '3' else "", 
                  "1" if severity == '2' else "",
                  "1" if severity == '1' else "",
                  "1"]
            software_vulns.append(row)
        elif any(term in title.lower() for term in ['configuration', 'ssh', 'ssl', 'hardening']):
            row = [title,
                  "1" if severity == '4' else "",
                  "1" if severity == '2' else "",
                  "1"]
            config_vulns.append(row)
    
    # Limit display
    software_vulns = software_vulns[:10]
    config_vulns = config_vulns[:10]
    
    slide4_data = {
        "title": "Vulnerability Analysis by Category",
        "subtitle1": "Software/Application Vulnerabilities",
        "table1": {
            "columns": ["Software/Application", "Critical", "High", "Medium", "Low", "Grand Total"],
            "rows": software_vulns if software_vulns else [["No software vulnerabilities categorized", "", "", "", "", ""]]
        },
        "subtitle2": "Configuration/Hardening Issues",
        "table2": {
            "columns": ["Configuration Issue", "Critical", "Medium", "Grand Total"],
            "rows": config_vulns if config_vulns else [["No configuration issues categorized", "", "", ""]]
        }
    }
    slide_data_list.append(slide4_data)
    
    # SLIDE 5: OS vulnerabilities breakdown
    os_vulns = []
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        os = original.get('OS', '')
        severity = original.get('Severity', '0')
        
        if os and os != 'Unknown':
            row = [os,
                  "1" if severity == '4' else "",
                  "1" if severity == '3' else "",
                  "1" if severity == '2' else "",
                  "1"]
            os_vulns.append(row)
    
    # Group by OS and count
    os_counts = defaultdict(lambda: {'4': 0, '3': 0, '2': 0, '1': 0})
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        os = original.get('OS', 'Unknown')
        severity = original.get('Severity', '0')
        os_counts[os][severity] += 1
    
    os_rows = []
    for os, counts in list(os_counts.items())[:10]:
        total = sum(counts.values())
        row = [os, str(counts['4']), str(counts['3']), str(counts['2']), str(total)]
        os_rows.append(row)
    
    slide5_data = {
        "title": "Operating System Vulnerability Analysis",
        "subtitle": "Vulnerabilities by Operating System",
        "table": {
            "columns": ["Operating System", "Critical", "High", "Medium", "Grand Total"],
            "rows": os_rows if os_rows else [["No OS data available", "", "", "", ""]]
        }
    }
    slide_data_list.append(slide5_data)
    
    # SLIDE 6: Remediation strategy (matches original slide6_data format)
    slide6_data = {
        "title": "Summary of Vulnerability Remediation Strategy",
        "stage1_title": "Stage - 1: Immediate Remediation Plan",
        "stage2_title": "Stage - 2: Planned Remediation (Future)",
        "stage1_table": {
            "columns": ["#", "Description", "Total", "Remediation Target", "Balance", "Timeline"],
            "rows": [
                ["1", "Critical Vulnerabilities", str(severity_counts.get('4', 0)), str(severity_counts.get('4', 0)), "0", "0-2 days"],
                ["2", "High Severity Issues", str(severity_counts.get('3', 0)), str(severity_counts.get('3', 0)), "0", "0-7 days"],
                ["3", "Medium Severity Issues", str(severity_counts.get('2', 0)), str(severity_counts.get('2', 0) // 2), str(severity_counts.get('2', 0) - (severity_counts.get('2', 0) // 2)), "8-30 days"],
                ["4", "Configuration Issues", str(len(config_vulns)), str(len(config_vulns) // 2), str(len(config_vulns) - (len(config_vulns) // 2)), "15-45 days"]
            ]
        },
        "stage2_table": {
            "columns": ["#", "Description", "Total", "Remediation Target", "Balance", "Timeline"],
            "rows": [
                ["1", "Remaining Medium Issues", str(severity_counts.get('2', 0) - (severity_counts.get('2', 0) // 2)), "TBD", "0", "TBD"],
                ["2", "Low Priority Issues", str(severity_counts.get('1', 0)), "TBD", "0", "TBD"],
                ["3", "Process Improvements", "TBD", "TBD", "0", "TBD"],
                ["4", "Policy Updates", "TBD", "TBD", "0", "TBD"]
            ]
        },
        "footnote": "**Remediation timeline based on severity and business impact"
    }
    slide_data_list.append(slide6_data)
    
    # SLIDE 7: Detailed remediation for stage 1 (critical/high)
    stage1_details = []
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        severity = original.get('Severity', '0')
        if severity in ['4', '3']:
            ip = original.get('IP', '')
            title = original.get('Title', '')
            port = original.get('Port', '')
            
            row = [f"{ip} - {title}", 
                  "1" if severity == '4' else "",
                  "1" if severity == '3' else "", 
                  "",
                  "",
                  "1"]
            stage1_details.append(row)
    
    stage1_details = stage1_details[:15]  # Limit display
    
    slide7_data = {
        "title": "Stage 1 - Critical & High Priority Remediation Details",
        "table": {
            "columns": ["Vulnerability Details", "Critical", "High", "Medium", "Low", "Grand Total"],
            "rows": stage1_details if stage1_details else [["No critical/high vulnerabilities found", "", "", "", "", ""]]
        }
    }
    slide_data_list.append(slide7_data)
    
    # SLIDE 8: Medium priority details
    stage2_details = []
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        severity = original.get('Severity', '0')
        if severity == '2':
            ip = original.get('IP', '')
            title = original.get('Title', '')
            
            row = [f"{ip} - {title}", "", "", "1", "", "1"]
            stage2_details.append(row)
    
    stage2_details = stage2_details[:15]  # Limit display
    
    slide8_data = {
        "title": "Stage 2 - Medium Priority Remediation Details",
        "table": {
            "columns": ["Vulnerability Details", "Critical", "High", "Medium", "Low", "Grand Total"],
            "rows": stage2_details if stage2_details else [["No medium priority vulnerabilities found", "", "", "", "", ""]]
        }
    }
    slide_data_list.append(slide8_data)
    
    # SLIDE 9: Asset and network summary
    network_summary = []
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        network = original.get('Network', 'Unknown')
        ip = original.get('IP', '')
        
        if network and ip:
            network_summary.append([network, ip])
    
    # Group by network
    network_counts = defaultdict(set)
    for vuln in vulnerabilities:
        original = vuln.get('original_data', {})
        network = original.get('Network', 'Unknown')
        ip = original.get('IP', '')
        if network and ip:
            network_counts[network].add(ip)
    
    network_rows = []
    for network, ips in network_counts.items():
        network_rows.append([network, str(len(ips))])
    
    # SLIDE 9: EOL/Obsolete breakdown (match original format)
    slide9_data = {
        'title': 'Vulnerability Categories - Detailed Breakdown',
        'tables': [
            {
                'columns': ['Category', 'Count'],
                'rows': [
                    ['SSL/TLS Issues', str(ssl_count)],
                    ['SSH Configuration', str(ssh_count)],
                    ['OS Vulnerabilities', str(os_count)],
                    ['Web Server Issues', str(web_count)]
                ]
            },
            {
                'columns': ['Network', 'Vulnerabilities'],
                'rows': network_rows if network_rows else [['No network data', '0']]
            }
        ]
    }
    slide_data_list.append(slide9_data)
    
    # SLIDE 10: Next steps and recommendations
    recommendations = []
    if severity_counts.get('4', 0) > 0:
        recommendations.append(['Address Critical Vulnerabilities', '', str(severity_counts.get('4', 0)), str(severity_counts.get('4', 0))])  # 4 columns
    if severity_counts.get('3', 0) > 0:
        recommendations.append(['Remediate High Severity Issues', '', str(severity_counts.get('3', 0)), str(severity_counts.get('3', 0))])  # 4 columns
    if severity_counts.get('2', 0) > 0:
        recommendations.append(['Plan Medium Priority Fixes', '', str(severity_counts.get('2', 0)), str(severity_counts.get('2', 0))])  # 4 columns

    recommendations.extend([
        ['Implement Security Monitoring', '', '', 'Ongoing'],
        ['Regular Vulnerability Scanning', '', '', 'Monthly'],
        ['Security Awareness Training', '', '', 'Quarterly'],
        ['Patch Management Process', '', '', 'Continuous']
    ])

    slide10_data = {
        'title': 'Stage 1 - Configuration Issues Breakdown',
        'table': {
            'columns': ['Configuration Issue', 'Critical', 'Medium', 'Grand Total'],  # 4 columns
            'rows': recommendations
        }
    }
    slide_data_list.append(slide10_data)
    
    return slide_data_list

def generate_ppt_from_vulnerability_data(json_file_path: str, output_filename: str = "Vulnerability_Report.pptx"):
    """
    Main function to generate PowerPoint from vulnerability JSON data
    """
    slide_data_list = transform_vulnerability_data_to_slides(json_file_path)
    return slide_data_list

# Example usage:
if __name__ == "__main__":
    slide_data = generate_ppt_from_vulnerability_data("data.json")
    print("Generated slide data structure:")
    print(f"Total slides: {len(slide_data)}")
    
    # Call the main PPT generation function
    main(slide_data[0], slide_data[1], slide_data[2], slide_data[3], slide_data[4], 
         slide_data[5], slide_data[6], slide_data[7], slide_data[8], slide_data[9])
