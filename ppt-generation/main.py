from pptx.util import Cm
from components.chart import create_chart
from components.table import create_table
from components.header import create_header
from utils import create_presentation, add_slide
from components.footer import create_complete_slide_layout

# Data configuration
CHART_DATA = {
    'categories': ['Critical', 'High', 'Medium', 'Low'],
    'values': (0, 0, 5, 3)
}

TABLE_DATA = [
    ["Vulnerability", "Severity"],
    ["Weak ciphers", "Medium"],
    ["Improper input validation", "Medium"],
    ["Missing file upload validation", "Medium"],
    ["Missing security Headers", "Medium"],
    ["Missing Cookie attributes-Http only, secure flag", "Medium"],
    ["Data exposure", "Low"],
    ["Weak Hashing Algorithm", "Low"],
    ["Vulnerable Bootstrap and jQuery version", "Low"]
]

SECOND_TABLE_DATA = [
    ["Threat Type", "Risks"],
    ["Data exposure", "Usernames are exposed, enabling password attacks that risk unauthorized access, data breaches, and compliance violations."],
    ["Subdomain Takeover", "Subdomains are misconfigured and vulnerable to takeover, allowing attackers to hijack them for phishing or malware, risking brand abuse and user compromise."],
    ["Open Port", "Port 22 is exposed, making the server a target for SSH brute-force attacks, increasing the risk of unauthorized access and server compromise."]
]

RECOMMENDATIONS_DATA = [
        {
            "title": "Assess & Manage",
            "subtitle": "Security performance",
            "icon": "🔧"  # Placeholder for brain/gear icon
        },
        {
            "title": "Continuously Monitor",
            "subtitle": "Critical Vendors", 
            "icon": "📊"  # Placeholder for monitor icon
        },
        {
            "title": "Map to Global Cyber",
            "subtitle": "Security Frameworks",
            "icon": "🌐"  # Placeholder for network/framework icon
        }
    ]

def create_vulnerability_summary():
    """
    Create the vulnerability summary slide
    """
    # Create presentation
    p = create_presentation()
    
    # Add slide with blank layout
    slide = add_slide(p)
    
    # Add header
    create_header(slide, "Vulnerability Summary")
    
    # Add chart
    create_chart(slide, CHART_DATA)
    
    # Add first table
    create_table(slide, TABLE_DATA, 9, 2)
    
    # Add second table
    create_table(slide, SECOND_TABLE_DATA, 4, 2, 
                left=Cm(1), top=Cm(11), width=Cm(19), height=Cm(4.5),
                column_widths=[Cm(4), Cm(15)], is_second_table=True)
    
    # Create the complete two-column layout
    create_complete_slide_layout(slide, RECOMMENDATIONS_DATA)
    
    # Save presentation
    p.save('vulnerability_summary_with_table.pptx')
    print("Vulnerability summary with table created successfully!")

if __name__ == "__main__":
    create_vulnerability_summary()