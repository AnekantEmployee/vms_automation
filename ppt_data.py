from pptx.dml.color import RGBColor

TEXT_BLACK = RGBColor(0, 0, 0)
LIGHT_BLUE = RGBColor(0, 176, 240)  
DARK_BLUE = RGBColor(7, 128, 181)
WHITE = RGBColor(255, 255, 255)



CHART_CATEGORIES = ['Critical', 'High', 'Medium', 'Low']

CHART_VALUES = (0, 0, 5, 3)

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

SECOND_TABLE_DATA = [
    ["Threat Type", "Risks"],
    ["Data exposure", "Usernames are exposed, enabling password attacks that risk unauthorized access, data breaches, and compliance violations."],
    ["Subdomain Takeover", "Subdomains are misconfigured and vulnerable to takeover, allowing attackers to hijack them for phishing or malware, risking brand abuse and user compromise."],
    ["Open Port", "Port 22 is exposed, making the server a target for SSH brute-force attacks, increasing the risk of unauthorized access and server compromise."]
]