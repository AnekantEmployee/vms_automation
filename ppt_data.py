from pptx.dml.color import RGBColor

TEXT_BLACK = RGBColor(0, 0, 0)
LIGHT_BLUE = RGBColor(0, 176, 240)  
DARK_BLUE = RGBColor(7, 128, 181)
WHITE = RGBColor(255, 255, 255)
LIGHT_SKY_BLUE = RGBColor(213, 239, 255)
YELLOW = RGBColor(255, 192, 0)



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
        "image_path": "ppt-generation/bg/icons/img1.png",
        "image_size": 0.5,  # Size in cm (controllable)
        "fallback_icon": "🔧"  # Fallback if image fails
    },
    {
        "title": "Continuously Monitor",
        "subtitle": "Critical Vendors",
        "image_path": "ppt-generation/bg/icons/img2.png",
        "image_size": 0.5,  # Different size for this icon
        "fallback_icon": "📊"  # Fallback if image fails
    },
    {
        "title": "Map to Global Cyber",
        "subtitle": "Security Frameworks",
        "image_path": "ppt-generation/bg/icons/img3.png",
        "image_size": 0.5,  # Another size option
        "fallback_icon": "🌐"  # Fallback if image fails
    }
]

SECOND_TABLE_DATA = [
    ["Threat Type", "Risks"],
    ["Data exposure", "Usernames are exposed, enabling password attacks that risk unauthorized access, data breaches, and compliance violations."],
    ["Subdomain Takeover", "Subdomains are misconfigured and vulnerable to takeover, allowing attackers to hijack them for phishing or malware, risking brand abuse and user compromise."],
    ["Open Port", "Port 22 is exposed, making the server a target for SSH brute-force attacks, increasing the risk of unauthorized access and server compromise."]
]

VULNERABILITIES = [
        {
            'icon': 'ppt-generation/bg/icons/img1.png',
            'text': 'The "Get Quote" page of Honestycar website lacks input validation, risking script-based attacks that could expose data, damage brand trust, and trigger compliance issues.'
        },
        {
            'icon': 'ppt-generation/bg/icons/img1.png',
            'text': 'Honestycar website supports outdated TLS 1.0/1.1 protocols, exposing it to known attacks and putting encrypted data, compliance, and customer trust at risk.'
        },
        {
            'icon': 'ppt-generation/bg/icons/img1.png',
            'text': 'The web application accepts SVG and GIF files with malicious content, risking code execution in users browsers, potentially leading to session hijacking and user data compromise.'
        },
        {
            'icon': 'ppt-generation/bg/icons/img1.png',
            'text': 'Missing security headers in the Honestycar website increase exposure to cross-site scripting, clickjacking, and other web attacks, putting user data and session integrity at risk.'
        }
    ]