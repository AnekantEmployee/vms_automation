import requests

url = "https://api.osv.dev/v1/vulns/OSV-2020-111"

response = requests.get(url)
if response.status_code == 200:
    vulnerability = response.json()
    print(vulnerability)
    # This endpoint returns a single vulnerability, not a list
    print(f"Vulnerability ID: {vulnerability.get('id', 'No ID')}")
    print(f"Summary: {vulnerability.get('summary', 'No summary')}")
    print(f"Severity: {vulnerability.get('affected', [{}])[0].get('ecosystem_specific', {}).get('severity', 'Unknown')}")
    print(f"Published: {vulnerability.get('published', 'Unknown')}")
else:
    print(f"Error: {response.status_code}")
