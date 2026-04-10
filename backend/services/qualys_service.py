import requests
import xml.etree.ElementTree as ET
import os
from dotenv import load_dotenv

load_dotenv()

QUALYS_BASE_URL = os.getenv("QUALYS_BASE_URL", "qualysguard.qg1.apps.qualys.in")
USERNAME        = os.getenv("QUALYS_USERNAME")
PASSWORD        = os.getenv("QUALYS_PASSWORD")

BASE_URL = f"https://{QUALYS_BASE_URL}/api/2.0/fo/knowledge_base/vuln/"
HEADERS  = {
    "X-Requested-With": "Python-Demo",
    "Content-Type": "application/x-www-form-urlencoded",
}
AUTH = (USERNAME, PASSWORD)


def _kb_request(params: dict) -> ET.Element:
    params["action"] = "list"
    try:
        response = requests.post(BASE_URL, headers=HEADERS, auth=AUTH, data=params, stream=True, timeout=300)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Could not connect to '{QUALYS_BASE_URL}'.")
    except requests.exceptions.Timeout:
        raise RuntimeError("Request timed out.")

    if not response.ok:
        try:
            root = ET.fromstring(response.content)
            code = root.findtext(".//CODE") or str(response.status_code)
            text = root.findtext(".//TEXT") or "No details returned."
            raise RuntimeError(f"Qualys API Error {code}: {text} (HTTP {response.status_code})")
        except ET.ParseError:
            raise RuntimeError(f"HTTP {response.status_code} {response.reason}: {response.text[:500]}")

    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as e:
        raise RuntimeError(f"Could not parse XML: {e}")

    api_error = root.find(".//API_ERROR") or root.find(".//SIMPLE_RETURN/RESPONSE")
    if api_error is not None:
        code = api_error.findtext("CODE") or "?"
        text = api_error.findtext("TEXT") or "Unknown API error"
        raise RuntimeError(f"Qualys API Error {code}: {text}")

    return root


def debug_raw_xml(root: ET.Element) -> str:
    """Temporary: returns raw XML of first VULN for debugging."""
    vuln = root.find(".//VULN")
    return ET.tostring(vuln, encoding="unicode") if vuln is not None else ""


def _parse_vulns(root: ET.Element) -> list[dict]:
    vulns = []
    for vuln in root.findall(".//VULN"):
        def get(tag):
            el = vuln.find(tag)
            return el.text.strip() if el is not None and el.text else ""

        def get_all(tag):
            return [el.text.strip() for el in vuln.findall(tag) if el.text]

        def get_html(tag):
            el = vuln.find(tag)
            if el is None:
                return ""
            return (ET.tostring(el, encoding="unicode", method="text") or "").strip()

        record = {
            # Identity
            "qid":                  get("QID"),
            "vuln_type":            get("VULN_TYPE"),
            "severity":             get("SEVERITY_LEVEL"),
            "title":                get("TITLE"),
            "category":             get("CATEGORY"),
            "sub_category":         get("SUB_CATEGORY"),
            # Dates
            "published":            get("PUBLISHED_DATETIME"),
            "last_modified":        get("LAST_SERVICE_MODIFICATION_DATETIME"),
            # Patch info
            "patchable":            get("PATCHABLE"),
            "virtual_patch":        get("VIRTUAL_PATCH_AVAILABLE"),
            "patch_published":      get("PATCH_PUBLISHED_DATETIME") or get("CORRELATION/PATCH_PUBLISHED_DATETIME"),
            # CVSS v2
            "cvss_base":            get("CVSS/BASE"),
            "cvss_temporal":        get("CVSS/TEMPORAL"),
            "cvss_vector":          get("CVSS/VECTOR_STRING"),
            "cvss_access_vector":   get("CVSS/ACCESS"),
            # CVSS v3
            "cvss3_base":           get("CVSS_V3/BASE"),
            "cvss3_temporal":       get("CVSS_V3/TEMPORAL"),
            "cvss3_vector":         get("CVSS_V3/VECTOR_STRING"),
            "cvss3_attack_vector":  get("CVSS_V3/ATTACK"),
            # References
            "cve_ids":              get_all(".//CVE_LIST/CVE/ID"),
            "bugtraq_ids":          get_all(".//BUGTRAQ_LIST/BUGTRAQ/ID"),
            "vendor_refs":          get_all(".//VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/ID"),
            # Threat intelligence
            "threat_intel":         ", ".join([
                ti.find("LABEL").text
                for ti in vuln.findall(".//THREAT_INTELLIGENCE/THREAT_INTEL")
                if ti.find("LABEL") is not None
            ]),
            # Affected software
            "affected_software":    get_all(".//SOFTWARE_LIST/SOFTWARE/PRODUCT"),
            # Compliance
            "compliance":           [
                {
                    "type":        c.findtext("TYPE") or "",
                    "section":     c.findtext("SECTION") or "",
                    "description": c.findtext("DESCRIPTION") or "",
                }
                for c in vuln.findall(".//COMPLIANCE_LIST/COMPLIANCE")
            ],
            # Discovery
            "discovery_remote":     get("DISCOVERY/REMOTE"),
            "discovery_auth":       ", ".join([
                el.text.strip()
                for el in vuln.findall(".//DISCOVERY/AUTH_TYPE_LIST/AUTH_TYPE")
                if el.text
            ]),
            # Affected versions
            "affected_products":    get_html("AFFECTED_PRODUCTS"),
            # Supported modules
            "supported_modules":    get("SUPPORTED_MODULES"),
            # Edited
            "edited":               get("EDITED"),
            # Ownership / dates
            "owner":                get("OWNER"),
            "created":              get("CREATION_DATETIME"),
            "user_modified":        get("USER_MODIFIED_DATETIME"),
            "modified_by":          get("MODIFIED_BY"),
            "code_modified":        get("CODE_MODIFIED_DATETIME"),
            # Content
            "diagnosis":            get_html("DIAGNOSIS"),
            "consequence":          get_html("CONSEQUENCE"),
            "solution":             get_html("SOLUTION"),
            "exploitability":       get("CORRELATION/EXPLOITABILITY") or get("EXPLOITABILITY") or get(".//EXPLOITABILITY"),
            "associated_malware":   get("ASSOCIATED_MALWARE") or get(".//ASSOCIATED_MALWARE"),
            "news_or_patch":        get("NEWS_OR_PATCH"),
            "is_disabled":          get("IS_DISABLED"),
            "is_ignored":           get("IS_IGNORED"),
        }
        vulns.append(record)
    return vulns


def query_by_qids(qids: list[int]) -> list[dict]:
    root = _kb_request({"ids": ",".join(str(q) for q in qids), "details": "All"})
    return _parse_vulns(root)
