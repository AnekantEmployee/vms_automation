import re
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of CVE validation"""
    is_relevant: bool
    confidence_score: float  # 0.0 to 1.0
    relevance_reasons: List[str]
    warning_flags: List[str]


class CVEValidator:
    """Validates CVE relevance to vulnerability context"""
    
    def __init__(self):
        # Generic vulnerability indicators that shouldn't map to specific product CVEs
        self.generic_indicators = [
            "deprecated",
            "self-signed certificate",
            "certificate verification",
            "weak cipher",
            "plain-text",
            "http authentication",
            "ssh configuration",
            "ssl configuration"
        ]
        
        # Product-specific CVE patterns
        self.product_specific_patterns = [
            r'windows\s+(server|xp|vista|7|8|10|11)',
            r'(brocade|cisco|fortinet|palo alto)',
            r'(apache|nginx|iis)\s+[\d\.]+',
            r'(linux\s+kernel|ubuntu|redhat|centos)\s+[\d\.]+'
        ]
    
    def validate_cve_relevance(
        self,
        cve_data: Dict[str, Any],
        vulnerability_context: Dict[str, Any]
    ) -> ValidationResult:
        """
        Validate if a CVE is relevant to the vulnerability context
        
        Args:
            cve_data: CVE information (id, description, affected_products, etc.)
            vulnerability_context: Original vulnerability data (title, OS, asset info, etc.)
        
        Returns:
            ValidationResult with relevance assessment
        """
        relevance_reasons = []
        warning_flags = []
        confidence_score = 0.0
        
        vuln_title = str(vulnerability_context.get("Title", "")).lower()
        vuln_os = str(vulnerability_context.get("Operating System", "")).lower()
        cve_description = str(cve_data.get("description", "")).lower()
        cve_id = cve_data.get("cve_id", "")
        affected_products = cve_data.get("affected_products", [])
        
        # Check 1: Is this a generic configuration issue?
        is_generic = self._is_generic_vulnerability(vuln_title)
        
        if is_generic:
            # For generic issues, CVE should NOT be product-specific
            is_product_specific = self._is_product_specific_cve(cve_description, affected_products)
            
            if is_product_specific:
                warning_flags.append(
                    f"Generic vulnerability '{vuln_title}' mapped to product-specific CVE"
                )
                confidence_score -= 0.5
        
        # Check 2: OS/Platform matching
        os_match = self._check_os_platform_match(vuln_os, cve_description, affected_products)
        if os_match["matches"]:
            relevance_reasons.append(os_match["reason"])
            confidence_score += 0.3
        elif os_match["conflicts"]:
            warning_flags.append(os_match["reason"])
            confidence_score -= 0.4
        
        # Check 3: Software/Product matching
        software_match = self._check_software_match(
            vuln_title, 
            vuln_os,
            cve_description, 
            affected_products
        )
        if software_match["matches"]:
            relevance_reasons.append(software_match["reason"])
            confidence_score += 0.4
        
        # Check 4: Vulnerability type matching
        vuln_type_match = self._check_vulnerability_type_match(vuln_title, cve_description)
        if vuln_type_match["matches"]:
            relevance_reasons.append(vuln_type_match["reason"])
            confidence_score += 0.2
        
        # Check 5: QID-specific validation
        qid_validation = self._validate_by_qid(vulnerability_context, cve_data)
        if qid_validation["warnings"]:
            warning_flags.extend(qid_validation["warnings"])
            confidence_score -= 0.3
        if qid_validation["matches"]:
            relevance_reasons.extend(qid_validation["matches"])
            confidence_score += 0.2
        
        # Normalize confidence score
        confidence_score = max(0.0, min(1.0, confidence_score))
        
        # Determine if relevant (threshold: 0.4)
        is_relevant = confidence_score >= 0.4 and not any(
            "severe mismatch" in flag.lower() for flag in warning_flags
        )
        
        return ValidationResult(
            is_relevant=is_relevant,
            confidence_score=confidence_score,
            relevance_reasons=relevance_reasons,
            warning_flags=warning_flags
        )
    
    def _is_generic_vulnerability(self, vuln_title: str) -> bool:
        """Check if vulnerability is a generic configuration issue"""
        return any(indicator in vuln_title for indicator in self.generic_indicators)
    
    def _is_product_specific_cve(
        self, 
        cve_description: str, 
        affected_products: List[str]
    ) -> bool:
        """Check if CVE is specific to a particular product/vendor"""
        # Check description for specific product mentions
        for pattern in self.product_specific_patterns:
            if re.search(pattern, cve_description, re.IGNORECASE):
                return True
        
        # Check affected products list
        if affected_products and len(affected_products) < 5:
            # If it only affects a few specific products, it's product-specific
            return True
        
        return False
    
    def _check_os_platform_match(
        self,
        vuln_os: str,
        cve_description: str,
        affected_products: List[str]
    ) -> Dict[str, Any]:
        """Check if OS/platform matches between vulnerability and CVE"""
        if not vuln_os or vuln_os == "unknown":
            return {"matches": False, "conflicts": False, "reason": ""}
        
        # Extract OS type from vulnerability
        os_indicators = {
            "windows": ["windows", "microsoft"],
            "linux": ["linux", "ubuntu", "debian", "redhat", "centos", "fedora"],
            "unix": ["unix", "solaris", "aix"],
            "network": ["cisco", "juniper", "fortinet", "palo alto"]
        }
        
        vuln_os_type = None
        for os_type, keywords in os_indicators.items():
            if any(keyword in vuln_os for keyword in keywords):
                vuln_os_type = os_type
                break
        
        if not vuln_os_type:
            return {"matches": False, "conflicts": False, "reason": ""}
        
        # Check for conflicting OS in CVE
        cve_content = f"{cve_description} {' '.join(affected_products)}".lower()
        
        for os_type, keywords in os_indicators.items():
            if os_type != vuln_os_type:
                if any(keyword in cve_content for keyword in keywords):
                    return {
                        "matches": False,
                        "conflicts": True,
                        "reason": f"OS mismatch: Vulnerability is {vuln_os_type} but CVE mentions {os_type}"
                    }
        
        # Check for matching OS
        if any(keyword in cve_content for keyword in os_indicators[vuln_os_type]):
            return {
                "matches": True,
                "conflicts": False,
                "reason": f"OS match: Both involve {vuln_os_type} systems"
            }
        
        return {"matches": False, "conflicts": False, "reason": ""}
    
    def _check_software_match(
        self,
        vuln_title: str,
        vuln_os: str,
        cve_description: str,
        affected_products: List[str]
    ) -> Dict[str, Any]:
        """Check if specific software/service matches"""
        # Extract software mentions from vulnerability title
        software_patterns = {
            "ssh": r'\bssh\b',
            "ssl/tls": r'\b(ssl|tls)\b',
            "apache": r'\bapache\b',
            "nginx": r'\bnginx\b',
            "openssh": r'\bopenssh\b',
            "openssl": r'\bopenssl\b',
        }
        
        vuln_software = set()
        for software, pattern in software_patterns.items():
            if re.search(pattern, vuln_title, re.IGNORECASE):
                vuln_software.add(software)
        
        if not vuln_software:
            return {"matches": False, "reason": ""}
        
        # Check if CVE mentions the same software
        cve_content = f"{cve_description} {' '.join(affected_products)}".lower()
        
        matching_software = []
        for software in vuln_software:
            pattern = software_patterns.get(software)
            if pattern and re.search(pattern, cve_content, re.IGNORECASE):
                matching_software.append(software)
        
        if matching_software:
            return {
                "matches": True,
                "reason": f"Software match: Both involve {', '.join(matching_software)}"
            }
        
        return {"matches": False, "reason": ""}
    
    def _check_vulnerability_type_match(
        self,
        vuln_title: str,
        cve_description: str
    ) -> Dict[str, Any]:
        """Check if vulnerability types match (e.g., both about certificates)"""
        vuln_type_keywords = {
            "certificate": ["certificate", "cert", "ca", "trust"],
            "authentication": ["authentication", "auth", "login", "credential"],
            "encryption": ["encryption", "cipher", "crypto", "tls", "ssl"],
            "privilege_escalation": ["privilege", "escalation", "root", "admin"],
            "injection": ["injection", "sql", "command", "code execution"],
        }
        
        vuln_types = set()
        for vuln_type, keywords in vuln_type_keywords.items():
            if any(keyword in vuln_title for keyword in keywords):
                vuln_types.add(vuln_type)
        
        if not vuln_types:
            return {"matches": False, "reason": ""}
        
        matching_types = []
        for vuln_type in vuln_types:
            keywords = vuln_type_keywords[vuln_type]
            if any(keyword in cve_description for keyword in keywords):
                matching_types.append(vuln_type.replace("_", " "))
        
        if matching_types:
            return {
                "matches": True,
                "reason": f"Vulnerability type match: {', '.join(matching_types)}"
            }
        
        return {"matches": False, "reason": ""}
    
    def _validate_by_qid(
        self,
        vulnerability_context: Dict[str, Any],
        cve_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate CVE relevance based on specific QID patterns
        This handles known QID-CVE mapping issues
        """
        warnings = []
        matches = []
        
        qid = str(vulnerability_context.get("QID", ""))
        title = str(vulnerability_context.get("Title", "")).lower()
        cve_id = cve_data.get("cve_id", "")
        cve_desc = cve_data.get("description", "").lower()
        
        # QID 38909 / 38739: SSH deprecation - should not map to Brocade SANnav
        if qid in ["38909", "38739"] and "sha1" in title and "ssh" in title:
            if "brocade" in cve_desc or "sannav" in cve_desc:
                warnings.append(
                    f"QID {qid} (generic SSH config) incorrectly mapped to product-specific CVE {cve_id}"
                )
            elif "ssh" in cve_desc and "sha1" in cve_desc:
                matches.append(f"QID {qid}: CVE correctly relates to SSH SHA1 issues")
        
        # QID 38173: SSL Certificate validation - should not map to Windows/specific products
        if qid == "38173" and "certificate" in title and "signature verification" in title:
            if any(prod in cve_desc for prod in ["windows", "schannel", "graylog", "scala"]):
                warnings.append(
                    f"QID {qid} (generic SSL cert issue) mapped to product-specific CVE {cve_id}"
                )
        
        # QID 38169: Self-signed certificate - should not map to LDAP/specific software
        if qid == "38169" and "self-signed" in title:
            if any(prod in cve_desc for prod in ["ldap", "graylog", "terminal server"]):
                warnings.append(
                    f"QID {qid} (generic self-signed cert) mapped to specific software CVE {cve_id}"
                )
        
        # QID 86728: Plain-text form authentication - should not map to specific apps
        if qid == "86728" and "plain-text" in title:
            if any(app in cve_desc for app in ["signal k", "kafka", "lobe chat"]):
                warnings.append(
                    f"QID {qid} (generic HTTP auth) mapped to specific application CVE {cve_id}"
                )
        
        # QID 6022303: Ubuntu Security Notification - should only map to Ubuntu/Linux kernel CVEs
        if qid == "6022303" and "ubuntu" in title:
            if "linux" in cve_desc or "kernel" in cve_desc or "ubuntu" in cve_desc:
                matches.append(f"QID {qid}: CVE correctly relates to Ubuntu/Linux")
            else:
                warnings.append(
                    f"QID {qid} (Ubuntu security) mapped to non-Linux CVE {cve_id}"
                )
        
        return {"warnings": warnings, "matches": matches}


def get_relevant_cves_from_nist(
    keywords: str,
    os_context: Optional[str] = None,
    max_results: int = 5
) -> List[Dict[str, Any]]:
    """
    Search NIST NVD for relevant CVEs with better context awareness
    
    Args:
        keywords: Search keywords
        os_context: Operating system context for filtering
        max_results: Maximum number of results
    
    Returns:
        List of relevant CVE data
    """
    try:
        # NIST NVD API 2.0
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        params = {
            "keywordSearch": keywords,
            "resultsPerPage": max_results
        }
        
        headers = {
            "User-Agent": "CVE-Validator/1.0 (Security Research)"
        }
        
        response = requests.get(base_url, params=params, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"NIST API returned status: {response.status_code}")
            return []
        
        data = response.json()
        results = []
        
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "")
                
                # Extract description
                descriptions = cve_item.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Extract CVSS metrics
                metrics = cve_item.get("metrics", {})
                cvss_data = {}
                
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                
                # Extract CPE (affected products)
                configurations = cve_item.get("configurations", [])
                affected_products = []
                for config in configurations:
                    nodes = config.get("nodes", [])
                    for node in nodes:
                        cpe_matches = node.get("cpeMatch", [])
                        for cpe in cpe_matches:
                            if cpe.get("vulnerable"):
                                affected_products.append(cpe.get("criteria", ""))
                
                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "score": cvss_data.get("baseScore", 0.0),
                    "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    "vector_string": cvss_data.get("vectorString", ""),
                    "affected_products": affected_products,
                    "published_date": cve_item.get("published", ""),
                    "modified_date": cve_item.get("lastModified", "")
                })
        
        return results
        
    except Exception as e:
        print(f"Error querying NIST: {e}")
        return []
