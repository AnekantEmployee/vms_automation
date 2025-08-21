import re
import requests
import time
import urllib.parse
import concurrent.futures
from threading import Lock
from bs4 import BeautifulSoup
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple


# Cache for NIST API results to avoid duplicate calls
_nist_cache = {}
_cve_org_cache = {}
_cache_lock = Lock()


@dataclass
class CVEResult:
    cve_id: str
    description: str
    severity: str
    published_date: str
    modified_date: str
    score: float
    source: str = "NIST"
    # Enhanced fields
    vuln_status: str = "Unknown"
    cwe_info: List[str] = None
    affected_products: List[str] = None
    references: List[str] = None
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    vector_string: str = ""
    cvss_version: str = ""

    def __post_init__(self):
        if self.cwe_info is None:
            self.cwe_info = []
        if self.affected_products is None:
            self.affected_products = []
        if self.references is None:
            self.references = []


def extract_cpe_products(configurations: List[Dict]) -> List[str]:
    """Extract affected products from CPE configurations"""
    products = []
    try:
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe_match in cpe_matches:
                    if cpe_match.get("vulnerable", False):
                        criteria = cpe_match.get("criteria", "")
                        if criteria.startswith("cpe:2.3:"):
                            # Parse CPE format: cpe:2.3:part:vendor:product:version:...
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3].replace("_", " ").title()
                                product = parts[4].replace("_", " ").title()
                                version = (
                                    parts[5] if parts[5] != "*" else "All Versions"
                                )
                                product_info = f"{vendor} {product}"
                                if version != "All Versions":
                                    product_info += f" {version}"
                                products.append(product_info)
    except Exception as e:
        print(f"Error extracting CPE products: {e}")

    return list(set(products))  # Remove duplicates


def extract_weakness_info(weaknesses: List[Dict]) -> List[str]:
    """Extract CWE information from weaknesses"""
    cwe_list = []
    try:
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    cwe_value = desc.get("value", "")
                    if cwe_value and cwe_value != "NVD-CWE-Other":
                        cwe_list.append(cwe_value)
    except Exception as e:
        print(f"Error extracting weakness info: {e}")

    return cwe_list


def get_nist_cve_details(cve_id: str) -> Optional[CVEResult]:
    """Get detailed information for a specific CVE from NIST with enhanced data extraction"""
    with _cache_lock:
        if cve_id in _nist_cache:
            print(f"Using cached NIST data for: {cve_id}")
            return _nist_cache[cve_id]

    try:
        print(f"Fetching enhanced NIST details for: {cve_id}")

        nist_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        response = requests.get(nist_url, params=params, headers=headers, timeout=15)
        response.raise_for_status()

        data = response.json()
        result = None

        if "vulnerabilities" in data and data["vulnerabilities"]:
            vuln = data["vulnerabilities"][0]
            cve_data = vuln.get("cve", {})

            # Basic information
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available",
            )

            # Enhanced vulnerability status
            vuln_status = cve_data.get("vulnStatus", "Unknown")

            # Enhanced metrics extraction
            metrics = cve_data.get("metrics", {})
            score = 0.0
            severity = "Unknown"
            exploitability_score = 0.0
            impact_score = 0.0
            vector_string = ""
            cvss_version = ""

            # Try CVSS v3.1 first, then v3.0, then v2
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "Unknown")
                vector_string = cvss_data.get("vectorString", "")
                cvss_version = "3.1"
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "Unknown")
                vector_string = cvss_data.get("vectorString", "")
                cvss_version = "3.0"
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_v2 = metrics["cvssMetricV2"][0]
                cvss_data = cvss_v2["cvssData"]
                score = cvss_data.get("baseScore", 0.0)
                vector_string = cvss_data.get("vectorString", "")
                cvss_version = "2.0"
                exploitability_score = cvss_v2.get("exploitabilityScore", 0.0)
                impact_score = cvss_v2.get("impactScore", 0.0)
                # Map CVSS v2 score to severity
                if score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                elif score > 0.0:
                    severity = "LOW"

            # Extract CWE information
            weaknesses = cve_data.get("weaknesses", [])
            cwe_info = extract_weakness_info(weaknesses)

            # Extract affected products from configurations
            configurations = cve_data.get("configurations", [])
            affected_products = extract_cpe_products(configurations)

            # Extract references
            references = []
            ref_list = cve_data.get("references", [])
            for ref in ref_list:
                url = ref.get("url", "")
                if url:
                    references.append(url)

            result = CVEResult(
                cve_id=cve_id,
                description=description,
                severity=severity,
                published_date=cve_data.get("published", "Unknown"),
                modified_date=cve_data.get("lastModified", "Unknown"),
                score=score,
                source="NIST",
                vuln_status=vuln_status,
                cwe_info=cwe_info,
                affected_products=affected_products[:10],  # Limit to first 10
                references=references[:5],  # Limit to first 5
                exploitability_score=exploitability_score,
                impact_score=impact_score,
                vector_string=vector_string,
                cvss_version=cvss_version,
            )

        # Cache the result (even if None)
        with _cache_lock:
            _nist_cache[cve_id] = result

        return result

    except Exception as e:
        print(f"Error fetching enhanced NIST details for {cve_id}: {e}")
        with _cache_lock:
            _nist_cache[cve_id] = None
        return None


def search_cve_org(query: str, max_results: int = 10) -> List[str]:
    """Search CVE.org for CVE IDs using the new search interface"""
    try:
        print(f"Searching CVE.org for: '{query}'")
        
        # URL encode the query
        encoded_query = urllib.parse.quote_plus(query)
        cve_org_url = f"https://www.cve.org/CVERecord/SearchResults?query={encoded_query}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        response = requests.get(cve_org_url, headers=headers, timeout=30)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")
        cve_ids = []

        # Look for CVE IDs in the search results
        # Method 1: Find direct CVE links
        cve_links = soup.find_all("a", href=re.compile(r"/CVERecord\?id=CVE-\d{4}-\d+", re.I))
        for link in cve_links:
            href = link.get("href", "")
            cve_match = re.search(r"CVE-\d{4}-\d{4,}", href, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group().upper()
                if cve_id not in cve_ids:
                    cve_ids.append(cve_id)

        # Method 2: Find CVE patterns in text content
        if not cve_ids:
            # Look for CVE patterns in the page text
            page_text = soup.get_text()
            cve_patterns = re.findall(r"CVE-\d{4}-\d{4,}", page_text, re.IGNORECASE)
            for cve_pattern in cve_patterns:
                cve_id = cve_pattern.upper()
                if cve_id not in cve_ids:
                    cve_ids.append(cve_id)

        # Method 3: Look for specific CVE result sections
        if not cve_ids:
            # Try to find result containers
            result_sections = soup.find_all(['div', 'section', 'article'], 
                                          class_=re.compile(r"result|search|cve", re.I))
            for section in result_sections:
                section_text = section.get_text()
                cve_patterns = re.findall(r"CVE-\d{4}-\d{4,}", section_text, re.IGNORECASE)
                for cve_pattern in cve_patterns:
                    cve_id = cve_pattern.upper()
                    if cve_id not in cve_ids:
                        cve_ids.append(cve_id)

        # Remove duplicates and limit results
        unique_cve_ids = list(dict.fromkeys(cve_ids))[:max_results]
        print(f"CVE.org found {len(unique_cve_ids)} CVE IDs")
        
        return unique_cve_ids

    except Exception as e:
        print(f"Error searching CVE.org: {e}")
        return []


def get_cve_org_details(cve_id: str) -> Optional[Dict]:
    """Get detailed information for a specific CVE from CVE.org"""
    with _cache_lock:
        if cve_id in _cve_org_cache:
            print(f"Using cached CVE.org data for: {cve_id}")
            return _cve_org_cache[cve_id]

    try:
        print(f"Fetching CVE.org details for: {cve_id}")
        
        cve_url = f"https://www.cve.org/CVERecord?id={cve_id}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        response = requests.get(cve_url, headers=headers, timeout=15)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")
        
        details = {
            "cve_id": cve_id,
            "description": "",
            "title": "",
            "published_date": "",
            "cwe_info": [],
            "cvss_score": 0.0,
            "severity": "Unknown",
            "vector_string": "",
            "cvss_version": "",
            "affected_products": [],
            "references": []
        }

        # Extract title
        title_elem = soup.find("h1") or soup.find(text=re.compile("Title", re.I))
        if title_elem:
            if hasattr(title_elem, 'get_text'):
                details["title"] = title_elem.get_text().strip()
            else:
                # Find the next sibling or parent that contains the actual title
                parent = title_elem.parent if title_elem.parent else title_elem
                title_text = parent.get_text().strip()
                if "Title:" in title_text:
                    details["title"] = title_text.split("Title:")[-1].strip()

        # Extract description
        desc_section = soup.find(text=re.compile("Description", re.I))
        if desc_section:
            desc_parent = desc_section.parent
            # Look for the description content in nearby elements
            for sibling in desc_parent.next_siblings:
                if sibling and hasattr(sibling, 'get_text'):
                    text = sibling.get_text().strip()
                    if len(text) > 20 and not text.startswith(("CWE", "CVSS", "Product")):
                        details["description"] = text
                        break

        # Extract CWE information
        cwe_section = soup.find(text=re.compile("CWE", re.I))
        if cwe_section:
            cwe_parent = cwe_section.parent
            cwe_links = cwe_parent.find_all("a", href=re.compile("cwe", re.I))
            for link in cwe_links:
                cwe_text = link.get_text().strip()
                if cwe_text:
                    details["cwe_info"].append(cwe_text)

        # Extract CVSS information
        cvss_section = soup.find(text=re.compile("CVSS", re.I))
        if cvss_section:
            cvss_parent = cvss_section.parent
            # Look for score patterns
            score_pattern = re.search(r"(\d+\.?\d*)\s*(HIGH|MEDIUM|LOW|CRITICAL)", 
                                    cvss_parent.get_text(), re.IGNORECASE)
            if score_pattern:
                details["cvss_score"] = float(score_pattern.group(1))
                details["severity"] = score_pattern.group(2).upper()
            
            # Look for vector string
            vector_match = re.search(r"CVSS:\d+\.\d+/[A-Z:/_]+", cvss_parent.get_text())
            if vector_match:
                details["vector_string"] = vector_match.group()
                if "CVSS:4.0" in details["vector_string"]:
                    details["cvss_version"] = "4.0"
                elif "CVSS:3.1" in details["vector_string"]:
                    details["cvss_version"] = "3.1"
                elif "CVSS:3.0" in details["vector_string"]:
                    details["cvss_version"] = "3.0"

        # Extract affected products
        product_section = soup.find(text=re.compile("Product Status|Vendor", re.I))
        if product_section:
            product_parent = product_section.parent
            # Look for vendor/product information
            for elem in product_parent.find_all(text=True):
                text = elem.strip()
                if len(text) > 3 and not text.lower() in ["vendor", "product", "versions", "affected"]:
                    if any(char.isalnum() for char in text):
                        details["affected_products"].append(text)

        # Extract references
        refs_section = soup.find(text=re.compile("References", re.I))
        if refs_section:
            refs_parent = refs_section.parent
            ref_links = refs_parent.find_all("a", href=True)
            for link in ref_links:
                href = link.get("href", "")
                if href.startswith("http"):
                    details["references"].append(href)

        # Extract published date
        pub_section = soup.find(text=re.compile("Published", re.I))
        if pub_section:
            pub_parent = pub_section.parent
            date_pattern = re.search(r"\d{4}-\d{2}-\d{2}", pub_parent.get_text())
            if date_pattern:
                details["published_date"] = date_pattern.group()

        # Cache the result
        with _cache_lock:
            _cve_org_cache[cve_id] = details

        return details

    except Exception as e:
        print(f"Error fetching CVE.org details for {cve_id}: {e}")
        with _cache_lock:
            _cve_org_cache[cve_id] = None
        return None


def search_nist_cve_by_keyword(query: str, max_results: int = 10) -> List[str]:
    """Search NIST NVD for CVE IDs using keyword search"""
    try:
        print(f"Searching NIST NVD for: '{query}'")
        
        nist_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": query,
            "resultsPerPage": min(max_results, 20)  # NIST API limit
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        response = requests.get(nist_url, params=params, headers=headers, timeout=15)
        response.raise_for_status()

        data = response.json()
        cve_ids = []

        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                if cve_id and cve_id not in cve_ids:
                    cve_ids.append(cve_id)

        print(f"NIST NVD found {len(cve_ids)} CVE IDs")
        return cve_ids[:max_results]

    except Exception as e:
        print(f"Error searching NIST NVD: {e}")
        return []


def merge_cve_data(nist_result: CVEResult, cve_org_details: Dict) -> CVEResult:
    """Merge data from NIST and CVE.org sources"""
    if not cve_org_details:
        return nist_result

    # Use the more detailed description
    if cve_org_details.get("description") and len(cve_org_details["description"]) > len(nist_result.description):
        nist_result.description = cve_org_details["description"]

    # Merge CWE information
    if cve_org_details.get("cwe_info"):
        for cwe in cve_org_details["cwe_info"]:
            if cwe not in nist_result.cwe_info:
                nist_result.cwe_info.append(cwe)

    # Use CVE.org data if NIST is missing information
    if nist_result.score == 0.0 and cve_org_details.get("cvss_score", 0.0) > 0.0:
        nist_result.score = cve_org_details["cvss_score"]
        nist_result.severity = cve_org_details.get("severity", nist_result.severity)

    if not nist_result.vector_string and cve_org_details.get("vector_string"):
        nist_result.vector_string = cve_org_details["vector_string"]

    if not nist_result.cvss_version and cve_org_details.get("cvss_version"):
        nist_result.cvss_version = cve_org_details["cvss_version"]

    # Merge affected products
    if cve_org_details.get("affected_products"):
        for product in cve_org_details["affected_products"]:
            if product not in nist_result.affected_products:
                nist_result.affected_products.append(product)

    # Merge references
    if cve_org_details.get("references"):
        for ref in cve_org_details["references"]:
            if ref not in nist_result.references:
                nist_result.references.append(ref)

    # Update source to indicate merged data
    nist_result.source = "NIST+CVE.org"
    
    return nist_result


def parallel_cve_search(query: str, max_results: int = 10) -> Tuple[List[str], List[str]]:
    """Search both CVE.org and NIST NVD in parallel for CVE IDs"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        # Submit both searches concurrently
        cve_org_future = executor.submit(search_cve_org, query, max_results)
        nist_future = executor.submit(search_nist_cve_by_keyword, query, max_results)
        
        # Wait for results
        cve_org_results = cve_org_future.result()
        nist_results = nist_future.result()
        
        return cve_org_results, nist_results


def combined_cve_search(query: str, max_results: int = 10) -> List[CVEResult]:
    """Enhanced search that uses both CVE.org and NIST NVD in parallel"""
    print(f"Starting enhanced parallel search for: '{query}' (max: {max_results})")

    # Check if the query is a specific CVE ID
    cve_id_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    match = cve_id_pattern.match(query.strip())

    if match:
        cve_id = match.group(0).upper()
        print(f"Direct lookup detected for CVE ID: {cve_id}")
        
        # Get data from both sources in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            nist_future = executor.submit(get_nist_cve_details, cve_id)
            cve_org_future = executor.submit(get_cve_org_details, cve_id)
            
            nist_result = nist_future.result()
            cve_org_details = cve_org_future.result()
        
        if nist_result:
            merged_result = merge_cve_data(nist_result, cve_org_details)
            merged_result.source = "NIST+CVE.org (Direct)"
            return [merged_result]
        else:
            print(f"No details found for the specific CVE ID: {cve_id}")
            return []

    # Search both sources in parallel for CVE IDs
    print("Searching both CVE.org and NIST NVD in parallel...")
    cve_org_ids, nist_ids = parallel_cve_search(query, max_results)

    # Combine and deduplicate CVE IDs
    all_cve_ids = []
    seen_ids = set()
    
    # Prioritize CVE.org results (newer search interface)
    for cve_id in cve_org_ids:
        if cve_id not in seen_ids:
            all_cve_ids.append(cve_id)
            seen_ids.add(cve_id)
    
    # Add NIST results that aren't already included
    for cve_id in nist_ids:
        if cve_id not in seen_ids:
            all_cve_ids.append(cve_id)
            seen_ids.add(cve_id)

    # Limit to max_results
    all_cve_ids = all_cve_ids[:max_results]
    
    if not all_cve_ids:
        print("No CVEs found in either source")
        return []

    print(f"Found {len(all_cve_ids)} unique CVE IDs, fetching detailed information...")

    # Get detailed information for each CVE ID
    results = []
    
    def get_enhanced_cve_details(cve_id: str) -> Optional[CVEResult]:
        """Get detailed info from both NIST and CVE.org and merge them"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            nist_future = executor.submit(get_nist_cve_details, cve_id)
            cve_org_future = executor.submit(get_cve_org_details, cve_id)
            
            nist_result = nist_future.result()
            cve_org_details = cve_org_future.result()
        
        if nist_result:
            return merge_cve_data(nist_result, cve_org_details)
        elif cve_org_details:
            # Create CVEResult from CVE.org data if NIST doesn't have it
            return CVEResult(
                cve_id=cve_id,
                description=cve_org_details.get("description", f"CVE details from CVE.org for {cve_id}"),
                severity=cve_org_details.get("severity", "Unknown"),
                published_date=cve_org_details.get("published_date", "Unknown"),
                modified_date="Unknown",
                score=cve_org_details.get("cvss_score", 0.0),
                source="CVE.org",
                cwe_info=cve_org_details.get("cwe_info", []),
                affected_products=cve_org_details.get("affected_products", []),
                references=cve_org_details.get("references", []),
                vector_string=cve_org_details.get("vector_string", ""),
                cvss_version=cve_org_details.get("cvss_version", ""),
            )
        return None

    # Process CVE IDs with controlled concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_cve = {executor.submit(get_enhanced_cve_details, cve_id): cve_id 
                         for cve_id in all_cve_ids}
        
        for future in concurrent.futures.as_completed(future_to_cve):
            result = future.result()
            if result:
                results.append(result)
            
            # Small delay to be respectful to APIs
            time.sleep(0.2)

    print(f"Successfully retrieved detailed information for {len(results)} CVEs")
    
    # Sort results by score (highest first) and then by CVE ID
    results.sort(key=lambda x: (-x.score if x.score > 0 else 0, x.cve_id), reverse=True)
    
    return results


# Keep the original function for backward compatibility
def search_mitre_cve(query: str, max_results: int = 10) -> List[CVEResult]:
    """Wrapper function for backward compatibility - now uses the enhanced search"""
    return combined_cve_search(query, max_results)


def batch_enhance_cves(cve_results: List[CVEResult], max_concurrent: int = 3) -> List[CVEResult]:
    """Enhanced batch enhancement that now uses both NIST and CVE.org"""
    # The new combined search already enhances results, so we just return them
    print(f"Results are already enhanced with data from multiple sources")
    return cve_results