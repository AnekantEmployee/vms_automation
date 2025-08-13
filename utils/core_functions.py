import requests
from typing import List, Optional, Dict
from dataclasses import dataclass
import re
from bs4 import BeautifulSoup
import time
import urllib.parse
import concurrent.futures
from threading import Lock


# Cache for NIST API results to avoid duplicate calls
_nist_cache = {}
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


@dataclass
class CVEDetailResult:
    cve_id: str
    description: str
    references: List[str]
    cwe_info: str
    vendor_advisories: List[str]
    affected_products: List[str]
    source: str = "CVE.org"


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
                # v3 doesn't have separate exploitability/impact scores in the same way
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


def search_mitre_cve(query: str, max_results: int = 10) -> List[CVEResult]:
    """MITRE CVE database search with original functionality"""
    try:
        encoded_query = urllib.parse.quote_plus(query)
        mitre_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={encoded_query}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        response = requests.get(mitre_url, headers=headers, timeout=30)
        response.raise_for_status()

        print(f"MITRE Response Status: {response.status_code}")

        soup = BeautifulSoup(response.content, "html.parser")
        results = []

        # Extract key terms from the query for better filtering
        query_terms = query.lower().split()
        chrome_terms = ["chrome", "google", "browser"]
        is_chrome_query = any(term in query_terms for term in chrome_terms)

        # Method 1: Look for results in the main content area (more specific)
        content_div = soup.find("div", {"id": "GeneratedTable"}) or soup.find(
            "div", class_="searchresults"
        )

        if content_div:
            # Look for table rows with CVE information
            rows = content_div.find_all("tr")
            for row in rows[1:]:  # Skip header row
                if len(results) >= max_results:
                    break

                cells = row.find_all("td")
                if len(cells) >= 2:
                    # First cell contains CVE ID
                    first_cell = cells[0].get_text().strip()
                    cve_match = re.search(
                        r"CVE-\d{4}-\d{4,}", first_cell, re.IGNORECASE
                    )

                    if cve_match:
                        cve_id = cve_match.group().upper()

                        # Get description from second cell
                        description = cells[1].get_text().strip()

                        # Filter results - only include if description contains query terms
                        if is_chrome_query:
                            desc_lower = description.lower()
                            if not any(term in desc_lower for term in chrome_terms):
                                continue  # Skip if not Chrome-related

                        # Additional filtering based on query terms
                        query_lower = query.lower()
                        desc_lower = description.lower()

                        # Check if description contains relevant terms from the query
                        relevant_terms = []
                        if "chrome" in query_lower:
                            relevant_terms.extend(
                                ["chrome", "google chrome", "chromium"]
                            )
                        if any(
                            version_term in query_lower
                            for version_term in ["138", "137", "136"]
                        ):
                            relevant_terms.extend(["138", "137", "136"])

                        if relevant_terms and not any(
                            term in desc_lower for term in relevant_terms
                        ):
                            continue  # Skip if not relevant

                        # Limit description length
                        if len(description) > 300:
                            description = description[:300] + "..."

                        results.append(
                            CVEResult(
                                cve_id=cve_id,
                                description=description,
                                severity="Unknown",
                                published_date="Unknown",
                                modified_date="Unknown",
                                score=0.0,
                                source="MITRE",
                            )
                        )

        # Method 2: If no structured results, look for CVE links with context
        if not results:
            # Find all links that contain CVE IDs
            cve_links = soup.find_all("a", href=re.compile(r"CVE-\d{4}-\d+", re.I))

            for link in cve_links:
                if len(results) >= max_results:
                    break

                href = link.get("href", "")
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", href, re.IGNORECASE)

                if cve_match:
                    cve_id = cve_match.group().upper()

                    # Get description from surrounding context
                    description = ""

                    # Try to get description from the same table row
                    parent_row = link.find_parent("tr")
                    if parent_row:
                        cells = parent_row.find_all("td")
                        if len(cells) > 1:
                            # Find the cell with the description (usually not the first one)
                            for cell in cells[1:]:
                                cell_text = cell.get_text().strip()
                                if len(cell_text) > 50:  # Reasonable description length
                                    description = cell_text
                                    break

                    # If no description from table, try parent elements
                    if not description:
                        parent = link.parent
                        for _ in range(3):  # Check up to 3 parent levels
                            if parent:
                                parent_text = parent.get_text().strip()
                                if len(parent_text) > 50 and cve_id in parent_text:
                                    # Extract relevant portion
                                    description = parent_text[:300]
                                    break
                                parent = parent.parent

                    # Filter based on relevance
                    if description:
                        desc_lower = description.lower()

                        # For Chrome queries, ensure it's Chrome-related
                        if is_chrome_query and not any(
                            term in desc_lower for term in chrome_terms
                        ):
                            continue

                        # Check for query term relevance
                        query_terms_lower = [
                            term.lower() for term in query.split() if len(term) > 2
                        ]
                        if query_terms_lower and not any(
                            term in desc_lower for term in query_terms_lower
                        ):
                            continue

                    if not description:
                        description = f"CVE found in MITRE search for: {query}"

                    if len(description) > 300:
                        description = description[:300] + "..."

                    results.append(
                        CVEResult(
                            cve_id=cve_id,
                            description=description,
                            severity="Unknown",
                            published_date="Unknown",
                            modified_date="Unknown",
                            score=0.0,
                            source="MITRE",
                        )
                    )

        # Method 3: Last resort - parse page text with strict filtering
        if not results and len(query.split()) >= 2:  # Only for multi-word queries
            full_text = soup.get_text()

            # Split into paragraphs/sections
            sections = re.split(r"\n\s*\n", full_text)

            for section in sections:
                if len(results) >= max_results:
                    break

                # Look for CVE patterns in this section
                cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", section, re.IGNORECASE)

                if cve_matches:
                    section_lower = section.lower()

                    # Check if this section is relevant to the query
                    query_words = [
                        word.lower() for word in query.split() if len(word) > 2
                    ]
                    relevance_score = sum(
                        1 for word in query_words if word in section_lower
                    )

                    # Only include if section has good relevance
                    if relevance_score >= min(2, len(query_words)):
                        for cve_id in cve_matches:
                            if len(results) >= max_results:
                                break

                            # Get context around the CVE
                            cve_pos = section_lower.find(cve_id.lower())
                            if cve_pos > 0:
                                start = max(0, cve_pos - 100)
                                end = min(len(section), cve_pos + 200)
                                context = section[start:end].strip()

                                if len(context) > 50:
                                    results.append(
                                        CVEResult(
                                            cve_id=cve_id.upper(),
                                            description=(
                                                context[:300] + "..."
                                                if len(context) > 300
                                                else context
                                            ),
                                            severity="Unknown",
                                            published_date="Unknown",
                                            modified_date="Unknown",
                                            score=0.0,
                                            source="MITRE",
                                        )
                                    )

        # Remove duplicates based on CVE ID
        unique_results = {}
        for result in results:
            if result.cve_id not in unique_results:
                unique_results[result.cve_id] = result

        final_results = list(unique_results.values())[:max_results]
        print(
            f"MITRE found {len(final_results)} unique relevant CVEs (limited to {max_results})"
        )

        return final_results

    except Exception as e:
        print(f"Error searching MITRE CVE: {e}")
        import traceback

        traceback.print_exc()
        return []


def batch_enhance_cves(
    cve_results: List[CVEResult], max_concurrent: int = 3
) -> List[CVEResult]:
    """Batch enhance CVE results with concurrent NIST lookups"""

    # Identify which CVEs need enhancement
    needs_enhancement = []
    already_complete = []

    for result in cve_results:
        if result.source == "MITRE" and (
            result.severity == "Unknown" or result.score == 0.0
        ):
            needs_enhancement.append(result)
        else:
            already_complete.append(result)

    if not needs_enhancement:
        print("No CVEs need enhancement")
        return cve_results

    print(f"Enhancing {len(needs_enhancement)} CVEs with batch NIST lookup...")

    enhanced_results = []

    # Process in batches to avoid overwhelming the API
    def enhance_single_cve(cve_result):
        nist_details = get_nist_cve_details(cve_result.cve_id)
        if nist_details:
            return CVEResult(
                cve_id=cve_result.cve_id,
                description=(
                    nist_details.description
                    if len(nist_details.description) > len(cve_result.description)
                    else cve_result.description
                ),
                severity=(
                    nist_details.severity
                    if nist_details.severity != "Unknown"
                    else cve_result.severity
                ),
                published_date=(
                    nist_details.published_date
                    if nist_details.published_date != "Unknown"
                    else cve_result.published_date
                ),
                modified_date=(
                    nist_details.modified_date
                    if nist_details.modified_date != "Unknown"
                    else cve_result.modified_date
                ),
                score=(
                    nist_details.score if nist_details.score > 0 else cve_result.score
                ),
                source="MITRE+NIST",
                # Enhanced fields from NIST
                vuln_status=nist_details.vuln_status,
                cwe_info=nist_details.cwe_info,
                affected_products=nist_details.affected_products,
                references=nist_details.references,
                exploitability_score=nist_details.exploitability_score,
                impact_score=nist_details.impact_score,
                vector_string=nist_details.vector_string,
                cvss_version=nist_details.cvss_version,
            )
        return cve_result

    # Use ThreadPoolExecutor for concurrent API calls
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        # Add small delays between requests
        enhanced = list(executor.map(enhance_single_cve, needs_enhancement))
        enhanced_results.extend(enhanced)

        # Small delay to be respectful to the API
        time.sleep(0.5)

    # Combine results
    all_results = already_complete + enhanced_results
    print(
        f"Enhanced {len([r for r in enhanced_results if r.source == 'MITRE+NIST'])} CVEs successfully"
    )

    return all_results


def combined_cve_search(query: str, max_results: int = 10) -> List[CVEResult]:
    """Modified search that uses only MITRE for searching and NIST for details."""
    print(f"Starting MITRE-only search for: '{query}' (max: {max_results})")

    # Check if the query is a specific CVE ID
    cve_id_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    match = cve_id_pattern.match(query.strip())

    if match:
        cve_id = match.group(0).upper()
        print(f"Direct lookup detected for CVE ID: {cve_id}")
        result = get_nist_cve_details(cve_id)
        if result:
            # Add a specific source to indicate a direct lookup
            result.source = "NIST (Direct)"
            return [result]
        else:
            print(f"No details found for the specific CVE ID: {cve_id}")
            return []

    # If not a specific CVE ID, proceed with MITRE keyword search only
    print("Searching MITRE CVE database...")
    mitre_results = search_mitre_cve(query, max_results)

    if not mitre_results:
        print("No CVEs found in MITRE search")
        return []

    # Enhance all MITRE results with NIST details
    print(f"Found {len(mitre_results)} CVEs from MITRE, enhancing with NIST details...")
    enhanced_results = batch_enhance_cves(mitre_results, max_concurrent=2)

    print(f"Final result: {len(enhanced_results)} CVEs with enhanced data")
    return enhanced_results
