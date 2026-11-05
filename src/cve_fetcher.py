import requests

def get_cve_details(cve_id):
    """
    Fetches CVE details from the CIRCL CVE Search API (Free, no key required).
    Falls back to the NVD (NIST) API if CIRCL fails or returns incomplete data.
    
    Args:
        cve_id (str): The CVE ID (e.g., CVE-2021-44228)
        
    Returns:
        dict: Dictionary containing 'id', 'description', 'cvss', 'published',
              'references', or None if all sources failed.
    """
    cve_id = cve_id.strip().upper()
    
    # Try CIRCL API first
    result = _fetch_from_circl(cve_id)
    if result:
        # If CIRCL didn't provide a CVSS score, try to enrich from NVD
        if result.get("cvss") == "N/A":
            nvd_result = _fetch_from_nvd(cve_id)
            if nvd_result and nvd_result.get("cvss") != "N/A":
                result["cvss"] = nvd_result["cvss"]
        return result
    
    # Fallback to NVD API entirely
    result = _fetch_from_nvd(cve_id)
    if result:
        return result
    
    return None


def _fetch_from_circl(cve_id):
    """Fetches CVE data from the CIRCL CVE Search API.
    Handles both the legacy format (with 'summary' key) and the new
    CVE 5.0 format (with 'containers'/'cveMetadata' keys).
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data:
                return None
            
            # --- Legacy CIRCL format (has 'summary' key) ---
            if "summary" in data:
                return {
                    "id": cve_id,
                    "description": data.get("summary", "No description available."),
                    "cvss": data.get("cvss", "N/A"),
                    "published": data.get("Published", "Unknown"),
                    "references": data.get("references", [])
                }
            
            # --- New CVE 5.0 / CIRCL format (has 'containers' key) ---
            if "containers" in data:
                cna = data.get("containers", {}).get("cna", {})
                metadata = data.get("cveMetadata", {})
                
                # Extract description
                descriptions = cna.get("descriptions", [])
                description = "No description available."
                for desc in descriptions:
                    if desc.get("lang", "").startswith("en"):
                        description = desc.get("value", description)
                        break
                if description == "No description available." and descriptions:
                    description = descriptions[0].get("value", description)
                
                # Extract CVSS score from metrics
                cvss = _extract_cvss_from_cna(cna)
                
                # Extract published date
                published = metadata.get("datePublished", "Unknown")
                if published and published != "Unknown":
                    published = published[:10]  # Keep only YYYY-MM-DD
                
                # Extract references
                refs = cna.get("references", [])
                references = [ref.get("url", "") for ref in refs if ref.get("url")]
                
                return {
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "published": published,
                    "references": references
                }
    except Exception as e:
        print(f"Error fetching CVE from CIRCL: {e}")
    
    return None


def _extract_cvss_from_cna(cna):
    """Extracts the CVSS score from the CNA metrics block."""
    metrics = cna.get("metrics", [])
    for metric in metrics:
        # Try CVSS v3.1
        if "cvssV3_1" in metric:
            return metric["cvssV3_1"].get("baseScore", "N/A")
        # Try CVSS v3.0
        if "cvssV3_0" in metric:
            return metric["cvssV3_0"].get("baseScore", "N/A")
        # Try CVSS v2.0
        if "cvssV2_0" in metric:
            return metric["cvssV2_0"].get("baseScore", "N/A")
    return "N/A"


def _fetch_from_nvd(cve_id):
    """Fetches CVE data from the NVD (NIST) REST API as a fallback."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            
            cve_data = vulnerabilities[0].get("cve", {})
            
            # Extract English description
            descriptions = cve_data.get("descriptions", [])
            description = "No description available."
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break
            
            # Extract CVSS score (prefer v3.1 > v3.0 > v2)
            cvss = "N/A"
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A")
            
            # Extract published date
            published = cve_data.get("published", "Unknown")
            if published and published != "Unknown":
                published = published[:10]  # Keep only YYYY-MM-DD
            
            # Extract references
            refs = cve_data.get("references", [])
            references = [ref.get("url", "") for ref in refs if ref.get("url")]
            
            return {
                "id": cve_id,
                "description": description,
                "cvss": cvss,
                "published": published,
                "references": references
            }
    except Exception as e:
        print(f"Error fetching CVE from NVD: {e}")
    
    return None


if __name__ == "__main__":
    # Test
    print(get_cve_details("CVE-2021-44228"))
