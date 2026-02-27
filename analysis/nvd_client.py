"""NVD CVE API 2.0 client with rate limiting, exponential backoff, and in-memory cache."""

import time
import requests
from typing import Optional

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits: 5 requests per 30s without key, 50/30s with key
RATE_LIMIT_NO_KEY = 5
RATE_LIMIT_WITH_KEY = 50
RATE_WINDOW = 30  # seconds

_cache: dict = {}
_request_timestamps: list = []


def _wait_for_rate_limit(api_key: Optional[str]):
    """Enforce NVD rate limits using a sliding window."""
    global _request_timestamps
    limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
    now = time.time()
    # Remove timestamps outside the window
    _request_timestamps = [t for t in _request_timestamps if now - t < RATE_WINDOW]
    if len(_request_timestamps) >= limit:
        wait_time = RATE_WINDOW - (now - _request_timestamps[0]) + 0.5
        if wait_time > 0:
            time.sleep(wait_time)
        _request_timestamps = [t for t in _request_timestamps if time.time() - t < RATE_WINDOW]
    _request_timestamps.append(time.time())


def _parse_cvss_impacts(metrics: dict) -> tuple:
    """Extract numeric CIA impact values from CVSS v3 metrics."""
    impact_map = {"NONE": 0.0, "LOW": 0.5, "HIGH": 1.0, "PARTIAL": 0.5, "COMPLETE": 1.0}

    c_impact = i_impact = a_impact = 0.0
    cvss_score = None
    severity = "UNKNOWN"

    # Try CVSSv3.1 first, then v3.0
    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
        if metric_key in metrics:
            entry = metrics[metric_key][0].get("cvssData", {})
            cvss_score = entry.get("baseScore")
            severity = entry.get("baseSeverity", "UNKNOWN")
            c_impact = impact_map.get(entry.get("confidentialityImpact", "NONE"), 0.0)
            i_impact = impact_map.get(entry.get("integrityImpact", "NONE"), 0.0)
            a_impact = impact_map.get(entry.get("availabilityImpact", "NONE"), 0.0)
            return cvss_score, severity, c_impact, i_impact, a_impact

    # Fall back to CVSSv2
    if "cvssMetricV2" in metrics:
        entry = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_score = entry.get("baseScore")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        c_impact = impact_map.get(entry.get("confidentialityImpact", "NONE"), 0.0)
        i_impact = impact_map.get(entry.get("integrityImpact", "NONE"), 0.0)
        a_impact = impact_map.get(entry.get("availabilityImpact", "NONE"), 0.0)

    return cvss_score, severity, c_impact, i_impact, a_impact


def query_nvd(vendor: str, product: str, api_key: Optional[str] = None,
              results_per_page: int = 15, max_retries: int = 4) -> list:
    """
    Query NVD CVE API 2.0 for CVEs matching vendor + product.

    Parameters
    ----------
    vendor : str
    product : str
    api_key : str, optional
    results_per_page : int
    max_retries : int

    Returns
    -------
    list of dicts with keys:
        cve_id, description, cvss_v3_score, cvss_v3_severity,
        C_impact, I_impact, A_impact, published_date, references
    """
    cache_key = (vendor.lower().strip(), product.lower().strip())
    if not vendor.strip() and not product.strip():
        return []
    if cache_key in _cache:
        return _cache[cache_key]

    keyword = f"{vendor} {product}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(max_retries):
        _wait_for_rate_limit(api_key)
        try:
            resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
            if resp.status_code == 403:
                raise ValueError("NVD API key invalid or rate limit exceeded (403).")
            if resp.status_code == 404:
                _cache[cache_key] = []
                return []
            if resp.status_code == 200:
                break
            # Retry on 5xx
            if resp.status_code >= 500:
                wait = 2 ** attempt
                time.sleep(wait)
                continue
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
        except requests.exceptions.ConnectionError:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    else:
        _cache[cache_key] = []
        return []

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    results = []

    for item in vulnerabilities:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Description (prefer English)
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        metrics = cve_data.get("metrics", {})
        cvss_score, severity, c_imp, i_imp, a_imp = _parse_cvss_impacts(metrics)

        published = cve_data.get("published", "")[:10]

        refs = [
            r.get("url", "")
            for r in cve_data.get("references", [])
            if r.get("url")
        ][:5]

        results.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss_v3_score": cvss_score,
            "cvss_v3_severity": severity,
            "C_impact": c_imp,
            "I_impact": i_imp,
            "A_impact": a_imp,
            "published_date": published,
            "references": refs,
            "vendor": vendor,
            "product": product,
        })

    _cache[cache_key] = results
    return results


def clear_cache():
    """Clear the NVD query cache."""
    global _cache, _request_timestamps
    _cache = {}
    _request_timestamps = []
