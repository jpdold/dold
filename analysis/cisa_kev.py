"""CISA Known Exploited Vulnerabilities (KEV) feed client and matcher."""

import unicodedata
import requests
import pandas as pd

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev(session_state=None) -> list:
    """
    Fetch CISA KEV JSON feed, caching in st.session_state if provided.

    Parameters
    ----------
    session_state : streamlit session_state object or dict, optional

    Returns
    -------
    list of KEV vulnerability dicts
    """
    cache_key = "_kev_data"

    if session_state is not None and cache_key in session_state:
        return session_state[cache_key]

    try:
        resp = requests.get(KEV_FEED_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
    except Exception as exc:
        raise ConnectionError(f"Failed to fetch CISA KEV feed: {exc}") from exc

    if session_state is not None:
        session_state[cache_key] = vulns

    return vulns


def _normalize(text: str) -> str:
    """Normalize unicode (collapse non-breaking spaces etc.) and lowercase."""
    return unicodedata.normalize("NFKC", text).lower().strip()


def match_kev(kev_vulns: list, cve_ids: list = None, inventory_df: pd.DataFrame = None) -> pd.DataFrame:
    """
    Match KEV entries against CVE IDs and/or inventory vendor/product names.

    Inventory matching requires BOTH vendor AND product to match a single
    inventory row to avoid broad vendor-only sweeps (e.g. "Microsoft" alone
    would match hundreds of unrelated KEV entries).

    Parameters
    ----------
    kev_vulns : list
        Raw KEV vulnerability list from fetch_kev()
    cve_ids : list of str, optional
        CVE IDs found in NVD results to match against
    inventory_df : pd.DataFrame, optional
        Inventory DataFrame with Vendor and Product columns

    Returns
    -------
    pd.DataFrame with columns:
        cve_id, vendorProject, product, vulnerabilityName, dateAdded,
        shortDescription, requiredAction, knownRansomwareCampaignUse
    """
    if not kev_vulns:
        return _empty_kev_df()

    matched = []
    matched_cve_ids = set()

    cve_id_set = set(c.upper() for c in (cve_ids or []))

    # Build list of (vendor_tokens, product_tokens) pairs from inventory.
    # We require meaningful tokens (5+ chars) so that short words like
    # "pro", "dc", "se" don't generate false matches.
    inv_pairs = []
    if inventory_df is not None and not inventory_df.empty:
        seen = set()
        for _, row in inventory_df.iterrows():
            vendor = _normalize(str(row.get("Vendor", "")))
            product = _normalize(str(row.get("Product", "")))
            key = (vendor, product)
            if key in seen or (not vendor and not product):
                continue
            seen.add(key)
            v_tokens = {t for t in vendor.split() if len(t) >= 4}
            p_tokens = {t for t in product.split() if len(t) >= 4}
            inv_pairs.append((vendor, product, v_tokens, p_tokens))

    for vuln in kev_vulns:
        cve_id = vuln.get("cveID", "").upper()
        vendor_project = vuln.get("vendorProject", "")
        product_name = vuln.get("product", "")

        matched_by_cve = cve_id in cve_id_set
        matched_by_inv = False

        if inv_pairs:
            kev_vendor = _normalize(vendor_project)
            kev_product = _normalize(product_name)

            for inv_vendor, inv_product, v_tokens, p_tokens in inv_pairs:
                # Vendor must match: inventory vendor appears in KEV vendor (or vice versa)
                vendor_hit = (
                    inv_vendor and (inv_vendor in kev_vendor or kev_vendor in inv_vendor)
                ) or any(t in kev_vendor for t in v_tokens)

                if not vendor_hit:
                    continue

                # Product must also match — at least one meaningful product token
                product_hit = (
                    inv_product and (inv_product in kev_product or kev_product in inv_product)
                ) or any(t in kev_product for t in p_tokens if len(t) >= 5)

                if vendor_hit and product_hit:
                    matched_by_inv = True
                    break

        if (matched_by_cve or matched_by_inv) and cve_id not in matched_cve_ids:
            matched_cve_ids.add(cve_id)
            # Sanitize strings from CISA feed (may contain unusual unicode)
            matched.append({
                "cve_id": cve_id,
                "vendorProject": unicodedata.normalize("NFKC", vendor_project),
                "product": unicodedata.normalize("NFKC", product_name),
                "vulnerabilityName": unicodedata.normalize("NFKC", vuln.get("vulnerabilityName", "")),
                "dateAdded": vuln.get("dateAdded", ""),
                "shortDescription": unicodedata.normalize("NFKC", vuln.get("shortDescription", "")),
                "requiredAction": unicodedata.normalize("NFKC", vuln.get("requiredAction", "")),
                "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "matched_by": "CVE ID" if matched_by_cve else "Inventory Match",
            })

    if not matched:
        return _empty_kev_df()

    df = pd.DataFrame(matched)
    return df


def _empty_kev_df() -> pd.DataFrame:
    return pd.DataFrame(columns=[
        "cve_id", "vendorProject", "product", "vulnerabilityName",
        "dateAdded", "shortDescription", "requiredAction",
        "knownRansomwareCampaignUse", "matched_by",
    ])
