"""ATO recommendation engine and mitigation text generator."""

import pandas as pd

# NIST 800-53 control family mappings for common STIG categories
STIG_CONTROL_MAPPING = {
    "CAT I": [
        ("AC-2", "Account Management"),
        ("AC-6", "Least Privilege"),
        ("IA-5", "Authenticator Management"),
        ("SC-28", "Protection of Information at Rest"),
        ("SI-2", "Flaw Remediation"),
    ],
    "CAT II": [
        ("AU-2", "Event Logging"),
        ("CM-6", "Configuration Settings"),
        ("CM-7", "Least Functionality"),
        ("SC-8", "Transmission Confidentiality and Integrity"),
        ("SI-3", "Malicious Code Protection"),
    ],
    "CAT III": [
        ("AU-12", "Audit Record Generation"),
        ("CM-2", "Baseline Configuration"),
        ("RA-5", "Vulnerability Scanning"),
        ("SA-11", "Developer Testing and Evaluation"),
    ],
}

COMPENSATING_CONTROLS = {
    "CAT I": [
        "Implement network segmentation to isolate the affected system",
        "Apply compensating controls per NIST SP 800-53 Appendix F",
        "Increase monitoring and alerting on the affected asset",
        "Restrict access to authorized personnel only (least privilege)",
        "Document POA&M with concrete milestones within 30 days",
    ],
    "CAT II": [
        "Apply configuration hardening per applicable STIG",
        "Implement continuous monitoring for the affected control",
        "Document deviation rationale and obtain Authorizing Official (AO) acceptance",
        "Schedule remediation within 90 days with tracked POA&M",
    ],
    "CAT III": [
        "Document accepted risk per organizational risk tolerance",
        "Schedule remediation within 180 days per POA&M",
        "Apply defense-in-depth compensating controls",
    ],
}


def _ato_decision(risk_scores: dict, ckl_df: pd.DataFrame, kev_df: pd.DataFrame,
                  cve_list: list, emass_df: pd.DataFrame,
                  poam_metrics: dict = None) -> tuple:
    """
    Determine ATO recommendation and reasoning.

    Returns
    -------
    (recommendation: str, reasons: list[str], color: str)
    """
    reasons = []
    compliance_pct = risk_scores.get("emass_compliance_pct", 100.0)
    open_cat1 = risk_scores.get("open_cat1", 0)
    kev_count = risk_scores.get("kev_count", 0)

    # Check CRITICAL CIA dimension
    critical_dims = [
        d for d in ["C", "I", "A"]
        if risk_scores.get(d, {}).get("level") == "CRITICAL"
    ]

    # Check critical CVEs (CVSS ≥ 9)
    critical_cves = [c for c in (cve_list or []) if (c.get("cvss_v3_score") or 0) >= 9.0]

    # KEV with no mitigation noted
    kev_no_mitigation = False
    if kev_df is not None and not kev_df.empty:
        # Check if any KEV entry has no required action or if Comments in CKL are empty
        kev_no_mitigation = len(kev_df) > 0  # Conservative: any KEV match flags this

    # --- DATO conditions ---
    if critical_dims:
        reasons.append(f"CRITICAL risk level in CIA dimension(s): {', '.join(critical_dims)}")
    if open_cat1 > 5:
        reasons.append(f"{open_cat1} open CAT I (critical) STIG findings — exceeds 5-finding threshold")
    if kev_no_mitigation and kev_count > 0:
        reasons.append(f"{kev_count} CISA KEV match(es) with no documented mitigation")
    if compliance_pct < 60:
        reasons.append(f"eMASS compliance at {compliance_pct:.1f}% — below 60% minimum threshold")

    # --- POA&M health escalation (DATO level) ---
    poam_health = risk_scores.get("poam_health_score")
    if poam_health is not None and poam_health < 40:
        reasons.append(
            f"POA&M health score {poam_health:.0f}/100 — severely deficient "
            f"(NIST SP 800-37 Rev. 2 §3.6 non-conformance)"
        )

    if reasons:
        return "DATO", reasons, "#c0392b"

    # --- IATO conditions ---
    iato_reasons = []
    high_dims = [
        d for d in ["C", "I", "A"]
        if risk_scores.get(d, {}).get("level") == "HIGH"
    ]
    if high_dims:
        iato_reasons.append(f"HIGH risk level in CIA dimension(s): {', '.join(high_dims)}")
    if 1 <= open_cat1 <= 5:
        iato_reasons.append(f"{open_cat1} open CAT I STIG finding(s) — requires remediation within 30 days")
    if critical_cves:
        iato_reasons.append(
            f"{len(critical_cves)} CVE(s) with CVSS ≥ 9.0 without documented patch applied"
        )
    if 60 <= compliance_pct < 80:
        iato_reasons.append(f"eMASS compliance at {compliance_pct:.1f}% — below 80% (IATO threshold)")

    # --- POA&M health escalation (IATO level) ---
    if poam_health is not None and 40 <= poam_health < 60:
        iato_reasons.append(
            f"POA&M health score {poam_health:.0f}/100 — deficient remediation plan management "
            f"(NIST SP 800-171 §3.12.4)"
        )

    if iato_reasons:
        return "IATO", iato_reasons, "#e67e22"

    # --- Conditional ATO conditions ---
    cato_reasons = []
    medium_dims = [
        d for d in ["C", "I", "A"]
        if risk_scores.get(d, {}).get("level") == "MEDIUM"
    ]
    open_cat2 = risk_scores.get("open_cat2", 0)

    if medium_dims:
        cato_reasons.append(f"MEDIUM risk level in CIA dimension(s): {', '.join(medium_dims)}")
    if open_cat2 > 0:
        cato_reasons.append(f"{open_cat2} open CAT II finding(s) with POA&M required")
    if 80 <= compliance_pct < 90:
        cato_reasons.append(f"eMASS compliance at {compliance_pct:.1f}% — below 90% (full ATO threshold)")

    if cato_reasons:
        return "Conditional ATO", cato_reasons, "#f39c12"

    # --- Full ATO ---
    return "ATO", ["All CIA dimensions LOW", "No open CAT I findings",
                   "No unpatched CVSS ≥ 7 vulnerabilities",
                   f"eMASS compliance at {compliance_pct:.1f}%"], "#27ae60"


def _generate_stig_mitigations(ckl_df: pd.DataFrame) -> list:
    """Generate per-finding mitigation recommendations for open STIG findings."""
    if ckl_df is None or ckl_df.empty:
        return []

    mitigations = []
    open_findings = ckl_df[ckl_df["Status"] == "Open"].head(20)  # Cap at 20 for display

    for _, row in open_findings.iterrows():
        cat = row.get("CAT", "CAT II")
        controls = STIG_CONTROL_MAPPING.get(cat, STIG_CONTROL_MAPPING["CAT II"])
        comp_controls = COMPENSATING_CONTROLS.get(cat, COMPENSATING_CONTROLS["CAT II"])

        mitigations.append({
            "type": "STIG Finding",
            "severity": cat,
            "title": row.get("Rule_Title", row.get("Vuln_Num", "Unknown")),
            "vuln_id": row.get("Vuln_Num", ""),
            "nist_controls": [f"{c[0]} — {c[1]}" for c in controls[:3]],
            "compensating_controls": comp_controls[:3],
            "finding_details": row.get("Finding_Details", ""),
        })

    return mitigations


def _generate_cve_mitigations(cve_list: list) -> list:
    """Generate per-CVE mitigation recommendations."""
    if not cve_list:
        return []

    # Focus on high/critical CVEs
    high_cves = sorted(
        [c for c in cve_list if (c.get("cvss_v3_score") or 0) >= 7.0],
        key=lambda x: x.get("cvss_v3_score") or 0,
        reverse=True,
    )[:15]

    mitigations = []
    for cve in high_cves:
        score = cve.get("cvss_v3_score") or 0
        severity = cve.get("cvss_v3_severity", "UNKNOWN")
        refs = cve.get("references", [])

        # Check for patch references
        patch_refs = [r for r in refs if any(
            kw in r.lower() for kw in ["patch", "advisory", "update", "kb", "security"]
        )]

        actions = []
        if patch_refs:
            actions.append(f"Apply available patch — see: {patch_refs[0]}")
        else:
            actions.append("No patch reference found in NVD — monitor vendor advisories")

        if score >= 9.0:
            actions.append("Treat as emergency — apply within 15 days per CISA BOD 22-01")
            actions.append("Consider network isolation until patch is applied")
        elif score >= 7.0:
            actions.append("Apply within 30 days per NIST SP 800-40 guidance")

        actions.append("Verify with vulnerability scanner post-remediation")

        mitigations.append({
            "type": "CVE",
            "severity": severity,
            "cvss_score": score,
            "title": cve.get("cve_id", ""),
            "description": cve.get("description", "")[:300],
            "vendor": cve.get("vendor", ""),
            "product": cve.get("product", ""),
            "actions": actions,
            "references": refs[:3],
        })

    return mitigations


def _generate_kev_mitigations(kev_df: pd.DataFrame) -> list:
    """Generate KEV-specific mitigation recommendations."""
    if kev_df is None or kev_df.empty:
        return []

    mitigations = []
    for _, row in kev_df.iterrows():
        mitigations.append({
            "type": "KEV",
            "severity": "CRITICAL",
            "title": row.get("vulnerabilityName", row.get("cve_id", "")),
            "cve_id": row.get("cve_id", ""),
            "vendor": row.get("vendorProject", ""),
            "product": row.get("product", ""),
            "required_action": row.get("requiredAction", "Follow CISA remediation guidance"),
            "ransomware": row.get("knownRansomwareCampaignUse", "Unknown"),
            "date_added": row.get("dateAdded", ""),
            "description": row.get("shortDescription", ""),
        })

    return mitigations


_SEVERITY_SORT = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _derive_severity(control_id: str, poam_severity: str) -> str:
    """Derive display severity from POA&M severity field or fallback."""
    if poam_severity and poam_severity.strip():
        return poam_severity.strip()
    return "Unknown"


def _generate_poam_mitigations(poam_metrics: dict) -> list:
    """
    Build mitigation dicts from POA&M shortfalls, capped at 20 items,
    sorted by severity (critical first).
    """
    if not poam_metrics:
        return []
    shortfalls = poam_metrics.get("shortfalls", [])
    if not shortfalls:
        return []

    # Map POAM_ID → severity from items_df
    items_df = poam_metrics.get("items_df")
    severity_map = {}
    if items_df is not None and not items_df.empty and "POAM_ID" in items_df.columns:
        for _, row in items_df.iterrows():
            severity_map[str(row.get("POAM_ID", ""))] = str(row.get("Severity", "Unknown"))

    mitigations = []
    for sf in shortfalls:
        poam_id = sf.get("poam_id", "")
        sev = _derive_severity(sf.get("control_id", ""), severity_map.get(poam_id, "Unknown"))
        mitigations.append({
            "type": "POA&M Deficiency",
            "severity": sev,
            "poam_id": poam_id,
            "control_id": sf.get("control_id", ""),
            "weakness_name": sf.get("weakness_name", ""),
            "status": sf.get("status", ""),
            "issues": sf.get("issues", []),
            "recommendations": sf.get("recommendations", []),
        })

    # Sort by severity (critical first)
    mitigations.sort(
        key=lambda m: _SEVERITY_SORT.get(m["severity"].lower(), 4)
    )
    return mitigations[:20]


def generate_ato_recommendation(
    risk_scores: dict,
    ckl_df: pd.DataFrame,
    kev_df: pd.DataFrame,
    cve_list: list,
    emass_df: pd.DataFrame,
    poam_metrics: dict = None,
) -> dict:
    """
    Generate complete ATO recommendation with mitigations.

    Returns
    -------
    dict: {
        "recommendation": str,    # ATO / IATO / Conditional ATO / DATO
        "reasons": list[str],
        "color": str,             # hex color for UI
        "stig_mitigations": list,
        "cve_mitigations": list,
        "kev_mitigations": list,
        "poam_mitigations": list,
    }
    """
    recommendation, reasons, color = _ato_decision(
        risk_scores, ckl_df, kev_df, cve_list, emass_df, poam_metrics
    )

    return {
        "recommendation": recommendation,
        "reasons": reasons,
        "color": color,
        "stig_mitigations": _generate_stig_mitigations(ckl_df),
        "cve_mitigations": _generate_cve_mitigations(cve_list),
        "kev_mitigations": _generate_kev_mitigations(kev_df),
        "poam_mitigations": _generate_poam_mitigations(poam_metrics),
    }
