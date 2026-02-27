"""Excel and CSV export utilities for the RMF Assessment Dashboard."""

import io
import datetime
import pandas as pd


def _safe_df(df) -> pd.DataFrame:
    """Return an empty DataFrame if input is None or empty."""
    if df is None or (isinstance(df, pd.DataFrame) and df.empty):
        return pd.DataFrame()
    return df


def _cve_list_to_df(cve_list: list) -> pd.DataFrame:
    """Convert list of CVE dicts to a flat DataFrame."""
    if not cve_list:
        return pd.DataFrame(columns=[
            "CVE_ID", "Vendor", "Product", "CVSS_Score", "Severity",
            "C_Impact", "I_Impact", "A_Impact", "Published", "Description",
        ])
    rows = []
    for cve in cve_list:
        rows.append({
            "CVE_ID": cve.get("cve_id", ""),
            "Vendor": cve.get("vendor", ""),
            "Product": cve.get("product", ""),
            "CVSS_Score": cve.get("cvss_v3_score", ""),
            "Severity": cve.get("cvss_v3_severity", ""),
            "C_Impact": cve.get("C_impact", ""),
            "I_Impact": cve.get("I_impact", ""),
            "A_Impact": cve.get("A_impact", ""),
            "Published": cve.get("published_date", ""),
            "Description": cve.get("description", "")[:500],
        })
    return pd.DataFrame(rows)


def _risk_summary_df(risk_scores: dict, ato_result: dict, system_name: str, system_type: str) -> pd.DataFrame:
    """Build a summary DataFrame from risk scores and ATO result."""
    rows = [
        {"Field": "System Name",          "Value": system_name},
        {"Field": "System Type",          "Value": system_type},
        {"Field": "Analysis Date",        "Value": datetime.date.today().isoformat()},
        {"Field": "ATO Recommendation",   "Value": ato_result.get("recommendation", "")},
        {"Field": "Overall Risk Score",   "Value": risk_scores.get("overall_score", "")},
        {"Field": "Overall Risk Level",   "Value": risk_scores.get("overall_level", "")},
        {"Field": "Confidentiality Score","Value": risk_scores.get("C", {}).get("score", "")},
        {"Field": "Confidentiality Level","Value": risk_scores.get("C", {}).get("level", "")},
        {"Field": "Integrity Score",      "Value": risk_scores.get("I", {}).get("score", "")},
        {"Field": "Integrity Level",      "Value": risk_scores.get("I", {}).get("level", "")},
        {"Field": "Availability Score",   "Value": risk_scores.get("A", {}).get("score", "")},
        {"Field": "Availability Level",   "Value": risk_scores.get("A", {}).get("level", "")},
        {"Field": "Open CAT I Findings",  "Value": risk_scores.get("open_cat1", 0)},
        {"Field": "Open CAT II Findings", "Value": risk_scores.get("open_cat2", 0)},
        {"Field": "Open CAT III Findings","Value": risk_scores.get("open_cat3", 0)},
        {"Field": "eMASS Compliance %",   "Value": risk_scores.get("emass_compliance_pct", "")},
        {"Field": "KEV Matches",          "Value": risk_scores.get("kev_count", 0)},
    ]
    for i, reason in enumerate(ato_result.get("reasons", []), 1):
        rows.append({"Field": f"ATO Reason {i}", "Value": reason})
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Conditional formatting helpers
# ──────────────────────────────────────────────────────────────────────────────

def _add_formats(workbook):
    """Pre-build all reusable cell formats."""
    base = {"border": 1, "text_wrap": True}
    return {
        # Header
        "header": workbook.add_format({
            "bold": True, "bg_color": "#1a3a5c", "font_color": "white",
            "border": 1, "text_wrap": True, "valign": "vcenter",
        }),
        # Risk levels
        "critical": workbook.add_format({**base, "bg_color": "#c0392b", "font_color": "white", "bold": True}),
        "high":     workbook.add_format({**base, "bg_color": "#e67e22", "font_color": "white", "bold": True}),
        "medium":   workbook.add_format({**base, "bg_color": "#f39c12", "font_color": "#1a1a1a", "bold": True}),
        "low":      workbook.add_format({**base, "bg_color": "#27ae60", "font_color": "white", "bold": True}),
        # Status
        "open":     workbook.add_format({**base, "bg_color": "#fde8e8", "font_color": "#7b241c"}),
        "naf":      workbook.add_format({**base, "bg_color": "#e8f8e8", "font_color": "#1e8449"}),
        "na":       workbook.add_format({**base, "bg_color": "#f2f3f4", "font_color": "#626567"}),
        "nr":       workbook.add_format({**base, "bg_color": "#fdfefe", "font_color": "#aab7b8"}),
        # Compliance
        "compliant":     workbook.add_format({**base, "bg_color": "#d5f5e3", "font_color": "#1e8449"}),
        "noncompliant":  workbook.add_format({**base, "bg_color": "#fadbd8", "font_color": "#7b241c"}),
        # ATO banners (bold, larger)
        "ato_dato":  workbook.add_format({
            **base, "bg_color": "#c0392b", "font_color": "white",
            "bold": True, "font_size": 13,
        }),
        "ato_iato":  workbook.add_format({
            **base, "bg_color": "#e67e22", "font_color": "white",
            "bold": True, "font_size": 13,
        }),
        "ato_cato":  workbook.add_format({
            **base, "bg_color": "#f39c12", "font_color": "#1a1a1a",
            "bold": True, "font_size": 13,
        }),
        "ato_ato":   workbook.add_format({
            **base, "bg_color": "#27ae60", "font_color": "white",
            "bold": True, "font_size": 13,
        }),
        # Ransomware flag
        "ransomware": workbook.add_format({**base, "bg_color": "#7d3c98", "font_color": "white", "bold": True}),
        # Default cell
        "cell": workbook.add_format({**base, "valign": "top"}),
        # Numeric cell (right-aligned)
        "number": workbook.add_format({**base, "num_format": "0.0", "align": "center"}),
    }


def _col_index(df, col_name) -> int:
    """Return 0-based column index by name, or -1 if not found."""
    try:
        return df.columns.tolist().index(col_name)
    except ValueError:
        return -1


def _xl_range(col_idx: int, first_row: int, last_row: int) -> str:
    """Return an xlsxwriter A1-style range string for a single column."""
    from xlsxwriter.utility import xl_rowcol_to_cell
    top = xl_rowcol_to_cell(first_row, col_idx)
    bot = xl_rowcol_to_cell(last_row, col_idx)
    return f"{top}:{bot}"


def _apply_summary_formatting(ws, df, fmts):
    """Colour ATO recommendation and risk level rows on the Summary sheet."""
    ato_fmt_map = {
        "DATO":            fmts["ato_dato"],
        "IATO":            fmts["ato_iato"],
        "Conditional ATO": fmts["ato_cato"],
        "ATO":             fmts["ato_ato"],
    }
    level_fmt_map = {
        "CRITICAL": fmts["critical"],
        "HIGH":     fmts["high"],
        "MEDIUM":   fmts["medium"],
        "LOW":      fmts["low"],
    }

    for row_idx, (_, row) in enumerate(df.iterrows(), start=1):
        field = str(row["Field"])
        value = str(row["Value"])

        if field == "ATO Recommendation":
            fmt = ato_fmt_map.get(value, fmts["cell"])
            _safe_write(ws, row_idx, 0, field, fmt)
            _safe_write(ws, row_idx, 1, value, fmt)
        elif "Level" in field:
            fmt = level_fmt_map.get(value, fmts["cell"])
            _safe_write(ws, row_idx, 0, field, fmts["cell"])
            _safe_write(ws, row_idx, 1, value, fmt)
        else:
            _safe_write(ws, row_idx, 0, field, fmts["cell"])
            _safe_write(ws, row_idx, 1, value, fmts["cell"])


def _apply_stig_formatting(ws, df, fmts):
    """Colour CAT and Status columns on the STIG Findings sheet."""
    cat_fmt = {"CAT I": fmts["critical"], "CAT II": fmts["high"], "CAT III": fmts["medium"]}
    status_fmt = {
        "Open":          fmts["open"],
        "Not a Finding": fmts["naf"],
        "Not Applicable": fmts["na"],
        "Not Reviewed":  fmts["nr"],
    }

    cat_col    = _col_index(df, "CAT")
    status_col = _col_index(df, "Status_Label")

    for row_idx, (_, row) in enumerate(df.iterrows(), start=1):
        for col_idx, col_name in enumerate(df.columns):
            value = row[col_name]
            if col_idx == cat_col:
                fmt = cat_fmt.get(str(value), fmts["cell"])
            elif col_idx == status_col:
                fmt = status_fmt.get(str(value), fmts["cell"])
            else:
                fmt = fmts["cell"]
            _safe_write(ws, row_idx, col_idx, value, fmt)


def _safe_write(ws, row, col, value, fmt):
    """Write a cell, converting NaN/None to empty string to avoid xlsxwriter errors."""
    import math
    if value is None:
        ws.write(row, col, "", fmt)
    elif isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        ws.write(row, col, "", fmt)
    else:
        ws.write(row, col, value, fmt)


def _apply_cve_formatting(ws, df, fmts, last_row: int):
    """
    Colour Severity column and apply a 3-colour CVSS score scale
    on the CVE List sheet.
    """
    sev_fmt = {
        "CRITICAL": fmts["critical"],
        "HIGH":     fmts["high"],
        "MEDIUM":   fmts["medium"],
        "LOW":      fmts["low"],
    }
    sev_col  = _col_index(df, "Severity")
    cvss_col = _col_index(df, "CVSS_Score")

    for row_idx, (_, row) in enumerate(df.iterrows(), start=1):
        for col_idx, col_name in enumerate(df.columns):
            value = row[col_name]
            if col_idx == sev_col:
                fmt = sev_fmt.get(str(value).upper(), fmts["cell"])
            else:
                fmt = fmts["cell"]
            _safe_write(ws, row_idx, col_idx, value, fmt)

    # 3-colour scale on CVSS_Score column (green→yellow→red, 0–10)
    if cvss_col >= 0 and last_row >= 1:
        ws.conditional_format(
            1, cvss_col, last_row, cvss_col,
            {
                "type":      "3_color_scale",
                "min_color": "#63be7b",   # green  (low score)
                "mid_color": "#ffeb84",   # yellow (mid score)
                "max_color": "#f8696b",   # red    (high score)
                "min_type":  "num", "min_value":  0,
                "mid_type":  "num", "mid_value":  5,
                "max_type":  "num", "max_value": 10,
            },
        )


def _apply_kev_formatting(ws, df, fmts):
    """Colour ransomware flag column on the KEV Matches sheet."""
    rw_col = _col_index(df, "knownRansomwareCampaignUse")

    for row_idx, (_, row) in enumerate(df.iterrows(), start=1):
        for col_idx, col_name in enumerate(df.columns):
            value = row[col_name]
            if col_idx == rw_col and str(value).lower() == "known":
                fmt = fmts["ransomware"]
            else:
                fmt = fmts["cell"]
            _safe_write(ws, row_idx, col_idx, value, fmt)


def _apply_emass_formatting(ws, df, fmts, last_row: int):
    """
    Colour Status column and apply a data bar on eMASS Results sheet.
    """
    status_fmt = {
        "Compliant":    fmts["compliant"],
        "NonCompliant": fmts["noncompliant"],
        "NA":           fmts["na"],
        "NR":           fmts["nr"],
    }
    status_col = _col_index(df, "Status")

    for row_idx, (_, row) in enumerate(df.iterrows(), start=1):
        for col_idx, col_name in enumerate(df.columns):
            value = row[col_name]
            if col_idx == status_col:
                fmt = status_fmt.get(str(value), fmts["cell"])
            else:
                fmt = fmts["cell"]
            _safe_write(ws, row_idx, col_idx, value, fmt)


# ──────────────────────────────────────────────────────────────────────────────
# Main export function
# ──────────────────────────────────────────────────────────────────────────────

def export_excel(
    system_name: str,
    system_type: str,
    risk_scores: dict,
    ato_result: dict,
    ckl_df: pd.DataFrame,
    cve_list: list,
    kev_df: pd.DataFrame,
    emass_df: pd.DataFrame,
    inventory_df: pd.DataFrame,
) -> bytes:
    """
    Export full assessment to a multi-sheet Excel workbook with
    conditional formatting applied to every sheet.

    Returns
    -------
    bytes : Excel file content
    """
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        workbook = writer.book
        fmts = _add_formats(workbook)

        def write_sheet(df, sheet_name, col_widths=None):
            """Write DataFrame to sheet, returning (worksheet, df_written)."""
            if df.empty:
                df = pd.DataFrame({"No Data": ["No data available for this section"]})
            df.to_excel(writer, sheet_name=sheet_name, index=False)
            ws = writer.sheets[sheet_name]
            # Re-write header row with styled format
            for col_num, col_name in enumerate(df.columns):
                ws.write(0, col_num, col_name, fmts["header"])
                width = (col_widths or {}).get(col_name, max(len(str(col_name)) + 2, 15))
                ws.set_column(col_num, col_num, min(width, 60))
            ws.set_row(0, 20)
            ws.freeze_panes(1, 0)
            ws.autofilter(0, 0, 0, len(df.columns) - 1)
            return ws, df

        # ── Sheet 1: Summary ──────────────────────────────────────────────
        summary_df = _risk_summary_df(risk_scores, ato_result, system_name, system_type)
        ws_sum, _ = write_sheet(summary_df, "Summary", {"Field": 30, "Value": 50})
        _apply_summary_formatting(ws_sum, summary_df, fmts)

        # ── Sheet 2: STIG Findings ────────────────────────────────────────
        ckl_export = _safe_df(ckl_df)
        if not ckl_export.empty:
            ckl_export = ckl_export.drop(columns=["Finding_Details", "Comments"], errors="ignore")
        ws_ckl, ckl_written = write_sheet(ckl_export, "STIG Findings", {
            "Vuln_Num": 12, "Rule_ID": 25, "Rule_Title": 50,
            "CAT": 8, "Status_Label": 18,
        })
        if not ckl_written.empty and "CAT" in ckl_written.columns:
            _apply_stig_formatting(ws_ckl, ckl_written, fmts)

        # ── Sheet 3: CVE List ─────────────────────────────────────────────
        cve_df = _cve_list_to_df(cve_list)
        ws_cve, cve_written = write_sheet(cve_df, "CVE List", {
            "CVE_ID": 18, "Vendor": 20, "Product": 20,
            "CVSS_Score": 12, "Severity": 12, "Description": 60,
        })
        if not cve_written.empty:
            _apply_cve_formatting(ws_cve, cve_written, fmts, last_row=len(cve_written))

        # ── Sheet 4: KEV Matches ──────────────────────────────────────────
        kev_export = _safe_df(kev_df)
        ws_kev, kev_written = write_sheet(kev_export, "KEV Matches", {
            "cve_id": 18, "vendorProject": 22, "product": 28,
            "vulnerabilityName": 40, "dateAdded": 13,
            "knownRansomwareCampaignUse": 20, "requiredAction": 50,
            "matched_by": 18,
        })
        if not kev_written.empty and "knownRansomwareCampaignUse" in kev_written.columns:
            _apply_kev_formatting(ws_kev, kev_written, fmts)

        # ── Sheet 5: eMASS Results ────────────────────────────────────────
        emass_export = _safe_df(emass_df)
        ws_em, em_written = write_sheet(emass_export, "eMASS Results", {
            "Control_ID": 12, "Control_Name": 38, "Status": 15,
            "Test_Result": 15, "Findings": 55, "Test_Date": 14,
        })
        if not em_written.empty and "Status" in em_written.columns:
            _apply_emass_formatting(ws_em, em_written, fmts, last_row=len(em_written))

        # ── Sheet 6: Inventory ────────────────────────────────────────────
        inv_export = _safe_df(inventory_df)
        write_sheet(inv_export, "Inventory", {
            "Asset_Name": 25, "Type": 12, "Vendor": 20,
            "Product": 25, "Version": 15, "OS": 25, "IP_Address": 16,
        })

    return output.getvalue()


# ──────────────────────────────────────────────────────────────────────────────
# CSV export (unchanged)
# ──────────────────────────────────────────────────────────────────────────────

def export_csv(
    risk_scores: dict,
    ato_result: dict,
    ckl_df: pd.DataFrame,
    cve_list: list,
    kev_df: pd.DataFrame,
    emass_df: pd.DataFrame,
) -> bytes:
    """
    Export a flat combined findings CSV.

    Returns
    -------
    bytes : CSV file content (UTF-8 with BOM for Excel compatibility)
    """
    rows = []

    if ckl_df is not None and not ckl_df.empty:
        for _, r in ckl_df.iterrows():
            rows.append({
                "Source": "STIG",
                "ID": r.get("Vuln_Num", ""),
                "Title": r.get("Rule_Title", ""),
                "Severity": r.get("CAT", ""),
                "Status": r.get("Status_Label", ""),
                "Details": r.get("Finding_Details", "")[:200],
                "CVSS_Score": "",
            })

    for cve in (cve_list or []):
        rows.append({
            "Source": "CVE (NVD)",
            "ID": cve.get("cve_id", ""),
            "Title": f"{cve.get('vendor','')} {cve.get('product','')}".strip(),
            "Severity": cve.get("cvss_v3_severity", ""),
            "Status": "Open",
            "Details": cve.get("description", "")[:200],
            "CVSS_Score": cve.get("cvss_v3_score", ""),
        })

    if kev_df is not None and not kev_df.empty:
        for _, r in kev_df.iterrows():
            rows.append({
                "Source": "CISA KEV",
                "ID": r.get("cve_id", ""),
                "Title": r.get("vulnerabilityName", ""),
                "Severity": "CRITICAL",
                "Status": "Known Exploited",
                "Details": r.get("shortDescription", "")[:200],
                "CVSS_Score": "",
            })

    if not rows:
        rows = [{"Source": "N/A", "ID": "", "Title": "No findings", "Severity": "",
                 "Status": "", "Details": "", "CVSS_Score": ""}]

    df = pd.DataFrame(rows)
    return df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
