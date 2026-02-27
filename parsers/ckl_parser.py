"""STIG .ckl XML parser — converts DISA STIG Viewer checklist files to DataFrame."""

import io
import pandas as pd
from lxml import etree


SEVERITY_MAP = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
    "critical": "CAT I",
}

STATUS_LABELS = {
    "Open": "Open",
    "NotAFinding": "Not a Finding",
    "Not_Applicable": "Not Applicable",
    "Not_Reviewed": "Not Reviewed",
}


def _text(element, tag, default=""):
    """Extract text from a child element, returning default if not found."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _stig_data(vuln, sid_name):
    """Extract a STIG_DATA attribute value by its VULN_ATTRIBUTE name."""
    for stig_data in vuln.findall("STIG_DATA"):
        attr = stig_data.find("VULN_ATTRIBUTE")
        val = stig_data.find("ATTRIBUTE_DATA")
        if attr is not None and attr.text and attr.text.strip() == sid_name:
            return val.text.strip() if val is not None and val.text else ""
    return ""


def parse_ckl(file_obj) -> pd.DataFrame:
    """
    Parse a DISA STIG Viewer .ckl file.

    Parameters
    ----------
    file_obj : file-like object or bytes
        The uploaded .ckl file content.

    Returns
    -------
    pd.DataFrame with columns:
        Vuln_Num, Rule_ID, Rule_Title, Severity, CAT, Status,
        Status_Label, Finding_Details, Comments
    """
    if isinstance(file_obj, bytes):
        content = file_obj
    else:
        content = file_obj.read()

    try:
        root = etree.fromstring(content)
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"Invalid .ckl XML: {exc}") from exc

    records = []
    for vuln in root.iter("VULN"):
        vuln_num = _stig_data(vuln, "Vuln_Num")
        rule_id = _stig_data(vuln, "Rule_ID")
        rule_title = _stig_data(vuln, "Rule_Title")
        severity_raw = _stig_data(vuln, "Severity").lower()

        severity_label = severity_raw.capitalize() if severity_raw else "Unknown"
        cat = SEVERITY_MAP.get(severity_raw, "Unknown")

        status_raw = _text(vuln, "STATUS")
        status_label = STATUS_LABELS.get(status_raw, status_raw)

        finding_details = _text(vuln, "FINDING_DETAILS")
        comments = _text(vuln, "COMMENTS")

        records.append(
            {
                "Vuln_Num": vuln_num,
                "Rule_ID": rule_id,
                "Rule_Title": rule_title,
                "Severity": severity_label,
                "CAT": cat,
                "Status": status_raw,
                "Status_Label": status_label,
                "Finding_Details": finding_details,
                "Comments": comments,
            }
        )

    df = pd.DataFrame(records)
    if df.empty:
        df = pd.DataFrame(
            columns=[
                "Vuln_Num", "Rule_ID", "Rule_Title", "Severity", "CAT",
                "Status", "Status_Label", "Finding_Details", "Comments",
            ]
        )
    return df
