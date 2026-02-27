"""eMASS export parser — auto-detects CSV/XLSX and normalizes column names."""

import io
import pandas as pd


# Known eMASS column name variants for each normalized field
COLUMN_ALIASES = {
    "Control_ID": [
        "Control ID", "control_id", "CONTROL_ID", "Control Number",
        "control number", "ControlID", "Security Control Identifier",
        "AP Acronym", "AP acronym",
    ],
    "Control_Name": [
        "Control Name", "control_name", "CONTROL_NAME", "Control Title",
        "Security Control Name", "ControlName", "Control",
    ],
    "Status": [
        "Compliance Status", "Status", "status", "STATUS",
        "Test Result Status", "Implementation Status",
        "Inherited Status",
    ],
    "Test_Result": [
        "Test Result", "test_result", "TEST_RESULT", "Test Results",
        "Inherited Test Result", "Result",
    ],
    "Findings": [
        "Findings", "findings", "FINDINGS", "Finding Details",
        "Non-Compliant Findings", "Vulnerability Description",
        "Finding Description",
    ],
    "Test_Date": [
        "Test Date", "test_date", "TEST_DATE", "Last Tested",
        "Assessment Date", "Date Tested", "Test Completion Date",
    ],
}

STATUS_NORMALIZE = {
    # Compliant variants
    "compliant": "Compliant",
    "pass": "Compliant",
    "satisfied": "Compliant",
    "implemented": "Compliant",
    "inherited": "Compliant",
    "yes": "Compliant",
    # Non-compliant variants
    "non-compliant": "NonCompliant",
    "noncompliant": "NonCompliant",
    "fail": "NonCompliant",
    "not satisfied": "NonCompliant",
    "not implemented": "NonCompliant",
    "open": "NonCompliant",
    "no": "NonCompliant",
    # Not applicable
    "not applicable": "NA",
    "na": "NA",
    "n/a": "NA",
    # Not reviewed
    "not reviewed": "NR",
    "nr": "NR",
    "not tested": "NR",
    "pending": "NR",
}


def _find_column(df_columns, aliases):
    """Return the first matching column name from a list of aliases."""
    col_lower = {c.lower(): c for c in df_columns}
    for alias in aliases:
        if alias in df_columns:
            return alias
        if alias.lower() in col_lower:
            return col_lower[alias.lower()]
    return None


def _normalize_status(value):
    """Normalize eMASS status values to Compliant/NonCompliant/NA/NR."""
    if pd.isna(value):
        return "NR"
    normalized = str(value).strip().lower()
    return STATUS_NORMALIZE.get(normalized, str(value).strip())


def parse_emass(file_obj) -> pd.DataFrame:
    """
    Parse an eMASS export file (CSV or XLSX).

    Parameters
    ----------
    file_obj : UploadedFile or file-like with .name attribute

    Returns
    -------
    pd.DataFrame with columns:
        Control_ID, Control_Name, Status, Test_Result, Findings, Test_Date
    """
    name = getattr(file_obj, "name", "")
    if name.lower().endswith(".xlsx"):
        raw_df = pd.read_excel(file_obj, engine="openpyxl", dtype=str)
    else:
        # Try CSV; handle common encodings
        content = file_obj.read()
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                raw_df = pd.read_csv(io.StringIO(content.decode(enc)), dtype=str)
                break
            except (UnicodeDecodeError, pd.errors.ParserError):
                continue
        else:
            raise ValueError("Could not decode eMASS CSV file. Try saving as UTF-8.")

    # Strip whitespace from column names
    raw_df.columns = [c.strip() for c in raw_df.columns]

    # Build normalized DataFrame
    result = {}
    for field, aliases in COLUMN_ALIASES.items():
        col = _find_column(raw_df.columns, aliases)
        if col:
            result[field] = raw_df[col].fillna("").astype(str).str.strip()
        else:
            result[field] = ""

    df = pd.DataFrame(result)

    # Normalize status column
    if "Status" in df.columns:
        df["Status"] = df["Status"].apply(_normalize_status)

    # Drop entirely empty rows
    df = df[df["Control_ID"].str.strip() != ""].reset_index(drop=True)

    if df.empty:
        df = pd.DataFrame(
            columns=["Control_ID", "Control_Name", "Status", "Test_Result", "Findings", "Test_Date"]
        )
    return df
