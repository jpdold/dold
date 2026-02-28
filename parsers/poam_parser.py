"""eMASS POA&M export parser — auto-detects CSV/XLSX and normalizes column names."""

import io
import pandas as pd


# Known column name variants for each normalized field
COLUMN_ALIASES = {
    "POAM_ID": [
        "poam_id", "poam id", "item id", "id",
        "POAM_ID", "POAM ID", "Item ID", "ID",
    ],
    "Control_ID": [
        "control_id", "control id", "associated control",
        "Control_ID", "Control ID", "Associated Control",
    ],
    "Weakness_Name": [
        "weakness_name", "weakness name", "weakness description",
        "weakness", "description",
        "Weakness_Name", "Weakness Name", "Weakness Description",
        "Weakness", "Description",
    ],
    "Status": [
        "status", "poam status",
        "Status", "POAM Status",
    ],
    "POC": [
        "poc", "point of contact", "responsible party",
        "POC", "Point of Contact", "Responsible Party",
    ],
    "Resources_Required": [
        "resources_required", "resources required", "resources",
        "Resources_Required", "Resources Required", "Resources",
    ],
    "Scheduled_Completion": [
        "scheduled_completion", "scheduled completion date",
        "completion date", "scheduled completion",
        "Scheduled_Completion", "Scheduled Completion Date",
        "Completion Date", "Scheduled Completion",
    ],
    "Milestone_Description": [
        "milestone_description", "milestone description",
        "milestone", "milestones with completion dates",
        "Milestone_Description", "Milestone Description",
        "Milestone", "Milestones with Completion Dates",
    ],
    "Milestone_Completion": [
        "milestone_completion", "milestone completion date",
        "Milestone_Completion", "Milestone Completion Date",
    ],
    "Mitigation": [
        "mitigation", "mitigation plan", "mitigation strategy",
        "Mitigation", "Mitigation Plan", "Mitigation Strategy",
    ],
    "Severity": [
        "severity", "risk level",
        "Severity", "Risk Level",
    ],
    "Date_Entered": [
        "date_entered", "date entered", "date identified",
        "Date_Entered", "Date Entered", "Date Identified",
    ],
}

_DATE_COLUMNS = {"Scheduled_Completion", "Milestone_Completion", "Date_Entered"}


def _find_column(df_columns, aliases):
    """Return the first matching column name from a list of aliases."""
    col_lower = {c.lower(): c for c in df_columns}
    for alias in aliases:
        if alias in df_columns:
            return alias
        if alias.lower() in col_lower:
            return col_lower[alias.lower()]
    return None


def parse_poam(file_obj) -> pd.DataFrame:
    """
    Parse an eMASS POA&M export file (CSV or XLSX).

    Parameters
    ----------
    file_obj : UploadedFile or file-like with .name attribute

    Returns
    -------
    pd.DataFrame with columns:
        POAM_ID, Control_ID, Weakness_Name, Status, POC,
        Resources_Required, Scheduled_Completion, Milestone_Description,
        Milestone_Completion, Mitigation, Severity, Date_Entered

    Date columns are parsed to datetime (NaT on failure).
    Text columns are empty strings where data is missing.
    """
    name = getattr(file_obj, "name", "")
    if name.lower().endswith(".xlsx"):
        raw_df = pd.read_excel(file_obj, engine="openpyxl", dtype=str)
    else:
        content = file_obj.read()
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                raw_df = pd.read_csv(io.StringIO(content.decode(enc)), dtype=str)
                break
            except (UnicodeDecodeError, pd.errors.ParserError):
                continue
        else:
            raise ValueError("Could not decode POA&M CSV file. Try saving as UTF-8.")

    # Strip whitespace from column names
    raw_df.columns = [c.strip() for c in raw_df.columns]

    # Build normalized DataFrame
    result = {}
    for field, aliases in COLUMN_ALIASES.items():
        col = _find_column(raw_df.columns, aliases)
        if col:
            if field in _DATE_COLUMNS:
                result[field] = pd.to_datetime(
                    raw_df[col].str.strip(), errors="coerce"
                )
            else:
                result[field] = raw_df[col].fillna("").astype(str).str.strip()
        else:
            if field in _DATE_COLUMNS:
                result[field] = pd.NaT
            else:
                result[field] = ""

    df = pd.DataFrame(result)

    # Drop entirely empty rows (no POAM_ID and no Control_ID)
    df = df[
        (df["POAM_ID"].str.strip() != "") | (df["Control_ID"].str.strip() != "")
    ].reset_index(drop=True)

    if df.empty:
        df = pd.DataFrame(columns=list(COLUMN_ALIASES.keys()))
        for field in _DATE_COLUMNS:
            df[field] = pd.Series(dtype="datetime64[ns]")

    return df
