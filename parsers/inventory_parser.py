"""Hardware/Software inventory parser — normalizes CSV/XLSX inventory exports."""

import io
import pandas as pd


COLUMN_ALIASES = {
    "Asset_Name": [
        "Asset Name", "asset_name", "ASSET_NAME", "Hostname", "hostname",
        "Device Name", "System Name", "Name", "name", "Asset",
    ],
    "Type": [
        "Type", "type", "TYPE", "Asset Type", "Category", "category",
        "HW/SW", "Hardware/Software", "Device Type",
    ],
    "Vendor": [
        "Vendor", "vendor", "VENDOR", "Manufacturer", "manufacturer",
        "Make", "Company", "Publisher",
    ],
    "Product": [
        "Product", "product", "PRODUCT", "Product Name", "Software Name",
        "Application", "Model", "Description",
    ],
    "Version": [
        "Version", "version", "VERSION", "Software Version", "OS Version",
        "Firmware Version", "Build", "Release",
    ],
    "OS": [
        "OS", "os", "Operating System", "operating_system", "OS Name",
        "Platform", "OS/Platform",
    ],
    "IP_Address": [
        "IP Address", "ip_address", "IP_Address", "IP", "IPv4",
        "IPv4 Address", "Network Address",
    ],
}

TYPE_NORMALIZE = {
    "hardware": "Hardware",
    "hw": "Hardware",
    "h/w": "Hardware",
    "device": "Hardware",
    "appliance": "Hardware",
    "software": "Software",
    "sw": "Software",
    "s/w": "Software",
    "application": "Software",
    "app": "Software",
}


def _find_column(df_columns, aliases):
    col_lower = {c.lower(): c for c in df_columns}
    for alias in aliases:
        if alias in df_columns:
            return alias
        if alias.lower() in col_lower:
            return col_lower[alias.lower()]
    return None


def _normalize_type(value):
    if pd.isna(value):
        return "Unknown"
    normalized = str(value).strip().lower()
    return TYPE_NORMALIZE.get(normalized, str(value).strip().capitalize())


def parse_inventory(file_obj) -> pd.DataFrame:
    """
    Parse a hardware/software inventory file (CSV or XLSX).

    Parameters
    ----------
    file_obj : UploadedFile or file-like with .name attribute

    Returns
    -------
    pd.DataFrame with columns:
        Asset_Name, Type, Vendor, Product, Version, OS, IP_Address
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
            raise ValueError("Could not decode inventory CSV. Try saving as UTF-8.")

    raw_df.columns = [c.strip() for c in raw_df.columns]

    result = {}
    for field, aliases in COLUMN_ALIASES.items():
        col = _find_column(raw_df.columns, aliases)
        if col:
            result[field] = raw_df[col].fillna("").astype(str).str.strip()
        else:
            result[field] = ""

    df = pd.DataFrame(result)

    # Normalize Type column
    df["Type"] = df["Type"].apply(_normalize_type)

    # Drop rows with no asset name and no vendor+product
    mask = (df["Asset_Name"].str.strip() != "") | (
        (df["Vendor"].str.strip() != "") & (df["Product"].str.strip() != "")
    )
    df = df[mask].reset_index(drop=True)

    if df.empty:
        df = pd.DataFrame(
            columns=["Asset_Name", "Type", "Vendor", "Product", "Version", "OS", "IP_Address"]
        )
    return df
