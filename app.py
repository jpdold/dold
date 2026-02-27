"""RMF Assessment Dashboard — Main Streamlit Application."""

import datetime
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from config.system_types import SYSTEM_TYPES, SYSTEM_TYPE_OPTIONS
from parsers.ckl_parser import parse_ckl
from parsers.emass_parser import parse_emass
from parsers.inventory_parser import parse_inventory
from analysis.nvd_client import query_nvd, clear_cache
from analysis.cisa_kev import fetch_kev, match_kev
from analysis.risk_engine import compute_cia_scores
from analysis.ato_engine import generate_ato_recommendation
from utils.exporter import export_excel, export_csv

# ──────────────────────────────────────────────────────────────────────────────
# Page config
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="RMF Assessment Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
LEVEL_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f39c12",
    "LOW": "#27ae60",
    "UNKNOWN": "#7f8c8d",
}

LEVEL_BG = {
    "CRITICAL": "#fde8e8",
    "HIGH": "#fef3e2",
    "MEDIUM": "#fefce8",
    "LOW": "#e8f8e8",
    "UNKNOWN": "#f0f0f0",
}


def level_badge(level: str) -> str:
    color = LEVEL_COLORS.get(level, "#7f8c8d")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{level}</span>'


def gauge_chart(value: float, level: str, title: str) -> go.Figure:
    color = LEVEL_COLORS.get(level, "#7f8c8d")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"size": 14}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 20], "color": "#d5f5e3"},
                {"range": [20, 50], "color": "#fef9e7"},
                {"range": [50, 75], "color": "#fdebd0"},
                {"range": [75, 100], "color": "#fadbd8"},
            ],
            "threshold": {
                "line": {"color": "black", "width": 3},
                "thickness": 0.85,
                "value": value,
            },
        },
        number={"suffix": f"  {level}", "font": {"size": 16}},
    ))
    fig.update_layout(height=220, margin=dict(t=40, b=10, l=20, r=20))
    return fig


def compliance_gauge(pct: float) -> go.Figure:
    if pct >= 90:
        color = "#27ae60"
    elif pct >= 80:
        color = "#f39c12"
    elif pct >= 60:
        color = "#e67e22"
    else:
        color = "#c0392b"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=pct,
        title={"text": "eMASS Compliance Rate", "font": {"size": 14}},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 60], "color": "#fadbd8"},
                {"range": [60, 80], "color": "#fdebd0"},
                {"range": [80, 90], "color": "#fef9e7"},
                {"range": [90, 100], "color": "#d5f5e3"},
            ],
        },
        number={"suffix": "%"},
    ))
    fig.update_layout(height=250, margin=dict(t=40, b=10, l=20, r=20))
    return fig


def _run_analysis(
    system_type_key: str,
    system_name: str,
    nvd_api_key: str,
    emass_file,
    inventory_file,
    ckl_file,
    progress_bar,
    status_text,
):
    """Run the full analysis pipeline, storing results in st.session_state."""
    results = {}

    # Step 1: Parse files
    status_text.text("Parsing uploaded files…")
    progress_bar.progress(10)

    ckl_df = pd.DataFrame()
    if ckl_file is not None:
        try:
            ckl_df = parse_ckl(ckl_file.read())
            st.session_state["ckl_df"] = ckl_df
        except Exception as exc:
            st.warning(f"CKL parse error: {exc}")

    emass_df = pd.DataFrame()
    if emass_file is not None:
        try:
            emass_df = parse_emass(emass_file)
            st.session_state["emass_df"] = emass_df
        except Exception as exc:
            st.warning(f"eMASS parse error: {exc}")

    inventory_df = pd.DataFrame()
    if inventory_file is not None:
        try:
            inventory_df = parse_inventory(inventory_file)
            st.session_state["inventory_df"] = inventory_df
        except Exception as exc:
            st.warning(f"Inventory parse error: {exc}")

    progress_bar.progress(30)
    status_text.text("Querying NVD for CVEs…")

    # Step 2: NVD queries per inventory item
    cve_list = []
    if not inventory_df.empty:
        unique_products = inventory_df[["Vendor", "Product"]].drop_duplicates()
        total = len(unique_products)
        for idx, (_, row) in enumerate(unique_products.iterrows()):
            vendor = str(row.get("Vendor", "")).strip()
            product = str(row.get("Product", "")).strip()
            if not vendor and not product:
                continue
            try:
                status_text.text(f"Querying NVD: {vendor} {product} ({idx + 1}/{total})…")
                cves = query_nvd(vendor, product, api_key=nvd_api_key or None)
                cve_list.extend(cves)
            except Exception as exc:
                st.warning(f"NVD query failed for {vendor} {product}: {exc}")
            pct = 30 + int((idx + 1) / max(total, 1) * 30)
            progress_bar.progress(pct)

    st.session_state["cve_list"] = cve_list
    progress_bar.progress(60)
    status_text.text("Fetching CISA KEV feed…")

    # Step 3: CISA KEV
    kev_df = pd.DataFrame()
    try:
        kev_vulns = fetch_kev(st.session_state)
        cve_ids = [c["cve_id"] for c in cve_list]
        kev_df = match_kev(kev_vulns, cve_ids=cve_ids, inventory_df=inventory_df)
        st.session_state["kev_df"] = kev_df
    except Exception as exc:
        st.warning(f"KEV fetch error: {exc}")

    progress_bar.progress(75)
    status_text.text("Computing CIA risk scores…")

    # Step 4: Risk scoring
    risk_scores = compute_cia_scores(
        ckl_df=ckl_df,
        cve_list=cve_list,
        emass_df=emass_df,
        kev_df=kev_df,
        system_type_key=system_type_key,
    )
    st.session_state["risk_scores"] = risk_scores
    progress_bar.progress(90)
    status_text.text("Generating ATO recommendation…")

    # Step 5: ATO recommendation
    ato_result = generate_ato_recommendation(
        risk_scores=risk_scores,
        ckl_df=ckl_df,
        kev_df=kev_df,
        cve_list=cve_list,
        emass_df=emass_df,
    )
    st.session_state["ato_result"] = ato_result
    st.session_state["system_name"] = system_name
    st.session_state["system_type_key"] = system_type_key
    st.session_state["analysis_date"] = datetime.date.today().isoformat()
    st.session_state["analysis_complete"] = True

    progress_bar.progress(100)
    status_text.text("Analysis complete!")


# ──────────────────────────────────────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ RMF Dashboard")
    st.caption("Risk Management Framework Assessment Tool")
    st.divider()
    st.subheader("NVD API Key (optional)")
    nvd_api_key = st.text_input(
        "API Key",
        type="password",
        help="Obtain a free key at https://nvd.nist.gov/developers/request-an-api-key "
             "to increase rate limits (50 req/30s vs 5 req/30s)",
        key="nvd_key_input",
    )
    if nvd_api_key:
        st.session_state["nvd_api_key"] = nvd_api_key
        st.success("API key stored for this session")

    st.divider()
    if st.button("Clear Cache & Reset", use_container_width=True):
        clear_cache()
        for key in ["ckl_df", "emass_df", "inventory_df", "cve_list",
                    "kev_df", "risk_scores", "ato_result", "analysis_complete",
                    "_kev_data"]:
            st.session_state.pop(key, None)
        st.rerun()

    st.divider()
    st.caption("v1.0 | NIST RMF | DISA STIG | NVD CVE 2.0 | CISA KEV")

# ──────────────────────────────────────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "⚙️ Configuration",
    "📦 Inventory & CVEs",
    "🔍 STIG Compliance",
    "📋 eMASS Results",
    "🎯 Risk Dashboard",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Configuration
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.header("System Configuration")

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("System Identity")

        system_name = st.text_input(
            "System Name",
            value=st.session_state.get("system_name", ""),
            placeholder="e.g., NIPRNET-WEB-01",
        )

        type_keys = [k for k, _ in SYSTEM_TYPE_OPTIONS]
        type_labels = [v for _, v in SYSTEM_TYPE_OPTIONS]
        selected_type_idx = st.selectbox(
            "System Type",
            range(len(type_keys)),
            format_func=lambda i: type_labels[i],
            index=type_keys.index(st.session_state.get("system_type_key", "it_general"))
            if st.session_state.get("system_type_key", "it_general") in type_keys else 0,
        )
        system_type_key = type_keys[selected_type_idx]
        sys_config = SYSTEM_TYPES[system_type_key]

        if system_type_key == "custom":
            custom_name = st.text_input("Custom System Type Name", placeholder="e.g., Air-Gapped Lab Network")
            if custom_name:
                system_name = system_name or custom_name

        st.info(f"**{sys_config['label']}**: {sys_config['desc']}\n\n"
                f"CIA Weights → C: {sys_config['C_weight']}× | "
                f"I: {sys_config['I_weight']}× | A: {sys_config['A_weight']}× | "
                f"Criticality Bonus: +{sys_config['criticality_bonus']}")

    with col_right:
        st.subheader("File Uploads")

        ckl_file = st.file_uploader(
            "STIG Checklist (.ckl)",
            type=["ckl", "xml"],
            help="DISA STIG Viewer .ckl XML file",
        )

        inventory_file = st.file_uploader(
            "Hardware/Software Inventory (.csv or .xlsx)",
            type=["csv", "xlsx"],
            help="Asset inventory with columns: Asset Name, Type, Vendor, Product, Version, OS",
        )

        emass_file = st.file_uploader(
            "eMASS Export (.csv or .xlsx)",
            type=["csv", "xlsx"],
            help="eMASS controls export with compliance status columns",
        )

    st.divider()

    run_col, _ = st.columns([1, 3])
    with run_col:
        run_btn = st.button("▶ Run Analysis", type="primary", use_container_width=True)

    if run_btn:
        if not system_name.strip():
            st.error("Please enter a system name before running analysis.")
        elif not any([ckl_file, inventory_file, emass_file]):
            st.warning("Upload at least one file to analyze.")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            with st.spinner("Running RMF analysis…"):
                try:
                    _run_analysis(
                        system_type_key=system_type_key,
                        system_name=system_name.strip(),
                        nvd_api_key=st.session_state.get("nvd_api_key", ""),
                        emass_file=emass_file,
                        inventory_file=inventory_file,
                        ckl_file=ckl_file,
                        progress_bar=progress_bar,
                        status_text=status_text,
                    )
                    st.success("Analysis complete! Navigate to the Risk Dashboard tab for results.")
                except Exception as exc:
                    st.error(f"Analysis failed: {exc}")
                    raise

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Inventory & Vulnerabilities
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.header("Inventory & Vulnerability Analysis")

    if not st.session_state.get("analysis_complete"):
        st.info("Run an analysis in the Configuration tab to see results.")
        st.stop()

    inventory_df = st.session_state.get("inventory_df", pd.DataFrame())
    cve_list = st.session_state.get("cve_list", [])

    # Summary metrics
    total_assets = len(inventory_df) if not inventory_df.empty else 0
    total_cves = len(cve_list)
    crit_cves = len([c for c in cve_list if (c.get("cvss_v3_score") or 0) >= 9.0])
    high_cves = len([c for c in cve_list if 7.0 <= (c.get("cvss_v3_score") or 0) < 9.0])
    med_cves = len([c for c in cve_list if 4.0 <= (c.get("cvss_v3_score") or 0) < 7.0])
    low_cves = len([c for c in cve_list if 0 < (c.get("cvss_v3_score") or 0) < 4.0])

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Assets", total_assets)
    m2.metric("Total CVEs", total_cves)
    m3.metric("Critical (≥9.0)", crit_cves, delta=None)
    m4.metric("High (7-8.9)", high_cves)
    m5.metric("Medium (4-6.9)", med_cves)
    m6.metric("Low (<4)", low_cves)

    st.divider()

    col_inv, col_chart = st.columns([2, 1])

    with col_inv:
        st.subheader("Asset Inventory")
        if not inventory_df.empty:
            type_filter = st.multiselect(
                "Filter by Type",
                options=inventory_df["Type"].unique().tolist(),
                default=inventory_df["Type"].unique().tolist(),
            )
            filtered_inv = inventory_df[inventory_df["Type"].isin(type_filter)]
            st.dataframe(filtered_inv, use_container_width=True, height=300)
        else:
            st.info("No inventory data available. Upload an inventory file.")

    with col_chart:
        st.subheader("CVE Severity Distribution")
        if total_cves > 0:
            sev_counts = {"Critical": crit_cves, "High": high_cves,
                          "Medium": med_cves, "Low": low_cves}
            sev_counts = {k: v for k, v in sev_counts.items() if v > 0}
            fig_pie = px.pie(
                names=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                color=list(sev_counts.keys()),
                color_discrete_map={
                    "Critical": "#c0392b", "High": "#e67e22",
                    "Medium": "#f39c12", "Low": "#27ae60",
                },
            )
            fig_pie.update_layout(height=300, margin=dict(t=10, b=10, l=0, r=0))
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No CVE data to chart.")

    # CVE table with expandable rows
    if cve_list:
        st.subheader("CVE Details")

        # Group by asset
        cve_df = pd.DataFrame(cve_list)
        if not inventory_df.empty:
            unique_pairs = cve_df[["vendor", "product"]].drop_duplicates()
            for _, row in unique_pairs.iterrows():
                vendor = row["vendor"]
                product = row["product"]
                asset_cves = cve_df[
                    (cve_df["vendor"] == vendor) & (cve_df["product"] == product)
                ]
                with st.expander(f"{vendor} {product} — {len(asset_cves)} CVE(s)"):
                    display_cols = ["cve_id", "cvss_v3_score", "cvss_v3_severity",
                                    "published_date", "description"]
                    show_df = asset_cves[display_cols].copy()
                    show_df["description"] = show_df["description"].str[:200]
                    st.dataframe(show_df, use_container_width=True)
        else:
            display_df = cve_df[["cve_id", "vendor", "product", "cvss_v3_score",
                                  "cvss_v3_severity", "published_date"]].copy()
            st.dataframe(display_df, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — STIG Compliance
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.header("STIG Compliance Results")

    if not st.session_state.get("analysis_complete"):
        st.info("Run an analysis in the Configuration tab to see results.")
        st.stop()

    ckl_df = st.session_state.get("ckl_df", pd.DataFrame())

    if ckl_df.empty:
        st.info("No STIG checklist data. Upload a .ckl file in Configuration.")
        st.stop()

    # Summary cards
    total = len(ckl_df)
    open_f = len(ckl_df[ckl_df["Status"] == "Open"])
    naf = len(ckl_df[ckl_df["Status"] == "NotAFinding"])
    na = len(ckl_df[ckl_df["Status"] == "Not_Applicable"])
    nr = len(ckl_df[ckl_df["Status"] == "Not_Reviewed"])

    open_cat1 = len(ckl_df[(ckl_df["Status"] == "Open") & (ckl_df["CAT"] == "CAT I")])
    open_cat2 = len(ckl_df[(ckl_df["Status"] == "Open") & (ckl_df["CAT"] == "CAT II")])
    open_cat3 = len(ckl_df[(ckl_df["Status"] == "Open") & (ckl_df["CAT"] == "CAT III")])

    c1, c2, c3, c4, c5, c6, c7, c8 = st.columns(8)
    c1.metric("Total Checks", total)
    c2.metric("Open", open_f, delta=f"CAT I: {open_cat1}")
    c3.metric("CAT I Open", open_cat1)
    c4.metric("CAT II Open", open_cat2)
    c5.metric("CAT III Open", open_cat3)
    c6.metric("Not a Finding", naf)
    c7.metric("Not Applicable", na)
    c8.metric("Not Reviewed", nr)

    st.divider()

    col_bar, col_donut = st.columns(2)

    with col_bar:
        st.subheader("Findings by Category")
        cat_data = ckl_df[ckl_df["Status"] == "Open"]["CAT"].value_counts().reset_index()
        cat_data.columns = ["Category", "Count"]
        if not cat_data.empty:
            fig_bar = px.bar(
                cat_data,
                x="Category",
                y="Count",
                color="Category",
                color_discrete_map={
                    "CAT I": "#c0392b",
                    "CAT II": "#e67e22",
                    "CAT III": "#f39c12",
                    "Unknown": "#7f8c8d",
                },
                text="Count",
            )
            fig_bar.update_layout(height=300, showlegend=False,
                                   margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.success("No open findings!")

    with col_donut:
        st.subheader("Compliance Ratio")
        status_counts = ckl_df["Status_Label"].value_counts()
        fig_donut = go.Figure(go.Pie(
            labels=status_counts.index.tolist(),
            values=status_counts.values.tolist(),
            hole=0.5,
            marker_colors=["#c0392b", "#27ae60", "#7f8c8d", "#bdc3c7"],
        ))
        fig_donut.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig_donut, use_container_width=True)

    st.divider()
    st.subheader("Findings Table")

    filter_status = st.multiselect(
        "Filter by Status",
        options=ckl_df["Status_Label"].unique().tolist(),
        default=["Open"],
    )
    filter_cat = st.multiselect(
        "Filter by Category",
        options=ckl_df["CAT"].unique().tolist(),
        default=ckl_df["CAT"].unique().tolist(),
    )

    filtered_ckl = ckl_df[
        ckl_df["Status_Label"].isin(filter_status) &
        ckl_df["CAT"].isin(filter_cat)
    ]

    display_cols = ["Vuln_Num", "CAT", "Severity", "Status_Label", "Rule_Title"]
    st.dataframe(
        filtered_ckl[display_cols].rename(columns={"Status_Label": "Status"}),
        use_container_width=True,
        height=400,
    )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — eMASS Results
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.header("eMASS Compliance Results")

    if not st.session_state.get("analysis_complete"):
        st.info("Run an analysis in the Configuration tab to see results.")
        st.stop()

    emass_df = st.session_state.get("emass_df", pd.DataFrame())
    risk_scores = st.session_state.get("risk_scores", {})

    if emass_df.empty:
        st.info("No eMASS data. Upload an eMASS export file in Configuration.")
        st.stop()

    compliance_pct = risk_scores.get("emass_compliance_pct", 100.0)

    col_gauge, col_stats = st.columns([1, 2])

    with col_gauge:
        st.plotly_chart(compliance_gauge(compliance_pct), use_container_width=True)

    with col_stats:
        st.subheader("Compliance Summary")
        total_controls = len(emass_df)
        compliant = len(emass_df[emass_df["Status"] == "Compliant"])
        non_compliant = len(emass_df[emass_df["Status"] == "NonCompliant"])
        na_count = len(emass_df[emass_df["Status"] == "NA"])
        nr_count = len(emass_df[emass_df["Status"] == "NR"])

        mc1, mc2, mc3, mc4, mc5 = st.columns(5)
        mc1.metric("Total Controls", total_controls)
        mc2.metric("Compliant", compliant)
        mc3.metric("Non-Compliant", non_compliant)
        mc4.metric("Not Applicable", na_count)
        mc5.metric("Not Reviewed", nr_count)

        # Status bar chart
        status_data = pd.DataFrame({
            "Status": ["Compliant", "NonCompliant", "NA", "NR"],
            "Count": [compliant, non_compliant, na_count, nr_count],
        })
        fig_status = px.bar(
            status_data, x="Status", y="Count",
            color="Status",
            color_discrete_map={
                "Compliant": "#27ae60",
                "NonCompliant": "#c0392b",
                "NA": "#7f8c8d",
                "NR": "#bdc3c7",
            },
            text="Count",
        )
        fig_status.update_layout(height=200, showlegend=False,
                                  margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig_status, use_container_width=True)

    st.divider()

    # Control family breakdown
    st.subheader("Control Family Breakdown")

    def extract_family(control_id):
        if not control_id:
            return "Unknown"
        parts = str(control_id).strip().upper().split("-")
        return parts[0] if parts else "Unknown"

    emass_df["Family"] = emass_df["Control_ID"].apply(extract_family)
    family_stats = emass_df.groupby("Family")["Status"].apply(
        lambda x: (x == "NonCompliant").sum()
    ).reset_index()
    family_stats.columns = ["Family", "NonCompliant_Count"]
    family_stats = family_stats[family_stats["NonCompliant_Count"] > 0].sort_values(
        "NonCompliant_Count", ascending=True
    )

    if not family_stats.empty:
        fig_family = px.bar(
            family_stats,
            x="NonCompliant_Count",
            y="Family",
            orientation="h",
            color="NonCompliant_Count",
            color_continuous_scale=["#f39c12", "#c0392b"],
            text="NonCompliant_Count",
        )
        fig_family.update_layout(
            height=max(300, len(family_stats) * 25),
            coloraxis_showscale=False,
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="Non-Compliant Controls",
            yaxis_title="Control Family",
        )
        st.plotly_chart(fig_family, use_container_width=True)
    else:
        st.success("All controls compliant — no family-level deficiencies detected.")

    st.divider()
    st.subheader("Non-Compliant Controls")

    nc_df = emass_df[emass_df["Status"] == "NonCompliant"][
        ["Control_ID", "Control_Name", "Status", "Test_Result", "Findings", "Test_Date"]
    ]
    if not nc_df.empty:
        st.dataframe(nc_df, use_container_width=True, height=350)
    else:
        st.success("No non-compliant controls found.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — Risk Dashboard
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.header("Risk Dashboard")

    if not st.session_state.get("analysis_complete"):
        st.info("Run an analysis in the Configuration tab to see results.")
        st.stop()

    risk_scores = st.session_state.get("risk_scores", {})
    ato_result = st.session_state.get("ato_result", {})
    system_name = st.session_state.get("system_name", "Unknown System")
    system_type_key = st.session_state.get("system_type_key", "it_general")
    analysis_date = st.session_state.get("analysis_date", "")
    sys_label = SYSTEM_TYPES.get(system_type_key, {}).get("label", "Unknown")

    # System info header
    st.markdown(
        f"""
        <div style="background:#1a3a5c;color:white;padding:16px;border-radius:8px;margin-bottom:16px">
            <h3 style="margin:0">{system_name}</h3>
            <p style="margin:4px 0 0 0;opacity:0.8">Type: {sys_label} &nbsp;|&nbsp; Analysis Date: {analysis_date}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # CIA Gauge charts
    st.subheader("CIA Risk Dimensions")
    g1, g2, g3 = st.columns(3)

    with g1:
        c_score = risk_scores.get("C", {}).get("score", 0)
        c_level = risk_scores.get("C", {}).get("level", "UNKNOWN")
        st.plotly_chart(gauge_chart(c_score, c_level, "Confidentiality"), use_container_width=True)

    with g2:
        i_score = risk_scores.get("I", {}).get("score", 0)
        i_level = risk_scores.get("I", {}).get("level", "UNKNOWN")
        st.plotly_chart(gauge_chart(i_score, i_level, "Integrity"), use_container_width=True)

    with g3:
        a_score = risk_scores.get("A", {}).get("score", 0)
        a_level = risk_scores.get("A", {}).get("level", "UNKNOWN")
        st.plotly_chart(gauge_chart(a_score, a_level, "Availability"), use_container_width=True)

    # Overall score card
    overall = risk_scores.get("overall_score", 0)
    overall_level = risk_scores.get("overall_level", "UNKNOWN")
    overall_color = LEVEL_COLORS.get(overall_level, "#7f8c8d")
    overall_bg = LEVEL_BG.get(overall_level, "#f0f0f0")

    st.markdown(
        f"""
        <div style="background:{overall_bg};border-left:6px solid {overall_color};
                    padding:16px;border-radius:4px;margin:16px 0">
            <h3 style="margin:0;color:{overall_color}">Overall Risk Score: {overall}/100
                &nbsp; — &nbsp; {overall_level}</h3>
            <p style="margin:4px 0 0;font-size:13px">
                Open Findings: CAT I: {risk_scores.get('open_cat1',0)} |
                CAT II: {risk_scores.get('open_cat2',0)} |
                CAT III: {risk_scores.get('open_cat3',0)} &nbsp;&nbsp;
                eMASS Compliance: {risk_scores.get('emass_compliance_pct',100):.1f}% &nbsp;&nbsp;
                KEV Matches: {risk_scores.get('kev_count',0)}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    # ATO Recommendation banner
    recommendation = ato_result.get("recommendation", "Unknown")
    ato_color = ato_result.get("color", "#7f8c8d")
    ato_reasons = ato_result.get("reasons", [])

    ato_bg_map = {
        "#c0392b": "#fde8e8",
        "#e67e22": "#fef3e2",
        "#f39c12": "#fefce8",
        "#27ae60": "#e8f8e8",
    }
    ato_bg = ato_bg_map.get(ato_color, "#f5f5f5")

    reasons_html = "".join(f"<li>{r}</li>" for r in ato_reasons)
    st.markdown(
        f"""
        <div style="background:{ato_bg};border:3px solid {ato_color};
                    padding:20px;border-radius:8px;margin:16px 0">
            <h2 style="margin:0;color:{ato_color}">
                ATO Recommendation: {recommendation}
            </h2>
            <ul style="margin-top:12px;color:#333">
                {reasons_html}
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    # High-risk mitigations
    st.subheader("High-Risk Mitigations")

    kev_mits = ato_result.get("kev_mitigations", [])
    cve_mits = ato_result.get("cve_mitigations", [])
    stig_mits = ato_result.get("stig_mitigations", [])

    if not (kev_mits or cve_mits or stig_mits):
        st.success("No high-priority mitigations required.")
    else:
        if kev_mits:
            st.markdown("#### CISA Known Exploited Vulnerabilities (KEV)")
            for m in kev_mits:
                ransomware_flag = "⚠️ RANSOMWARE" if m.get("ransomware", "").lower() == "known" else ""
                with st.expander(f"🔴 {m['cve_id']} — {m['title']} {ransomware_flag}"):
                    col_a, col_b = st.columns(2)
                    col_a.write(f"**Vendor/Product:** {m.get('vendor','')} / {m.get('product','')}")
                    col_a.write(f"**Date Added to KEV:** {m.get('date_added','')}")
                    col_b.write(f"**Ransomware Use:** {m.get('ransomware','Unknown')}")
                    st.write(f"**Description:** {m.get('description','')}")
                    st.error(f"**Required Action:** {m.get('required_action','Follow CISA guidance')}")

        if cve_mits:
            st.markdown("#### Critical/High CVEs")
            for m in cve_mits:
                sev = m.get("severity", "")
                score = m.get("cvss_score", 0)
                icon = "🔴" if score >= 9 else "🟠"
                with st.expander(f"{icon} {m['title']} (CVSS {score} — {sev})"):
                    st.write(f"**Asset:** {m.get('vendor','')} {m.get('product','')}")
                    st.write(f"**Description:** {m.get('description','')}")
                    st.subheader("Recommended Actions")
                    for action in m.get("actions", []):
                        st.write(f"• {action}")
                    if m.get("references"):
                        st.write("**References:**")
                        for ref in m["references"]:
                            st.write(f"- {ref}")

        if stig_mits:
            st.markdown("#### Open STIG Findings")
            for m in stig_mits:
                cat = m.get("severity", "")
                icon = "🔴" if cat == "CAT I" else ("🟠" if cat == "CAT II" else "🟡")
                with st.expander(f"{icon} [{cat}] {m.get('vuln_id','')} — {m.get('title','')[:80]}"):
                    if m.get("finding_details"):
                        st.write(f"**Finding Details:** {m['finding_details'][:300]}")
                    st.write("**NIST 800-53 Controls:**")
                    for ctrl in m.get("nist_controls", []):
                        st.write(f"• {ctrl}")
                    st.write("**Compensating Controls:**")
                    for cc in m.get("compensating_controls", []):
                        st.write(f"• {cc}")

    st.divider()

    # KEV matches table
    kev_df = st.session_state.get("kev_df", pd.DataFrame())
    st.subheader("Known Exploited Vulnerabilities — Matched to System")

    if kev_df is not None and not kev_df.empty:
        display_kev = kev_df[[
            "cve_id", "vendorProject", "product", "vulnerabilityName",
            "dateAdded", "knownRansomwareCampaignUse", "requiredAction", "matched_by",
        ]].copy()
        display_kev.columns = [
            "CVE ID", "Vendor", "Product", "Vulnerability Name",
            "Date Added", "Ransomware Campaign", "Required Action", "Matched By",
        ]
        st.dataframe(display_kev, use_container_width=True)
    else:
        st.success("No CISA KEV matches found for this system's inventory and CVEs.")

    st.divider()

    # Export buttons
    st.subheader("Export Results")
    exp_col1, exp_col2, _ = st.columns([1, 1, 3])

    system_name_dl = st.session_state.get("system_name", "system")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in system_name_dl)

    with exp_col1:
        try:
            excel_bytes = export_excel(
                system_name=system_name_dl,
                system_type=sys_label,
                risk_scores=risk_scores,
                ato_result=ato_result,
                ckl_df=st.session_state.get("ckl_df"),
                cve_list=st.session_state.get("cve_list", []),
                kev_df=st.session_state.get("kev_df"),
                emass_df=st.session_state.get("emass_df"),
                inventory_df=st.session_state.get("inventory_df"),
            )
            st.download_button(
                label="📥 Download Excel Report",
                data=excel_bytes,
                file_name=f"rmf_assessment_{safe_name}_{analysis_date}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )
        except Exception as exc:
            st.error(f"Excel export error: {exc}")

    with exp_col2:
        try:
            csv_bytes = export_csv(
                risk_scores=risk_scores,
                ato_result=ato_result,
                ckl_df=st.session_state.get("ckl_df"),
                cve_list=st.session_state.get("cve_list", []),
                kev_df=st.session_state.get("kev_df"),
                emass_df=st.session_state.get("emass_df"),
            )
            st.download_button(
                label="📄 Download CSV Findings",
                data=csv_bytes,
                file_name=f"rmf_findings_{safe_name}_{analysis_date}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        except Exception as exc:
            st.error(f"CSV export error: {exc}")
