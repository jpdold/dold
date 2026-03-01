"""RMF Assessment Dashboard — DOS-Style Textual TUI."""

from __future__ import annotations

import datetime
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from config.system_types import SYSTEM_TYPES, SYSTEM_TYPE_OPTIONS

# ──────────────────────────────────────────────────────────────────────────────
# DOS Aesthetic — TCSS
# ──────────────────────────────────────────────────────────────────────────────

DOS_CSS = """
Screen {
    background: #0000AA;
    color: white;
}

Header {
    background: #000080;
    color: ansi_bright_white;
    text-style: bold;
}

Footer {
    background: #000080;
    color: ansi_bright_white;
}

TabbedContent {
    background: #0000AA;
}

TabbedContent > TabPane {
    background: #0000AA;
    padding: 1 2;
}

Tabs {
    background: #000080;
}

Tab {
    background: #000080;
    color: white;
    text-style: bold;
}

Tab:focus, Tab.-active {
    background: #AAAAAA;
    color: #000000;
    text-style: bold;
}

Button {
    background: #AAAAAA;
    color: #000000;
    text-style: bold;
    border: none;
}

Button:hover, Button:focus {
    background: white;
    color: #000000;
}

Input {
    background: #000066;
    color: white;
    border: solid #AAAAAA;
}

Select {
    background: #000066;
    color: white;
    border: solid #AAAAAA;
}

SelectOverlay {
    background: #000066;
    color: white;
    border: solid #AAAAAA;
}

ProgressBar {
    color: ansi_bright_white;
}

ProgressBar > .bar--bar {
    color: ansi_bright_white;
    background: #000066;
}

ProgressBar > .bar--complete {
    color: ansi_bright_green;
}

DataTable {
    background: #000066;
    color: white;
}

DataTable > .datatable--header {
    background: #000080;
    color: ansi_bright_white;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #AAAAAA;
    color: #000000;
}

DataTable > .datatable--even-row {
    background: #000066;
}

DataTable > .datatable--odd-row {
    background: #000080;
}

.metric-strip {
    height: 3;
    margin-bottom: 1;
}

.metric-box {
    background: #000080;
    color: ansi_bright_white;
    border: panel #AAAAAA;
    padding: 0 1;
    text-align: center;
    height: 3;
    width: 1fr;
}

.section-label {
    color: ansi_bright_white;
    text-style: bold;
    background: #000080;
    padding: 0 1;
    margin-bottom: 1;
}

.status-ok {
    color: ansi_bright_green;
    text-style: bold;
}

.status-warn {
    color: ansi_yellow;
    text-style: bold;
}

.status-error {
    color: ansi_bright_red;
    text-style: bold;
}

.status-info {
    color: ansi_bright_cyan;
}

.ascii-chart {
    color: ansi_bright_cyan;
    background: #000066;
    border: panel #AAAAAA;
    padding: 1;
    margin: 1 0;
}

.config-field {
    margin-bottom: 1;
}

.config-label {
    color: ansi_bright_yellow;
    text-style: bold;
    width: 24;
}

.ato-banner {
    border: heavy white;
    padding: 1 2;
    margin: 1 0;
    text-style: bold;
}

.ato-ato {
    background: #006600;
    color: ansi_bright_green;
}

.ato-iato {
    background: #666600;
    color: ansi_yellow;
}

.ato-ato-c {
    background: #660066;
    color: ansi_bright_magenta;
}

.ato-deny {
    background: #660000;
    color: ansi_bright_red;
}

.gauge-panel {
    width: 1fr;
    border: panel #AAAAAA;
    padding: 1;
    margin: 0 1;
    background: #000080;
}

.panel-title {
    color: ansi_bright_yellow;
    text-style: bold;
    text-align: center;
}

ScrollableContainer {
    background: #0000AA;
}

Vertical {
    background: #0000AA;
}

Horizontal {
    background: #0000AA;
}

Container {
    background: #0000AA;
}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def ascii_gauge(score: float, width: int = 20) -> str:
    score = max(0.0, min(100.0, float(score)))
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def risk_label(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def compliance_label(pct: float) -> str:
    if pct >= 90:
        return "COMPLIANT"
    if pct >= 80:
        return "MARGINAL"
    if pct >= 60:
        return "DEFICIENT"
    return "NON-COMPLIANT"


def health_label(score: float) -> str:
    if score >= 80:
        return "GOOD"
    if score >= 60:
        return "ACCEPTABLE"
    if score >= 40:
        return "DEFICIENT"
    return "SEVERELY DEFICIENT"


def safe_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


# ──────────────────────────────────────────────────────────────────────────────
# Messages
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalysisProgress(Message):
    pct: int
    status: str


@dataclass
class AnalysisComplete(Message):
    results: dict[str, Any]


@dataclass
class AnalysisError(Message):
    error: str


# ──────────────────────────────────────────────────────────────────────────────
# Config Screen
# ──────────────────────────────────────────────────────────────────────────────

class ConfigScreen(ScrollableContainer):
    """Configuration panel — collects inputs and launches analysis."""

    def compose(self) -> ComposeResult:
        yield Label(" SYSTEM CONFIGURATION ", classes="section-label")

        with Horizontal(classes="config-field"):
            yield Label("System Name:", classes="config-label")
            yield Input(placeholder="e.g. NIPRNET-WEB-01", id="sys_name")

        with Horizontal(classes="config-field"):
            yield Label("System Type:", classes="config-label")
            opts = [(label, key) for key, label in SYSTEM_TYPE_OPTIONS]
            yield Select(opts, id="sys_type", value=SYSTEM_TYPE_OPTIONS[4][0])

        yield Label(" FILE PATHS ", classes="section-label")

        with Horizontal(classes="config-field"):
            yield Label("CKL File (.ckl/.xml):", classes="config-label")
            yield Input(placeholder="C:\\path\\to\\checklist.ckl", id="ckl_path")

        with Horizontal(classes="config-field"):
            yield Label("Inventory (.csv/.xlsx):", classes="config-label")
            yield Input(placeholder="C:\\path\\to\\inventory.csv", id="inv_path")

        with Horizontal(classes="config-field"):
            yield Label("eMASS Export (.csv/.xlsx):", classes="config-label")
            yield Input(placeholder="C:\\path\\to\\emass_export.csv", id="emass_path")

        with Horizontal(classes="config-field"):
            yield Label("POA&M Export (.csv/.xlsx):", classes="config-label")
            yield Input(placeholder="C:\\path\\to\\poam.csv", id="poam_path")

        yield Label(" NVD API ", classes="section-label")

        with Horizontal(classes="config-field"):
            yield Label("NVD API Key (optional):", classes="config-label")
            yield Input(placeholder="(leave blank for 5 req/30s)", id="nvd_key", password=True)

        yield Label("", id="sys_info", classes="status-info")

        yield Button("▶ RUN ANALYSIS", id="run_btn", variant="default")
        yield Label("", id="run_status")
        yield ProgressBar(total=100, show_eta=False, id="run_progress")

    def on_mount(self) -> None:
        self._update_sys_info()

    def on_select_changed(self, event: Select.Changed) -> None:
        self._update_sys_info()

    def _update_sys_info(self) -> None:
        try:
            sel = self.query_one("#sys_type", Select)
            key = sel.value
            if key and key != Select.BLANK:
                cfg = SYSTEM_TYPES.get(str(key), {})
                info = (
                    f"[{cfg.get('label','')}] {cfg.get('desc','')}\n"
                    f"Weights → C:{cfg.get('C_weight',1)}x  "
                    f"I:{cfg.get('I_weight',1)}x  "
                    f"A:{cfg.get('A_weight',1)}x  "
                    f"Criticality Bonus: +{cfg.get('criticality_bonus',0)}"
                )
                self.query_one("#sys_info", Label).update(info)
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run_btn":
            self.app.run_analysis()


# ──────────────────────────────────────────────────────────────────────────────
# Inventory Screen
# ──────────────────────────────────────────────────────────────────────────────

class InventoryScreen(ScrollableContainer):
    """Inventory & CVE analysis panel."""

    def compose(self) -> ComposeResult:
        yield Label(" INVENTORY & VULNERABILITY ANALYSIS ", classes="section-label")

        with Horizontal(classes="metric-strip"):
            yield Label("Total Assets: --", id="inv_assets", classes="metric-box")
            yield Label("Total CVEs: --", id="inv_cves", classes="metric-box")
            yield Label("Critical: --", id="inv_crit", classes="metric-box")
            yield Label("High: --", id="inv_high", classes="metric-box")
            yield Label("Medium: --", id="inv_med", classes="metric-box")
            yield Label("Low: --", id="inv_low", classes="metric-box")

        yield Label(" ASSET INVENTORY TABLE ", classes="section-label")
        tbl = DataTable(id="inv_table", zebra_stripes=True, show_cursor=True)
        tbl.add_columns("Asset Name", "Type", "Vendor", "Product", "Version", "OS")
        yield tbl

        yield Label(" CVE SEVERITY DISTRIBUTION ", classes="section-label")
        yield Static("(Run analysis to populate)", id="inv_chart", classes="ascii-chart")

        yield Label(" CVE DETAILS TABLE ", classes="section-label")
        cve_tbl = DataTable(id="cve_table", zebra_stripes=True, show_cursor=True)
        cve_tbl.add_columns("CVE ID", "Vendor", "Product", "CVSS v3", "Severity", "Published")
        yield cve_tbl

    def refresh_data(self, results: dict) -> None:
        inventory_df: pd.DataFrame = results.get("inventory_df", pd.DataFrame())
        cve_list: list = results.get("cve_list", [])

        total_assets = len(inventory_df) if not inventory_df.empty else 0
        total_cves = len(cve_list)
        crit = sum(1 for c in cve_list if (c.get("cvss_v3_score") or 0) >= 9.0)
        high = sum(1 for c in cve_list if 7.0 <= (c.get("cvss_v3_score") or 0) < 9.0)
        med = sum(1 for c in cve_list if 4.0 <= (c.get("cvss_v3_score") or 0) < 7.0)
        low = sum(1 for c in cve_list if 0 < (c.get("cvss_v3_score") or 0) < 4.0)

        self.query_one("#inv_assets", Label).update(f"Total Assets: {total_assets}")
        self.query_one("#inv_cves", Label).update(f"Total CVEs: {total_cves}")
        self.query_one("#inv_crit", Label).update(f"Critical: {crit}")
        self.query_one("#inv_high", Label).update(f"High: {high}")
        self.query_one("#inv_med", Label).update(f"Medium: {med}")
        self.query_one("#inv_low", Label).update(f"Low: {low}")

        tbl = self.query_one("#inv_table", DataTable)
        tbl.clear()
        if not inventory_df.empty:
            for _, row in inventory_df.iterrows():
                tbl.add_row(
                    str(row.get("Asset_Name", row.get("Asset Name", ""))),
                    str(row.get("Type", "")),
                    str(row.get("Vendor", "")),
                    str(row.get("Product", "")),
                    str(row.get("Version", "")),
                    str(row.get("OS", "")),
                )

        # ASCII chart
        max_count = max(crit, high, med, low, 1)
        bar_w = 20

        def bar(n):
            return "█" * int(n / max_count * bar_w) + "░" * (bar_w - int(n / max_count * bar_w))

        chart = (
            f"CRITICAL [{bar(crit):20s}] {crit}\n"
            f"HIGH     [{bar(high):20s}] {high}\n"
            f"MEDIUM   [{bar(med):20s}] {med}\n"
            f"LOW      [{bar(low):20s}] {low}"
        )
        self.query_one("#inv_chart", Static).update(chart)

        cve_tbl = self.query_one("#cve_table", DataTable)
        cve_tbl.clear()
        for c in cve_list[:500]:
            cve_tbl.add_row(
                str(c.get("cve_id", "")),
                str(c.get("vendor", "")),
                str(c.get("product", "")),
                str(c.get("cvss_v3_score", "")),
                str(c.get("cvss_v3_severity", "")),
                str(c.get("published_date", ""))[:10],
            )


# ──────────────────────────────────────────────────────────────────────────────
# STIG Screen
# ──────────────────────────────────────────────────────────────────────────────

class StigScreen(ScrollableContainer):
    """STIG Compliance panel."""

    def compose(self) -> ComposeResult:
        yield Label(" STIG COMPLIANCE RESULTS ", classes="section-label")

        with Horizontal(classes="metric-strip"):
            yield Label("Total: --", id="stig_total", classes="metric-box")
            yield Label("Open: --", id="stig_open", classes="metric-box")
            yield Label("CAT I: --", id="stig_cat1", classes="metric-box")
            yield Label("CAT II: --", id="stig_cat2", classes="metric-box")
            yield Label("CAT III: --", id="stig_cat3", classes="metric-box")
            yield Label("Not a Finding: --", id="stig_naf", classes="metric-box")
            yield Label("Not Applicable: --", id="stig_na", classes="metric-box")
            yield Label("Not Reviewed: --", id="stig_nr", classes="metric-box")

        yield Static("(Run analysis to populate)", id="stig_chart", classes="ascii-chart")

        yield Label(" FINDINGS TABLE ", classes="section-label")
        tbl = DataTable(id="stig_table", zebra_stripes=True, show_cursor=True)
        tbl.add_columns("Vuln ID", "CAT", "Severity", "Status", "Rule Title")
        yield tbl

    def refresh_data(self, results: dict) -> None:
        ckl_df: pd.DataFrame = results.get("ckl_df", pd.DataFrame())
        if ckl_df.empty:
            self.query_one("#stig_total", Label).update("Total: N/A")
            return

        total = len(ckl_df)
        open_f = len(ckl_df[ckl_df["Status"] == "Open"])
        naf = len(ckl_df[ckl_df["Status"] == "NotAFinding"])
        na = len(ckl_df[ckl_df["Status"] == "Not_Applicable"])
        nr = len(ckl_df[ckl_df["Status"] == "Not_Reviewed"])
        cat1 = len(ckl_df[(ckl_df["Status"] == "Open") & (ckl_df["CAT"] == "CAT I")])
        cat2 = len(ckl_df[(ckl_df["Status"] == "Open") & (ckl_df["CAT"] == "CAT II")])
        cat3 = len(ckl_df[(ckl_df["Status"] == "Open") & (ckl_df["CAT"] == "CAT III")])

        self.query_one("#stig_total", Label).update(f"Total: {total}")
        self.query_one("#stig_open", Label).update(f"Open: {open_f}")
        self.query_one("#stig_cat1", Label).update(f"CAT I: {cat1}")
        self.query_one("#stig_cat2", Label).update(f"CAT II: {cat2}")
        self.query_one("#stig_cat3", Label).update(f"CAT III: {cat3}")
        self.query_one("#stig_naf", Label).update(f"Not a Finding: {naf}")
        self.query_one("#stig_na", Label).update(f"Not Applicable: {na}")
        self.query_one("#stig_nr", Label).update(f"Not Reviewed: {nr}")

        max_cat = max(cat1, cat2, cat3, 1)
        bar_w = 20

        def bar(n):
            filled = int(n / max_cat * bar_w)
            return "█" * filled + "░" * (bar_w - filled)

        chart = (
            f"CAT I   [{bar(cat1):20s}] {cat1}\n"
            f"CAT II  [{bar(cat2):20s}] {cat2}\n"
            f"CAT III [{bar(cat3):20s}] {cat3}"
        )
        self.query_one("#stig_chart", Static).update(chart)

        tbl = self.query_one("#stig_table", DataTable)
        tbl.clear()
        open_rows = ckl_df[ckl_df["Status"] == "Open"]
        for _, row in open_rows.iterrows():
            title = str(row.get("Rule_Title", ""))[:60]
            tbl.add_row(
                str(row.get("Vuln_Num", "")),
                str(row.get("CAT", "")),
                str(row.get("Severity", "")),
                str(row.get("Status_Label", row.get("Status", ""))),
                title,
            )


# ──────────────────────────────────────────────────────────────────────────────
# eMASS Screen
# ──────────────────────────────────────────────────────────────────────────────

class EmassScreen(ScrollableContainer):
    """eMASS Compliance panel."""

    def compose(self) -> ComposeResult:
        yield Label(" eMASS COMPLIANCE RESULTS ", classes="section-label")

        yield Label("COMPLIANCE RATE: ---%", id="emass_pct", classes="panel-title")
        yield Static("", id="emass_gauge", classes="ascii-chart")

        with Horizontal(classes="metric-strip"):
            yield Label("Total: --", id="emass_total", classes="metric-box")
            yield Label("Compliant: --", id="emass_compliant", classes="metric-box")
            yield Label("Non-Compliant: --", id="emass_nc", classes="metric-box")
            yield Label("Not Applicable: --", id="emass_na", classes="metric-box")
            yield Label("Not Reviewed: --", id="emass_nr", classes="metric-box")

        yield Label(" NON-COMPLIANT CONTROLS ", classes="section-label")
        tbl = DataTable(id="emass_table", zebra_stripes=True, show_cursor=True)
        tbl.add_columns("Control ID", "Control Name", "Status", "Test Result", "Test Date")
        yield tbl

    def refresh_data(self, results: dict) -> None:
        emass_df: pd.DataFrame = results.get("emass_df", pd.DataFrame())
        risk_scores: dict = results.get("risk_scores", {})

        if emass_df.empty:
            self.query_one("#emass_pct", Label).update("COMPLIANCE RATE: N/A (No eMASS data)")
            return

        compliance_pct = risk_scores.get("emass_compliance_pct", 100.0)
        label = compliance_label(compliance_pct)
        gauge = ascii_gauge(compliance_pct, 40)

        self.query_one("#emass_pct", Label).update(
            f"COMPLIANCE RATE: {compliance_pct:.1f}%  [{label}]"
        )
        self.query_one("#emass_gauge", Static).update(
            f"[{gauge}]  {compliance_pct:.1f}%"
        )

        total = len(emass_df)
        compliant = len(emass_df[emass_df["Status"] == "Compliant"])
        nc = len(emass_df[emass_df["Status"] == "NonCompliant"])
        na = len(emass_df[emass_df["Status"] == "NA"])
        nr = len(emass_df[emass_df["Status"] == "NR"])

        self.query_one("#emass_total", Label).update(f"Total: {total}")
        self.query_one("#emass_compliant", Label).update(f"Compliant: {compliant}")
        self.query_one("#emass_nc", Label).update(f"Non-Compliant: {nc}")
        self.query_one("#emass_na", Label).update(f"Not Applicable: {na}")
        self.query_one("#emass_nr", Label).update(f"Not Reviewed: {nr}")

        tbl = self.query_one("#emass_table", DataTable)
        tbl.clear()
        nc_rows = emass_df[emass_df["Status"] == "NonCompliant"]
        for _, row in nc_rows.iterrows():
            tbl.add_row(
                str(row.get("Control_ID", "")),
                str(row.get("Control_Name", ""))[:40],
                str(row.get("Status", "")),
                str(row.get("Test_Result", ""))[:30],
                str(row.get("Test_Date", ""))[:10],
            )


# ──────────────────────────────────────────────────────────────────────────────
# POA&M Screen
# ──────────────────────────────────────────────────────────────────────────────

class PoamScreen(ScrollableContainer):
    """POA&M Health Analysis panel."""

    def compose(self) -> ComposeResult:
        yield Label(" POA&M HEALTH ANALYSIS ", classes="section-label")

        with Horizontal(classes="metric-strip"):
            yield Label("Total Items: --", id="poam_total", classes="metric-box")
            yield Label("Completeness: --", id="poam_complete", classes="metric-box")
            yield Label("Timeliness: --", id="poam_timely", classes="metric-box")
            yield Label("Effectiveness: --", id="poam_effect", classes="metric-box")
            yield Label("Health Score: --", id="poam_health", classes="metric-box")

        yield Label("", id="poam_health_gauge", classes="ascii-chart")

        yield Label(" OVERDUE ITEMS ", classes="section-label")
        tbl = DataTable(id="poam_overdue_table", zebra_stripes=True, show_cursor=True)
        tbl.add_columns("POA&M ID", "Control ID", "Weakness", "Status", "Severity", "Due Date", "POC")
        yield tbl

        yield Label(" DEFICIENCY DETAILS ", classes="section-label")
        yield Static("", id="poam_shortfalls", classes="ascii-chart")

    def refresh_data(self, results: dict) -> None:
        poam_metrics: dict = results.get("poam_metrics", {})
        items_df: pd.DataFrame = poam_metrics.get("items_df", pd.DataFrame())

        if not poam_metrics:
            self.query_one("#poam_total", Label).update("Total Items: N/A")
            return

        total = poam_metrics.get("total_items", 0)
        completeness = poam_metrics.get("completeness_score", 0)
        timeliness = poam_metrics.get("timeliness_score", 0)
        effectiveness = poam_metrics.get("effectiveness_score", 0)
        health = poam_metrics.get("poam_health_score", 0)
        health_lbl = health_label(health)
        overdue_count = poam_metrics.get("overdue_count", 0)

        self.query_one("#poam_total", Label).update(f"Total Items: {total}")
        self.query_one("#poam_complete", Label).update(f"Completeness: {completeness:.0f}%")
        self.query_one("#poam_timely", Label).update(f"Timeliness: {timeliness:.0f}%")
        self.query_one("#poam_effect", Label).update(f"Effectiveness: {effectiveness:.0f}%")
        self.query_one("#poam_health", Label).update(f"Health: {health:.0f}/100  {health_lbl}")

        gauge = ascii_gauge(health, 40)
        self.query_one("#poam_health_gauge", Static).update(
            f"POA&M HEALTH SCORE\n[{gauge}]  {health:.0f}/100  [{health_lbl}]"
        )

        # Overdue table
        tbl = self.query_one("#poam_overdue_table", DataTable)
        tbl.clear()
        if not items_df.empty and overdue_count > 0:
            overdue_df = items_df[items_df.get("Overdue", pd.Series(False, index=items_df.index)) == True]
            for _, row in overdue_df.iterrows():
                due = row.get("Scheduled_Completion", "")
                if hasattr(due, "strftime") and not pd.isnull(due):
                    due = due.strftime("%Y-%m-%d")
                tbl.add_row(
                    str(row.get("POAM_ID", "")),
                    str(row.get("Control_ID", "")),
                    str(row.get("Weakness_Name", ""))[:35],
                    str(row.get("Status", "")),
                    str(row.get("Severity", "")),
                    str(due)[:10],
                    str(row.get("POC", ""))[:20],
                )

        # Shortfalls
        shortfalls = poam_metrics.get("shortfalls", [])
        if shortfalls:
            lines = []
            for sf in shortfalls[:20]:
                lines.append(
                    f"[{sf.get('control_id','')}] {sf.get('poam_id','')} "
                    f"— {sf.get('weakness_name','')[:50]}"
                )
                for issue in sf.get("issues", [])[:2]:
                    lines.append(f"  • {issue}")
            self.query_one("#poam_shortfalls", Static).update("\n".join(lines))
        else:
            self.query_one("#poam_shortfalls", Static).update(
                "No POA&M deficiencies identified."
            )


# ──────────────────────────────────────────────────────────────────────────────
# Risk Screen
# ──────────────────────────────────────────────────────────────────────────────

class RiskScreen(ScrollableContainer):
    """Risk Dashboard panel."""

    def compose(self) -> ComposeResult:
        yield Label(" RISK DASHBOARD ", classes="section-label")

        # System info
        yield Static("", id="risk_sysinfo", classes="status-info")

        yield Label(" CIA RISK DIMENSIONS ", classes="section-label")

        # CIA gauge row
        with Horizontal():
            with Container(classes="gauge-panel"):
                yield Label("CONFIDENTIALITY", classes="panel-title")
                yield Static("", id="risk_c_score")
                yield Static("", id="risk_c_gauge")
                yield Static("", id="risk_c_level")
            with Container(classes="gauge-panel"):
                yield Label("INTEGRITY", classes="panel-title")
                yield Static("", id="risk_i_score")
                yield Static("", id="risk_i_gauge")
                yield Static("", id="risk_i_level")
            with Container(classes="gauge-panel"):
                yield Label("AVAILABILITY", classes="panel-title")
                yield Static("", id="risk_a_score")
                yield Static("", id="risk_a_gauge")
                yield Static("", id="risk_a_level")

        yield Label(" OVERALL RISK SCORE ", classes="section-label")
        yield Static("", id="risk_overall", classes="status-info")
        yield Static("", id="risk_overall_gauge", classes="ascii-chart")

        yield Label(" ATO RECOMMENDATION ", classes="section-label")
        yield Static("", id="risk_ato_banner", classes="ato-banner")
        yield Static("", id="risk_ato_reasons")

        yield Label(" HIGH-RISK MITIGATIONS ", classes="section-label")
        yield Static("", id="risk_mitigations", classes="ascii-chart")

        yield Label(" KEV MATCHES ", classes="section-label")
        kev_tbl = DataTable(id="kev_table", zebra_stripes=True, show_cursor=True)
        kev_tbl.add_columns("CVE ID", "Vendor", "Product", "Vulnerability", "Date Added", "Ransomware")
        yield kev_tbl

        yield Label(" EXPORT RESULTS ", classes="section-label")
        with Horizontal():
            yield Button("EXPORT EXCEL REPORT", id="export_excel_btn")
            yield Button("EXPORT CSV FINDINGS", id="export_csv_btn")
        yield Label("", id="export_status")

    def refresh_data(self, results: dict) -> None:
        risk_scores: dict = results.get("risk_scores", {})
        ato_result: dict = results.get("ato_result", {})
        system_name: str = results.get("system_name", "Unknown")
        system_type_key: str = results.get("system_type_key", "it_general")
        analysis_date: str = results.get("analysis_date", "")
        kev_df: pd.DataFrame = results.get("kev_df", pd.DataFrame())
        sys_label = SYSTEM_TYPES.get(system_type_key, {}).get("label", "Unknown")

        self.query_one("#risk_sysinfo", Static).update(
            f"System: {system_name}   Type: {sys_label}   Analysis Date: {analysis_date}"
        )

        # CIA scores
        for dim, wid_score, wid_gauge, wid_level in [
            ("C", "#risk_c_score", "#risk_c_gauge", "#risk_c_level"),
            ("I", "#risk_i_score", "#risk_i_gauge", "#risk_i_level"),
            ("A", "#risk_a_score", "#risk_a_gauge", "#risk_a_level"),
        ]:
            score = risk_scores.get(dim, {}).get("score", 0)
            level = risk_scores.get(dim, {}).get("level", "UNKNOWN")
            gauge = ascii_gauge(score, 16)
            self.query_one(wid_score, Static).update(f"Score: {score:.1f}")
            self.query_one(wid_gauge, Static).update(f"[{gauge}]")
            self.query_one(wid_level, Static).update(level)

        # Overall
        overall = risk_scores.get("overall_score", 0)
        overall_level = risk_scores.get("overall_level", "UNKNOWN")
        cat1 = risk_scores.get("open_cat1", 0)
        cat2 = risk_scores.get("open_cat2", 0)
        cat3 = risk_scores.get("open_cat3", 0)
        emass_pct = risk_scores.get("emass_compliance_pct", 100.0)
        kev_count = risk_scores.get("kev_count", 0)
        poam_health = risk_scores.get("poam_health_score")

        poam_str = f"   POA&M Health: {poam_health:.0f}/100" if poam_health is not None else ""
        self.query_one("#risk_overall", Static).update(
            f"Overall Risk: {overall}/100  [{overall_level}]   "
            f"CAT I:{cat1}  CAT II:{cat2}  CAT III:{cat3}   "
            f"eMASS:{emass_pct:.1f}%   KEV:{kev_count}{poam_str}"
        )
        overall_gauge = ascii_gauge(overall, 40)
        self.query_one("#risk_overall_gauge", Static).update(
            f"[{overall_gauge}]  {overall}/100  [{overall_level}]"
        )

        # ATO Banner
        recommendation = ato_result.get("recommendation", "UNKNOWN")
        ato_reasons = ato_result.get("reasons", [])
        rec_key = recommendation.lower().replace(" ", "_").replace("/", "_")
        banner_text = f"  ATO RECOMMENDATION: {recommendation}  "
        self.query_one("#risk_ato_banner", Static).update(banner_text)

        reasons_text = "\n".join(f"  * {r}" for r in ato_reasons)
        self.query_one("#risk_ato_reasons", Static).update(reasons_text)

        # Mitigations (KEV, CVE, STIG, POA&M)
        lines = []
        kev_mits = ato_result.get("kev_mitigations", [])
        if kev_mits:
            lines.append("=== CISA KNOWN EXPLOITED VULNERABILITIES ===")
            for m in kev_mits[:10]:
                ransomware = " [RANSOMWARE]" if m.get("ransomware", "").lower() == "known" else ""
                lines.append(
                    f"  {m.get('cve_id','')} — {m.get('title','')[:50]}{ransomware}"
                )
                lines.append(f"    Action: {m.get('required_action','')[:70]}")

        cve_mits = ato_result.get("cve_mitigations", [])
        if cve_mits:
            lines.append("=== CRITICAL/HIGH CVEs ===")
            for m in cve_mits[:10]:
                lines.append(
                    f"  {m.get('title','')} (CVSS {m.get('cvss_score',0)} — {m.get('severity','')})"
                )
                for action in m.get("actions", [])[:2]:
                    lines.append(f"    • {action}")

        stig_mits = ato_result.get("stig_mitigations", [])
        if stig_mits:
            lines.append("=== OPEN STIG FINDINGS ===")
            for m in stig_mits[:10]:
                lines.append(
                    f"  [{m.get('severity','')}] {m.get('vuln_id','')} — {m.get('title','')[:50]}"
                )

        poam_mits = ato_result.get("poam_mitigations", [])
        if poam_mits:
            lines.append("=== POA&M DEFICIENCIES ===")
            for m in poam_mits[:10]:
                lines.append(
                    f"  [{m.get('control_id','')}] {m.get('poam_id','')} — "
                    f"{m.get('weakness_name','')[:50]}"
                )

        if not lines:
            lines = ["No high-priority mitigations required."]

        self.query_one("#risk_mitigations", Static).update("\n".join(lines))

        # KEV table
        kev_tbl = self.query_one("#kev_table", DataTable)
        kev_tbl.clear()
        if kev_df is not None and not kev_df.empty:
            for _, row in kev_df.iterrows():
                kev_tbl.add_row(
                    str(row.get("cve_id", "")),
                    str(row.get("vendorProject", ""))[:20],
                    str(row.get("product", ""))[:20],
                    str(row.get("vulnerabilityName", ""))[:35],
                    str(row.get("dateAdded", ""))[:10],
                    str(row.get("knownRansomwareCampaignUse", ""))[:10],
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "export_excel_btn":
            self.app.export_excel()
        elif event.button.id == "export_csv_btn":
            self.app.export_csv()


# ──────────────────────────────────────────────────────────────────────────────
# Main App
# ──────────────────────────────────────────────────────────────────────────────

class RMFApp(App):
    """DOS-Style RMF Assessment Dashboard TUI."""

    CSS = DOS_CSS

    TITLE = "RMF ASSESSMENT DASHBOARD v1.0 | NIST RMF | DISA STIG | NVD CVE 2.0 | CISA KEV"

    BINDINGS = [
        Binding("f1", "switch_tab('config')", "F1=Config"),
        Binding("f2", "switch_tab('inventory')", "F2=Inventory"),
        Binding("f3", "switch_tab('stig')", "F3=STIG"),
        Binding("f4", "switch_tab('emass')", "F4=eMASS"),
        Binding("f5", "switch_tab('poam')", "F5=POA&M"),
        Binding("f6", "switch_tab('risk')", "F6=Risk"),
        Binding("q", "quit", "Q=Quit"),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    # Shared analysis state
    _results: dict[str, Any] = {}
    _analysis_done: bool = False

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="main_tabs"):
            with TabPane("F1 CONFIG", id="config"):
                yield ConfigScreen(id="config_screen")
            with TabPane("F2 INVENTORY", id="inventory"):
                yield InventoryScreen(id="inventory_screen")
            with TabPane("F3 STIG", id="stig"):
                yield StigScreen(id="stig_screen")
            with TabPane("F4 eMASS", id="emass"):
                yield EmassScreen(id="emass_screen")
            with TabPane("F5 POA&M", id="poam"):
                yield PoamScreen(id="poam_screen")
            with TabPane("F6 RISK", id="risk"):
                yield RiskScreen(id="risk_screen")
        yield Footer()

    def action_switch_tab(self, tab_id: str) -> None:
        tabs = self.query_one("#main_tabs", TabbedContent)
        tabs.active = tab_id

    def action_quit(self) -> None:
        self.exit()

    # ──────────────────────────────────────────────────────────────────────────
    # Analysis pipeline helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _get_config(self) -> dict:
        cfg_screen = self.query_one("#config_screen", ConfigScreen)
        return {
            "system_name": cfg_screen.query_one("#sys_name", Input).value.strip(),
            "system_type_key": str(cfg_screen.query_one("#sys_type", Select).value),
            "ckl_path": cfg_screen.query_one("#ckl_path", Input).value.strip(),
            "inv_path": cfg_screen.query_one("#inv_path", Input).value.strip(),
            "emass_path": cfg_screen.query_one("#emass_path", Input).value.strip(),
            "poam_path": cfg_screen.query_one("#poam_path", Input).value.strip(),
            "nvd_key": cfg_screen.query_one("#nvd_key", Input).value.strip(),
        }

    def _set_progress(self, pct: int, status: str) -> None:
        try:
            cfg = self.query_one("#config_screen", ConfigScreen)
            cfg.query_one("#run_status", Label).update(status)
            cfg.query_one("#run_progress", ProgressBar).update(progress=pct)
        except NoMatches:
            pass

    def run_analysis(self) -> None:
        cfg = self._get_config()
        if not cfg["system_name"]:
            self._set_progress(0, "ERROR: System name is required.")
            return
        if not any([cfg["ckl_path"], cfg["inv_path"], cfg["emass_path"], cfg["poam_path"]]):
            self._set_progress(0, "ERROR: Provide at least one input file path.")
            return
        self._set_progress(0, "Starting analysis pipeline...")
        self._run_pipeline(cfg)

    @work(thread=True)
    def _run_pipeline(self, cfg: dict) -> None:
        """Background worker thread — runs full analysis pipeline."""
        from parsers.ckl_parser import parse_ckl
        from parsers.emass_parser import parse_emass
        from parsers.inventory_parser import parse_inventory
        from parsers.poam_parser import parse_poam
        from analysis.nvd_client import query_nvd
        from analysis.cisa_kev import fetch_kev, match_kev
        from analysis.risk_engine import compute_cia_scores
        from analysis.ato_engine import generate_ato_recommendation
        from analysis.poam_engine import analyze_poam

        def progress(pct: int, status: str) -> None:
            self.call_from_thread(self._set_progress, pct, status)

        try:
            results: dict[str, Any] = {}
            kev_cache: dict = {}

            progress(5, "Parsing input files...")

            # Parse CKL
            ckl_df = pd.DataFrame()
            if cfg["ckl_path"] and Path(cfg["ckl_path"]).exists():
                try:
                    with open(cfg["ckl_path"], "rb") as f:
                        ckl_df = parse_ckl(f.read())
                    results["ckl_df"] = ckl_df
                except Exception as e:
                    progress(5, f"WARN: CKL parse error: {e}")

            progress(10, "Parsing eMASS export...")

            # Parse eMASS
            emass_df = pd.DataFrame()
            if cfg["emass_path"] and Path(cfg["emass_path"]).exists():
                try:
                    emass_df = parse_emass(cfg["emass_path"])
                    results["emass_df"] = emass_df
                except Exception as e:
                    progress(10, f"WARN: eMASS parse error: {e}")

            progress(15, "Parsing inventory...")

            # Parse inventory
            inventory_df = pd.DataFrame()
            if cfg["inv_path"] and Path(cfg["inv_path"]).exists():
                try:
                    inventory_df = parse_inventory(cfg["inv_path"])
                    results["inventory_df"] = inventory_df
                except Exception as e:
                    progress(15, f"WARN: Inventory parse error: {e}")

            progress(20, "Parsing POA&M...")

            # Parse POA&M
            poam_df = pd.DataFrame()
            if cfg["poam_path"] and Path(cfg["poam_path"]).exists():
                try:
                    poam_df = parse_poam(cfg["poam_path"])
                    results["poam_df"] = poam_df
                except Exception as e:
                    progress(20, f"WARN: POA&M parse error: {e}")

            progress(25, "Querying NVD for CVEs...")

            # NVD queries
            cve_list = []
            if not inventory_df.empty:
                unique_products = inventory_df[["Vendor", "Product"]].drop_duplicates()
                total_prods = len(unique_products)
                for idx, (_, row) in enumerate(unique_products.iterrows()):
                    vendor = str(row.get("Vendor", "")).strip()
                    product = str(row.get("Product", "")).strip()
                    if not vendor and not product:
                        continue
                    try:
                        pct_nvd = 25 + int((idx + 1) / max(total_prods, 1) * 30)
                        progress(pct_nvd, f"NVD: {vendor} {product} ({idx+1}/{total_prods})...")
                        cves = query_nvd(vendor, product, api_key=cfg["nvd_key"] or None)
                        cve_list.extend(cves)
                    except Exception as e:
                        progress(pct_nvd, f"WARN: NVD error {vendor} {product}: {e}")
            results["cve_list"] = cve_list

            progress(60, "Fetching CISA KEV feed...")

            # CISA KEV
            kev_df = pd.DataFrame()
            try:
                kev_vulns = fetch_kev(kev_cache)
                cve_ids = [c["cve_id"] for c in cve_list]
                kev_df = match_kev(kev_vulns, cve_ids=cve_ids, inventory_df=inventory_df)
                results["kev_df"] = kev_df
            except Exception as e:
                progress(60, f"WARN: KEV error: {e}")

            progress(72, "Analyzing POA&M health...")

            # POA&M health
            poam_metrics = {}
            if not poam_df.empty:
                poam_metrics = analyze_poam(poam_df, emass_df)
            results["poam_metrics"] = poam_metrics

            progress(78, "Computing CIA risk scores...")

            # CIA risk scoring
            risk_scores = compute_cia_scores(
                ckl_df=ckl_df,
                cve_list=cve_list,
                emass_df=emass_df,
                kev_df=kev_df,
                system_type_key=cfg["system_type_key"],
                poam_metrics=poam_metrics if poam_metrics else None,
            )
            results["risk_scores"] = risk_scores

            progress(90, "Generating ATO recommendation...")

            # ATO recommendation
            ato_result = generate_ato_recommendation(
                risk_scores=risk_scores,
                ckl_df=ckl_df,
                kev_df=kev_df,
                cve_list=cve_list,
                emass_df=emass_df,
                poam_metrics=poam_metrics if poam_metrics else None,
            )
            results["ato_result"] = ato_result
            results["system_name"] = cfg["system_name"]
            results["system_type_key"] = cfg["system_type_key"]
            results["analysis_date"] = datetime.date.today().isoformat()

            progress(100, "Analysis complete!")
            self.call_from_thread(self.post_message, AnalysisComplete(results))

        except Exception as exc:
            self.call_from_thread(self.post_message, AnalysisError(str(exc)))

    def on_analysis_complete(self, message: AnalysisComplete) -> None:
        self._results = message.results
        self._analysis_done = True
        self._set_progress(100, "Analysis complete! Use F2-F6 to view results.")
        self._refresh_all_screens()

    def on_analysis_error(self, message: AnalysisError) -> None:
        self._set_progress(0, f"ERROR: {message.error}")

    def _refresh_all_screens(self) -> None:
        try:
            self.query_one("#inventory_screen", InventoryScreen).refresh_data(self._results)
        except NoMatches:
            pass
        try:
            self.query_one("#stig_screen", StigScreen).refresh_data(self._results)
        except NoMatches:
            pass
        try:
            self.query_one("#emass_screen", EmassScreen).refresh_data(self._results)
        except NoMatches:
            pass
        try:
            self.query_one("#poam_screen", PoamScreen).refresh_data(self._results)
        except NoMatches:
            pass
        try:
            self.query_one("#risk_screen", RiskScreen).refresh_data(self._results)
        except NoMatches:
            pass

    # ──────────────────────────────────────────────────────────────────────────
    # Export
    # ──────────────────────────────────────────────────────────────────────────

    def export_excel(self) -> None:
        if not self._analysis_done:
            self._set_export_status("No analysis results to export. Run analysis first.")
            return
        self._do_export_excel()

    @work(thread=True)
    def _do_export_excel(self) -> None:
        from utils.exporter import export_excel

        try:
            r = self._results
            system_name = r.get("system_name", "system")
            sys_label = SYSTEM_TYPES.get(r.get("system_type_key", ""), {}).get("label", "Unknown")
            analysis_date = r.get("analysis_date", datetime.date.today().isoformat())
            safe_name = safe_filename(system_name)

            excel_bytes = export_excel(
                system_name=system_name,
                system_type=sys_label,
                risk_scores=r.get("risk_scores", {}),
                ato_result=r.get("ato_result", {}),
                ckl_df=r.get("ckl_df"),
                cve_list=r.get("cve_list", []),
                kev_df=r.get("kev_df"),
                emass_df=r.get("emass_df"),
                inventory_df=r.get("inventory_df"),
                poam_df=r.get("poam_df"),
            )
            filename = f"rmf_assessment_{safe_name}_{analysis_date}.xlsx"
            Path(filename).write_bytes(excel_bytes)
            self.call_from_thread(
                self._set_export_status,
                f"Exported: {Path(filename).resolve()}"
            )
        except Exception as e:
            self.call_from_thread(self._set_export_status, f"Excel export error: {e}")

    def export_csv(self) -> None:
        if not self._analysis_done:
            self._set_export_status("No analysis results to export. Run analysis first.")
            return
        self._do_export_csv()

    @work(thread=True)
    def _do_export_csv(self) -> None:
        from utils.exporter import export_csv

        try:
            r = self._results
            system_name = r.get("system_name", "system")
            analysis_date = r.get("analysis_date", datetime.date.today().isoformat())
            safe_name = safe_filename(system_name)

            csv_bytes = export_csv(
                risk_scores=r.get("risk_scores", {}),
                ato_result=r.get("ato_result", {}),
                ckl_df=r.get("ckl_df"),
                cve_list=r.get("cve_list", []),
                kev_df=r.get("kev_df"),
                emass_df=r.get("emass_df"),
            )
            filename = f"rmf_findings_{safe_name}_{analysis_date}.csv"
            Path(filename).write_bytes(csv_bytes)
            self.call_from_thread(
                self._set_export_status,
                f"Exported: {Path(filename).resolve()}"
            )
        except Exception as e:
            self.call_from_thread(self._set_export_status, f"CSV export error: {e}")

    def _set_export_status(self, msg: str) -> None:
        try:
            self.query_one("#export_status", Label).update(msg)
        except NoMatches:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = RMFApp()
    app.run()
