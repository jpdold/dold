"""
Playwright automation — drives the RMF dashboard end-to-end in a visible browser,
uploads the three TCS test files, runs analysis, then screenshots every tab.
"""

import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, expect, TimeoutError as PWTimeout

BASE      = Path(__file__).parent
DASH_URL  = "http://localhost:8501"
NVD_KEY   = "3c58938a-ee14-434b-af8c-4065622db2ba"
SYS_NAME  = "Tactical Command System (TCS)"
FILES     = {
    "ckl":       str(BASE / "TCS-APP-01_WIN2019.ckl"),
    "inventory": str(BASE / "tcs_inventory.xlsx"),
    "emass":     str(BASE / "tcs_emass_export.csv"),
}
SHOTS_DIR = BASE / "screenshots"
SHOTS_DIR.mkdir(exist_ok=True)


def shot(page, name):
    path = str(SHOTS_DIR / f"{name}.png")
    page.screenshot(path=path, full_page=True)
    print(f"  screenshot -> {path}")


def wait_spinner_gone(page, timeout=300_000):
    """Wait until the Streamlit running spinner disappears."""
    try:
        page.wait_for_selector("[data-testid='stStatusWidget']", timeout=5_000)
        page.wait_for_selector(
            "[data-testid='stStatusWidget']",
            state="hidden",
            timeout=timeout,
        )
    except PWTimeout:
        pass  # spinner may not appear for fast ops


with sync_playwright() as p:
    browser = p.chromium.launch(headless=False, slow_mo=100)
    ctx     = browser.new_context(viewport={"width": 1400, "height": 900})
    page    = ctx.new_page()

    # ── Load dashboard ───────────────────────────────────────────────────────
    print("Opening dashboard…")
    page.goto(DASH_URL, wait_until="networkidle")
    wait_spinner_gone(page)
    page.wait_for_timeout(1500)
    shot(page, "01_landing")

    # ── Sidebar: NVD API key ─────────────────────────────────────────────────
    print("Entering NVD API key…")
    nvd_input = page.locator("input[type='password']").first
    nvd_input.click()
    nvd_input.fill(NVD_KEY)
    nvd_input.press("Tab")
    wait_spinner_gone(page)
    page.wait_for_timeout(800)

    # ── Tab 1: System Name ───────────────────────────────────────────────────
    print("Entering system name…")
    sys_name_input = page.get_by_label("System Name")
    sys_name_input.click()
    sys_name_input.fill(SYS_NAME)
    sys_name_input.press("Tab")
    wait_spinner_gone(page)
    page.wait_for_timeout(500)

    # ── Upload CKL ───────────────────────────────────────────────────────────
    print("Uploading CKL…")
    uploaders = page.locator("input[type='file']")
    uploaders.nth(0).set_input_files(FILES["ckl"])
    wait_spinner_gone(page)
    page.wait_for_timeout(1000)

    # ── Upload Inventory ─────────────────────────────────────────────────────
    print("Uploading inventory…")
    uploaders.nth(1).set_input_files(FILES["inventory"])
    wait_spinner_gone(page)
    page.wait_for_timeout(1000)

    # ── Upload eMASS ─────────────────────────────────────────────────────────
    print("Uploading eMASS export…")
    uploaders.nth(2).set_input_files(FILES["emass"])
    wait_spinner_gone(page)
    page.wait_for_timeout(1000)
    shot(page, "02_files_loaded")

    # ── Click Run Analysis ───────────────────────────────────────────────────
    print("Clicking Run Analysis…")
    page.get_by_text("Run Analysis", exact=False).click()
    page.wait_for_timeout(1000)
    shot(page, "03_analysis_running")

    # ── Wait for completion (NVD queries take time) ──────────────────────────
    print("Waiting for analysis to complete (NVD queries in progress)…")
    try:
        page.wait_for_selector(
            "text=Analysis complete",
            timeout=600_000,   # up to 10 min
        )
    except PWTimeout:
        print("  [WARN] Timed out waiting for 'Analysis complete' — continuing anyway")
    wait_spinner_gone(page, timeout=60_000)
    page.wait_for_timeout(2000)
    shot(page, "04_analysis_done")

    # ── Tab 2: Inventory & CVEs ──────────────────────────────────────────────
    print("Navigating to Inventory & CVEs tab…")
    page.get_by_role("tab", name="Inventory & CVEs").click()
    wait_spinner_gone(page)
    page.wait_for_timeout(1500)
    shot(page, "05_inventory_cves")

    # ── Tab 3: STIG Compliance ───────────────────────────────────────────────
    print("Navigating to STIG Compliance tab…")
    page.get_by_role("tab", name="STIG Compliance").click()
    wait_spinner_gone(page)
    page.wait_for_timeout(1500)
    shot(page, "06_stig_compliance")

    # ── Tab 4: eMASS Results ─────────────────────────────────────────────────
    print("Navigating to eMASS Results tab…")
    page.get_by_role("tab", name="eMASS Results").click()
    wait_spinner_gone(page)
    page.wait_for_timeout(1500)
    shot(page, "07_emass_results")

    # ── Tab 5: Risk Dashboard ────────────────────────────────────────────────
    print("Navigating to Risk Dashboard tab…")
    page.get_by_role("tab", name="Risk Dashboard").click()
    wait_spinner_gone(page)
    page.wait_for_timeout(2000)
    shot(page, "08_risk_dashboard")

    # Scroll to ATO recommendation banner
    ato_el = page.get_by_text("ATO Recommendation:", exact=False).first
    ato_el.scroll_into_view_if_needed()
    page.wait_for_timeout(800)
    shot(page, "09_risk_dashboard_ato")

    # Scroll to mitigations section
    mit_el = page.get_by_text("High-Risk Mitigations", exact=False).first
    mit_el.scroll_into_view_if_needed()
    page.wait_for_timeout(800)
    shot(page, "10_risk_dashboard_mitigations")

    print("\nDone. Browser will stay open for 30 seconds.")
    page.wait_for_timeout(30_000)
    browser.close()

print(f"\nAll screenshots saved to: {SHOTS_DIR}")
