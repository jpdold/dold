"""
Playwright automation — drives the RMF dashboard end-to-end in a visible (or
headless) browser, uploads assessment files, runs analysis, and screenshots
every tab.

Usage
-----
# Use built-in TCS test fixtures (defaults):
  python _run_dashboard.py

# Real files on any device:
  python _run_dashboard.py \\
      --ckl      /path/to/system.ckl \\
      --inventory /path/to/inventory.xlsx \\
      --emass    /path/to/emass_export.csv \\
      --name     "My System Name" \\
      --key      "your-nvd-api-key" \\
      --url      "http://localhost:8501" \\
      --headless \\
      --out      /path/to/screenshots

All file arguments are optional — omit any you don't have and that uploader
will be skipped.
"""

import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# ── Defaults (TCS test fixtures, same directory as this script) ──────────────
_HERE = Path(__file__).parent

DEFAULT_URL      = "http://localhost:8501"
DEFAULT_NVD_KEY  = ""
DEFAULT_SYS_NAME = "Tactical Command System (TCS)"
DEFAULT_CKL      = str(_HERE / "TCS-APP-01_WIN2019.ckl")
DEFAULT_INVENTORY= str(_HERE / "tcs_inventory.xlsx")
DEFAULT_EMASS    = str(_HERE / "tcs_emass_export.csv")
DEFAULT_POAM     = str(_HERE / "tcs_poam_export.csv")
DEFAULT_OUT      = str(_HERE / "screenshots")


# ── Argument parsing ─────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Run the RMF Assessment Dashboard end-to-end via Playwright.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--url",       default=DEFAULT_URL,
                   help="Streamlit dashboard URL")
    p.add_argument("--key",       default=DEFAULT_NVD_KEY,
                   metavar="NVD_API_KEY",
                   help="NVD API key (omit to run unauthenticated)")
    p.add_argument("--name",      default=DEFAULT_SYS_NAME,
                   metavar="SYSTEM_NAME",
                   help="System name entered in the dashboard")
    p.add_argument("--ckl",       default=DEFAULT_CKL,
                   help="Path to STIG checklist (.ckl). Pass 'none' to skip.")
    p.add_argument("--inventory", default=DEFAULT_INVENTORY,
                   help="Path to HW/SW inventory (.csv or .xlsx). Pass 'none' to skip.")
    p.add_argument("--emass",     default=DEFAULT_EMASS,
                   help="Path to eMASS export (.csv or .xlsx). Pass 'none' to skip.")
    p.add_argument("--poam",      default=DEFAULT_POAM,
                   help="Path to POA&M export (.csv or .xlsx). Pass 'none' to skip.")
    p.add_argument("--out",       default=DEFAULT_OUT,
                   metavar="SCREENSHOTS_DIR",
                   help="Directory to write screenshots into")
    p.add_argument("--headless",  action="store_true",
                   help="Run Chromium headless (no visible window; useful on servers)")
    p.add_argument("--keep-open", type=int, default=30, metavar="SECONDS",
                   help="Seconds to keep the browser open after finishing (0 = close immediately)")
    return p.parse_args()


def resolve_file(path_str: str) -> str | None:
    """Return the path if it exists and isn't 'none', otherwise None."""
    if not path_str or path_str.lower() == "none":
        return None
    p = Path(path_str)
    if not p.exists():
        print(f"  [WARN] File not found, skipping: {p}")
        return None
    return str(p)


# ── Helpers ──────────────────────────────────────────────────────────────────
def shot(page, name: str, shots_dir: Path):
    path = str(shots_dir / f"{name}.png")
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
        pass


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    shots_dir = Path(args.out)
    shots_dir.mkdir(parents=True, exist_ok=True)

    ckl_path       = resolve_file(args.ckl)
    inventory_path = resolve_file(args.inventory)
    emass_path     = resolve_file(args.emass)
    poam_path      = resolve_file(args.poam)

    print(f"Dashboard : {args.url}")
    print(f"System    : {args.name}")
    print(f"CKL       : {ckl_path or '(skipped)'}")
    print(f"Inventory : {inventory_path or '(skipped)'}")
    print(f"eMASS     : {emass_path or '(skipped)'}")
    print(f"POA&M     : {poam_path or '(skipped)'}")
    print(f"NVD key   : {'set' if args.key else '(none — unauthenticated)'}")
    print(f"Headless  : {args.headless}")
    print(f"Screenshots: {shots_dir}")
    print()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=args.headless, slow_mo=100)
        ctx     = browser.new_context(viewport={"width": 1400, "height": 900})
        page    = ctx.new_page()

        # ── Load dashboard ───────────────────────────────────────────────────
        print("Opening dashboard…")
        page.goto(args.url, wait_until="networkidle")
        wait_spinner_gone(page)
        page.wait_for_timeout(1500)
        shot(page, "01_landing", shots_dir)

        # ── Sidebar: NVD API key ─────────────────────────────────────────────
        if args.key:
            print("Entering NVD API key…")
            nvd_input = page.locator("input[type='password']").first
            nvd_input.click()
            nvd_input.fill(args.key)
            nvd_input.press("Tab")
            wait_spinner_gone(page)
            page.wait_for_timeout(800)

        # ── System Name ──────────────────────────────────────────────────────
        print("Entering system name…")
        sys_name_input = page.get_by_label("System Name")
        sys_name_input.click()
        sys_name_input.fill(args.name)
        sys_name_input.press("Tab")
        wait_spinner_gone(page)
        page.wait_for_timeout(500)

        # ── File uploads ─────────────────────────────────────────────────────
        uploaders = page.locator("input[type='file']")

        if ckl_path:
            print("Uploading CKL…")
            uploaders.nth(0).set_input_files(ckl_path)
            wait_spinner_gone(page)
            page.wait_for_timeout(1000)

        if inventory_path:
            print("Uploading inventory…")
            uploaders.nth(1).set_input_files(inventory_path)
            wait_spinner_gone(page)
            page.wait_for_timeout(1000)

        if emass_path:
            print("Uploading eMASS export…")
            uploaders.nth(2).set_input_files(emass_path)
            wait_spinner_gone(page)
            page.wait_for_timeout(1000)

        if poam_path:
            print("Uploading POA&M export…")
            uploaders.nth(3).set_input_files(poam_path)
            wait_spinner_gone(page)
            page.wait_for_timeout(1000)

        shot(page, "02_files_loaded", shots_dir)

        # ── Run Analysis ─────────────────────────────────────────────────────
        print("Clicking Run Analysis…")
        page.get_by_text("Run Analysis", exact=False).click()
        page.wait_for_timeout(1000)
        shot(page, "03_analysis_running", shots_dir)

        print("Waiting for analysis to complete…")
        try:
            page.wait_for_selector("text=Analysis complete", timeout=600_000)
        except PWTimeout:
            print("  [WARN] Timed out waiting for 'Analysis complete' — continuing anyway")
        wait_spinner_gone(page, timeout=60_000)
        page.wait_for_timeout(2000)
        shot(page, "04_analysis_done", shots_dir)

        # ── Tab 2: Inventory & CVEs ──────────────────────────────────────────
        print("Navigating to Inventory & CVEs tab…")
        page.get_by_role("tab", name="Inventory & CVEs").click()
        wait_spinner_gone(page)
        page.wait_for_timeout(1500)
        shot(page, "05_inventory_cves", shots_dir)

        # ── Tab 3: STIG Compliance ───────────────────────────────────────────
        print("Navigating to STIG Compliance tab…")
        page.get_by_role("tab", name="STIG Compliance").click()
        wait_spinner_gone(page)
        page.wait_for_timeout(1500)
        shot(page, "06_stig_compliance", shots_dir)

        # ── Tab 4: eMASS Results ─────────────────────────────────────────────
        print("Navigating to eMASS Results tab…")
        page.get_by_role("tab", name="eMASS Results").click()
        wait_spinner_gone(page)
        page.wait_for_timeout(1500)
        shot(page, "07_emass_results", shots_dir)

        # ── Tab 5: POA&M Analysis ────────────────────────────────────────────
        print("Navigating to POA&M Analysis tab…")
        page.get_by_role("tab", name="POA&M Analysis").click()
        wait_spinner_gone(page)
        page.wait_for_timeout(2000)
        shot(page, "11_poam_analysis", shots_dir)

        # ── Tab 6: Risk Dashboard ────────────────────────────────────────────
        print("Navigating to Risk Dashboard tab…")
        page.get_by_role("tab", name="Risk Dashboard").click()
        wait_spinner_gone(page)
        page.wait_for_timeout(2000)
        shot(page, "08_risk_dashboard", shots_dir)

        page.get_by_text("ATO Recommendation:", exact=False).first.scroll_into_view_if_needed()
        page.wait_for_timeout(800)
        shot(page, "09_risk_dashboard_ato", shots_dir)

        page.get_by_text("High-Risk Mitigations", exact=False).first.scroll_into_view_if_needed()
        page.wait_for_timeout(800)
        shot(page, "10_risk_dashboard_mitigations", shots_dir)

        if args.keep_open > 0:
            print(f"\nDone. Browser will stay open for {args.keep_open} seconds.")
            page.wait_for_timeout(args.keep_open * 1000)

        browser.close()

    print(f"\nAll screenshots saved to: {shots_dir}")


if __name__ == "__main__":
    main()
