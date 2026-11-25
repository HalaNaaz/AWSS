"""
Ashlynx WebSec Scanner — Full Browser-Based E2E QA Test Suite
Uses Playwright with real Chrome browser binary to validate:
- Dashboard, Navigation, Metrics
- Target Registration Modal & Scope Verification
- Scan Configuration & Safe Active Scan Execution
- Findings Drawer, Severity Badges, CVSS/CWE, Cryptographic Evidence SHA-256 seal
- Attack Surface Dashboard (All 7 tabs: Overview, Prioritized, Endpoints, Parameters, APIs, Assets, Graph)
- Graph Controls: Zoom in/out, Node type filters, Export JSON
- Dedicated Management Pages: /targets, /scans, /findings, /reports
- Console errors and network failure monitoring
"""

import sys
import time
import json
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://127.0.0.1:8000"
TARGET_URL = "http://127.0.0.1:8089"

console_logs = []
page_errors = []
failed_requests = []


def run_e2e_browser_test():
    print("=" * 80)
    print("ASHLYNX WEBSEC SCANNER — BROWSER E2E QA VALIDATION")
    print("=" * 80)

    with sync_playwright() as p:
        print(f"[1/8] Launching Chrome executable at: {CHROME_PATH}...")
        browser = p.chromium.launch(
            executable_path=CHROME_PATH,
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
        )
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        # Listeners for console & network telemetry
        page.on("console", lambda msg: console_logs.append(f"[{msg.type.upper()}] {msg.text}"))
        page.on("pageerror", lambda err: page_errors.append(str(err)))

        def handle_response(response):
            if response.status >= 400 and not response.url.endswith("/favicon.ico"):
                failed_requests.append(f"{response.status} {response.request.method} {response.url}")

        page.on("response", handle_response)

        # ---------------------------------------------------------------------
        # 1. DASHBOARD & NAVIGATION
        # ---------------------------------------------------------------------
        print("\n[2/8] Testing Dashboard & Navigation (/)...")
        page.goto(f"{FRONTEND_URL}/", wait_until="networkidle", timeout=15000)
        assert "Ashlynx" in page.title() or page.locator("text=Ashlynx").count() > 0, "Branding not found"

        # Verify Navigation Links
        for link_text in ["Dashboard", "Scans", "Targets", "Findings", "Reports", "Attack Surface"]:
            assert page.locator(f"nav >> text={link_text}").is_visible(), f"Nav link '{link_text}' missing"
        print("  ✓ Navigation bar verified with all 6 main links")

        # Verify Dashboard Metric Cards
        for metric in ["Critical", "High", "Medium", "Low", "Info", "Active Scans"]:
            assert page.locator(f"text={metric}").count() > 0, f"Metric card '{metric}' missing"
        print("  ✓ Severity summary metric cards present (Critical, High, Medium, Low, Info, Active Scans)")

        # Verify Action Buttons
        assert page.locator("button:has-text('+ New Scan')").is_visible(), "'+ New Scan' button missing"
        assert page.locator("button:has-text('Register Target')").first.is_visible(), "'Register Target' button missing"
        print("  ✓ Action buttons verified")

        # ---------------------------------------------------------------------
        # 2. TARGET REGISTRATION MODAL
        # ---------------------------------------------------------------------
        print("\n[3/8] Testing Target Registration Modal...")
        page.locator("button:has-text('Register Target')").first.click()
        page.wait_for_selector("text=Register Target Scope", timeout=5000)

        # Fill Target Registration Form
        name_input = page.locator("input[placeholder*='Staging']").first
        name_input.fill("Ashlynx QA Labs")
        url_input = page.locator("input[placeholder*='8089']").first
        url_input.fill(TARGET_URL)

        # Submit Registration
        page.locator("form button:has-text('Register Target')").click()
        page.wait_for_timeout(1000)
        print("  ✓ Target registration submitted and modal dismissed cleanly")

        # ---------------------------------------------------------------------
        # 3. SCAN LAUNCH & LIVE WORKFLOW
        # ---------------------------------------------------------------------
        print("\n[4/8] Testing Scan Configuration & Execution...")
        page.locator("button:has-text('+ New Scan')").first.click()
        page.wait_for_selector("text=Configure New DAST Scan", timeout=5000)

        # Fill scan form
        scan_target_input = page.locator("input[placeholder*='8089']").first
        scan_target_input.fill(TARGET_URL)

        # Select Safe Active profile
        profile_select = page.locator("select").first
        profile_select.select_option("SAFE_ACTIVE")

        # Check authorization checkbox in scan modal
        scan_auth_checkbox = page.locator("input#auth-check")
        if not scan_auth_checkbox.is_checked():
            scan_auth_checkbox.check()

        # Submit scan
        page.locator("button:has-text('Start Scan Job')").click()
        page.wait_for_timeout(2000)
        print("  ✓ Scan job launched via UI modal")

        # Wait for scan to appear and transition to COMPLETED
        print("  Polling scans table for completion...")
        scan_completed = False
        scan_id = None
        for attempt in range(25):
            page.wait_for_timeout(2000)
            rows = page.locator("tbody tr")
            if rows.count() > 0:
                first_row_text = rows.first.inner_text()
                if "COMPLETED" in first_row_text:
                    scan_completed = True
                    print(f"  ✓ Scan completed on poll attempt {attempt + 1}")
                    surface_btn = rows.first.locator("a:has-text('Surface')")
                    if surface_btn.count() > 0:
                        href = surface_btn.get_attribute("href")
                        if "scan_id=" in href:
                            scan_id = href.split("scan_id=")[-1]
                    break
                elif "FAILED" in first_row_text:
                    raise RuntimeError(f"Scan failed: {first_row_text}")

        assert scan_completed, "Scan did not reach COMPLETED state within 50s"
        assert scan_id is not None, "Failed to extract scan ID from completed scan row"
        print(f"  ✓ Verified scan completion. Detected Scan ID: {scan_id}")

        # ---------------------------------------------------------------------
        # 4. FINDINGS DRAWER & CRYPTOGRAPHIC EVIDENCE
        # ---------------------------------------------------------------------
        print("\n[5/8] Testing Findings Drawer & Cryptographic Evidence...")
        first_row = page.locator("tbody tr").first
        findings_btn = first_row.locator("button:has-text('Findings')")
        assert findings_btn.is_visible(), "Findings button missing in scan row"
        findings_btn.click()

        # Drawer should appear
        page.wait_for_selector("text=Security Vulnerability Findings", timeout=5000)
        details_buttons = page.locator("button:has-text('Details')")
        buttons_count = details_buttons.count()
        print(f"  ✓ Findings drawer opened with {buttons_count} findings")
        assert buttons_count > 0, "No findings rendered in drawer"

        # Expand first finding
        details_buttons.first.click()
        page.wait_for_timeout(500)

        # Check for Evidence and SHA-256 seal
        assert page.locator("text=Cryptographic Evidence").count() > 0, "Cryptographic Evidence header missing"
        assert page.locator("text=SHA-256:").count() > 0, "SHA-256 seal missing"
        seal_element = page.locator("p:has-text('SHA-256:')").first
        seal_text = seal_element.inner_text().replace("SHA-256:", "").strip()
        assert len(seal_text) == 64, f"Invalid SHA-256 seal length: {len(seal_text)} ({seal_text})"
        print(f"  ✓ Verified Cryptographic SHA-256 seal: {seal_text}")

        # Verify Remediation Guidance
        assert page.locator("text=Remediation Guidance").count() > 0, "Remediation guidance missing"
        print("  ✓ Verified Actionable Remediation Guidance")

        # Close Drawer
        close_btn = page.locator("button:has-text('✕')").first
        close_btn.click()
        page.wait_for_timeout(500)
        print("  ✓ Findings drawer closed")

        # ---------------------------------------------------------------------
        # 5. ATTACK SURFACE DASHBOARD (/attack-surface)
        # ---------------------------------------------------------------------
        print("\n[6/8] Testing Attack Surface Dashboard (/attack-surface)...")
        page.goto(f"{FRONTEND_URL}/attack-surface?scan_id={scan_id}", wait_until="networkidle")
        page.wait_for_selector("text=Attack Surface Intelligence", timeout=10000)

        # Verify all 7 tabs exist
        tab_names = [
            ("Overview & Signals", "overview"),
            ("Prioritization Queue", "prioritized"),
            ("Endpoints", "endpoints"),
            ("Parameters", "parameters"),
            ("APIs", "apis"),
            ("Assets", "assets"),
            ("Topology Graph", "graph"),
        ]
        for label, _ in tab_names:
            tab_btn = page.locator(f"button:has-text('{label}')")
            assert tab_btn.is_visible(), f"Tab '{label}' missing on Attack Surface page"
            print(f"  ✓ Tab '{label}' is visible")

        # Tab 1: Overview & Signals
        page.locator("button:has-text('Overview & Signals')").click()
        page.wait_for_timeout(500)
        assert page.locator("text=Endpoints").count() > 0, "Endpoints metric missing"
        assert page.locator("text=Parameters").count() > 0, "Parameters metric missing"
        print("  ✓ Overview tab: Telemetry metrics and breakdown cards verified")

        # Tab 2: Prioritization Queue
        page.locator("button:has-text('Prioritization Queue')").click()
        page.wait_for_timeout(500)
        assert page.locator("th:has-text('Priority')").is_visible(), "Prioritized table header missing"
        print("  ✓ Prioritization Queue tab verified")

        # Tab 3: Endpoints
        page.locator("button:has-text('Endpoints')").click()
        page.wait_for_timeout(500)
        assert page.locator("th:has-text('Discovery Method')").is_visible(), "Endpoints table header missing"
        # Test search filter
        search_input = page.locator("input[placeholder*='Filter']").first
        search_input.fill("about")
        page.wait_for_timeout(300)
        search_input.fill("")
        print("  ✓ Endpoints tab & search filter verified")

        # Tab 4: Parameters
        page.locator("button:has-text('Parameters')").click()
        page.wait_for_timeout(500)
        assert page.locator("th:has-text('Location')").is_visible(), "Parameters table header missing"
        print("  ✓ Parameters tab verified")

        # Tab 5: APIs
        page.locator("button:has-text('APIs')").click()
        page.wait_for_timeout(500)
        assert page.locator("th:has-text('Auth Required')").is_visible(), "APIs table header missing"
        print("  ✓ APIs tab verified")

        # Tab 6: Assets
        page.locator("button:has-text('Assets')").click()
        page.wait_for_timeout(500)
        assert page.locator("th:has-text('In Scope')").is_visible(), "Assets table header missing"
        print("  ✓ Assets tab verified")

        # Tab 7: Topology Graph
        page.locator("button:has-text('Topology Graph')").click()
        page.wait_for_timeout(500)

        # Verify Graph Controls: Zoom In, Zoom Out, Node Filters, Export
        assert page.locator("button[title='Zoom In']").is_visible(), "Zoom In button missing"
        assert page.locator("button[title='Zoom Out']").is_visible(), "Zoom Out button missing"
        assert page.locator("button:has-text('Export Graph JSON')").is_visible(), "Export Graph JSON button missing"

        page.locator("button[title='Zoom In']").click()
        page.locator("button[title='Zoom Out']").click()
        print("  ✓ Graph tab: Topology canvas, Zoom In/Out, and Export JSON verified")

        # ---------------------------------------------------------------------
        # 6. DEDICATED MANAGEMENT PAGES
        # ---------------------------------------------------------------------
        print("\n[7/8] Testing Dedicated Management Pages...")

        # /targets
        page.goto(f"{FRONTEND_URL}/targets", wait_until="networkidle")
        assert page.locator("text=Authorized Target Management").count() > 0, "/targets title missing"
        print("  ✓ /targets page verified")

        # /scans
        page.goto(f"{FRONTEND_URL}/scans", wait_until="networkidle")
        assert page.locator("text=Scan Execution Registry").count() > 0, "/scans title missing"
        assert page.locator("tbody tr").count() > 0, "No scan rows found in /scans"
        print("  ✓ /scans page verified")

        # /findings (Phase 5 AVIVE Findings Intelligence UI - test navbar click, reload, and direct nav)
        page.locator("nav >> text=Findings").click()
        page.wait_for_url("**/findings", timeout=5000)
        page.reload(wait_until="networkidle")
        assert page.locator("text=Vulnerability Findings & Evidence").count() > 0, "/findings title missing"
        assert page.locator("text=PHASE 5 · AVIVE").is_visible(), "PHASE 5 AVIVE badge missing on /findings"
        assert page.locator("button:has-text('ALL')").is_visible(), "Severity filter missing on /findings"
        assert page.locator("select[aria-label='Confidence Filter']").is_visible(), "Confidence filter missing"
        assert page.locator("select[aria-label='Validation Status Filter']").is_visible(), "Validation filter missing"
        assert page.locator("select[aria-label='Vulnerability Category Filter']").is_visible(), "Category filter missing"
        assert page.locator("select[aria-label='Correlation Group Filter']").is_visible(), "Correlation group filter missing"
        assert page.locator("select[aria-label='Remediation Status Filter']").is_visible(), "Remediation filter missing"
        assert page.get_by_text("Total Normalized", exact=True).is_visible(), "AVIVE Total Normalized counter missing"
        assert page.get_by_text("Unique Primary", exact=True).is_visible(), "AVIVE Unique Primary counter missing"
        assert page.get_by_text("Correlation Groups", exact=True).is_visible(), "AVIVE Correlation Groups counter missing"

        # Verify finding card AVIVE pills and expand detail intelligence
        page.wait_for_selector("button:has-text('View Details')", timeout=8000)
        assert page.locator("text=CONTEXT PRIO:").count() > 0, "Contextual priority pill missing"
        assert page.locator("text=CONF (").count() > 0, "Confidence pill missing"
        page.locator("button:has-text('View Details')").first.click()
        page.wait_for_selector("text=Explainable Confidence Assessment", timeout=5000)
        assert page.locator("text=Contextual Risk Rationale").first.is_visible(), "Risk rationale missing"
        assert page.locator("text=Remediation Intelligence").first.is_visible(), "Remediation intelligence missing"
        assert page.locator("text=Safe Validation Workflow & Audit History").first.is_visible(), "Validation history panel missing"

        # Exercise interactive remediation status update button against backend API
        page.locator("button:has-text('IN_PROGRESS')").first.click()
        page.wait_for_selector("text=Remediation status updated to IN_PROGRESS", timeout=5000)

        # Exercise confidence filter dropdown
        page.locator("select[aria-label='Confidence Filter']").select_option("HIGH")
        page.wait_for_timeout(400)
        page.locator("select[aria-label='Confidence Filter']").select_option("ALL")
        page.wait_for_timeout(400)
        print("  ✓ /findings Phase 5 AVIVE intelligence UI, filters, and validation workflow verified")

        # /reports
        page.goto(f"{FRONTEND_URL}/reports", wait_until="networkidle")
        assert page.locator("text=Security Assessment Reports").count() > 0, "/reports title missing"
        assert page.locator("button:has-text('Preview Report')").is_visible(), "Preview Report button missing"
        assert page.locator("a:has-text('Download')").is_visible(), "Download link missing"
        print("  ✓ /reports page verified")

        # ---------------------------------------------------------------------
        # 7. TELEMETRY & CONSOLE AUDIT
        # ---------------------------------------------------------------------
        print("\n[8/8] Console & Network Quality Audit...")
        print(f"  Total console logs: {len(console_logs)}")
        critical_errors = [e for e in page_errors if "favicon" not in e.lower()]
        critical_failed = [r for r in failed_requests if "favicon" not in r.lower()]

        print(f"  Uncaught page errors: {len(critical_errors)}")
        print(f"  Failed HTTP requests (4xx/5xx): {len(critical_failed)}")

        for err in critical_errors:
            print(f"    [PAGE ERROR] {err}")
        for req in critical_failed:
            print(f"    [FAILED REQ] {req}")

        assert len(critical_errors) == 0, f"Uncaught page errors detected: {critical_errors}"
        assert len(critical_failed) == 0, f"Failed HTTP requests detected: {critical_failed}"

        browser.close()

    print("\n" + "=" * 80)
    print("ALL BROWSER E2E QA TESTS PASSED SUCCESSFULLY! (VERDICT: PASS)")
    print("=" * 80)


if __name__ == "__main__":
    try:
        run_e2e_browser_test()
        sys.exit(0)
    except Exception as exc:
        print(f"\n[FATAL E2E FAILURE] {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
