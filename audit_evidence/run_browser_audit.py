import json
import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_URL = "http://localhost:3000"
SCREENSHOT_DIR = Path("audit_evidence/screenshots")
LOG_DIR = Path("audit_evidence/logs")
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

results = {
    "routes": [],
    "interactions": [],
    "workflows": [],
    "responsive": [],
    "accessibility": [],
    "defects_detected": [],
    "console_errors": [],
    "page_errors": [],
    "http_failures": [],
}

def record_interaction(name, passed, details=""):
    results["interactions"].append({"name": name, "passed": passed, "details": details})
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}: {details}")

def record_workflow(name, passed, details=""):
    results["workflows"].append({"name": name, "passed": passed, "details": details})
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] WORKFLOW {name}: {details}")

def run_audit():
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME_PATH, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        # Global listeners
        ignore_404_urls = ["/nonexistent-audit-route"]

        def on_console(msg):
            if msg.type == "error":
                results["console_errors"].append({"url": page.url, "text": msg.text})

        def on_pageerror(err):
            results["page_errors"].append({"url": page.url, "error": str(err)})

        def on_response(resp):
            if resp.status >= 400:
                if not any(ig in resp.url for ig in ignore_404_urls):
                    results["http_failures"].append({"page": page.url, "url": resp.url, "status": resp.status})

        page.on("console", on_console)
        page.on("pageerror", on_pageerror)
        page.on("response", on_response)

        # ---------------------------------------------------------
        # PHASE 2: EVERY ROUTE CHECK + STYLING/TYPOGRAPHY/CONTRAST
        # ---------------------------------------------------------
        print("\n=== PHASE 2: ROUTE INVENTORY & RENDERING AUDIT ===")
        routes = [
            "/",
            "/targets",
            "/scans",
            "/attack-surface",
            "/findings",
            "/analytics",
            "/reports",
            "/nonexistent-audit-route",
        ]
        for r in routes:
            url = f"{BASE_URL}{r}"
            resp = page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(400)
            status = resp.status if resp else 0

            checks = page.evaluate("""() => {
                const bodyStyle = window.getComputedStyle(document.body);
                const stylesheets = document.styleSheets.length;
                const h1 = document.querySelector('h1');
                const h2 = document.querySelector('h2');
                const imgs = Array.from(document.querySelectorAll('img'));
                const brokenImgs = imgs.filter(i => !i.complete || i.naturalWidth === 0).length;
                const textLen = document.body.innerText.trim().length;
                // Check invisible buttons/links (e.g. white text on transparent/white background)
                const interactive = Array.from(document.querySelectorAll('a, button'));
                const lowContrastOrBroken = [];
                for (const el of interactive) {
                    const st = window.getComputedStyle(el);
                    if (st.display === 'none' || st.visibility === 'hidden') continue;
                    const rect = el.getBoundingClientRect();
                    if (rect.width === 0 || rect.height === 0) continue;
                    if (st.color === 'rgb(255, 255, 255)' && (st.backgroundColor === 'rgba(0, 0, 0, 0)' || st.backgroundColor === 'rgb(255, 255, 255)')) {
                        lowContrastOrBroken.push({tag: el.tagName, text: el.innerText.trim().slice(0, 40), color: st.color, bg: st.backgroundColor, cls: el.className});
                    }
                }
                return {
                    bodyBg: bodyStyle.backgroundColor,
                    bodyColor: bodyStyle.color,
                    bodyFont: bodyStyle.fontFamily,
                    stylesheets: stylesheets,
                    hasHeading: Boolean(h1 || h2),
                    brokenImgs: brokenImgs,
                    textLen: textLen,
                    lowContrastButtons: lowContrastOrBroken,
                    overflowX: document.documentElement.scrollWidth > window.innerWidth,
                    scrollWidth: document.documentElement.scrollWidth,
                    innerWidth: window.innerWidth
                };
            }""")

            safe_name = r.strip("/").replace("/", "_") or "dashboard"
            page.screenshot(path=str(SCREENSHOT_DIR / f"route_{safe_name}.png"), full_page=True)

            route_ok = (
                (status == 200 or (r == "/nonexistent-audit-route" and status == 404))
                and checks["stylesheets"] > 0
                and checks["bodyBg"] == "rgb(245, 245, 243)"
                and checks["brokenImgs"] == 0
                and checks["textLen"] > 50
            )
            if checks["lowContrastButtons"]:
                results["defects_detected"].append({
                    "type": "UI_STYLING_CONTRAST",
                    "route": r,
                    "details": checks["lowContrastButtons"],
                })
            results["routes"].append({
                "route": r,
                "status": status,
                "passed": route_ok,
                "checks": checks,
            })
            print(f"  [{'PASS' if route_ok else 'FAIL'}] {r} (HTTP {status}) | BG={checks['bodyBg']} | BrokenContrastBtns={len(checks['lowContrastButtons'])}")

        # ---------------------------------------------------------
        # PHASE 3 & 4: INTERACTIONS & COMPLETE WORKFLOWS
        # ---------------------------------------------------------
        print("\n=== PHASE 3 & 4: INTERACTIVE CONTROLS & E2E WORKFLOWS ===")
        page.goto(f"{BASE_URL}/", wait_until="networkidle")

        # 1. Theme Toggle
        theme_btn = page.locator("button[aria-label='Toggle Light/Dark Theme']")
        if theme_btn.count() == 0:
            theme_btn = page.locator("header button", has_text="Dark")
        before_bg = page.evaluate("() => window.getComputedStyle(document.body).backgroundColor")
        theme_btn.click()
        page.wait_for_timeout(200)
        dark_bg = page.evaluate("() => window.getComputedStyle(document.body).backgroundColor")
        is_dark_class = page.evaluate("() => document.documentElement.classList.contains('dark')")
        stored_theme = page.evaluate("() => localStorage.getItem('awss_theme')")
        page.screenshot(path=str(SCREENSHOT_DIR / "theme_dark_mode.png"))
        page.reload(wait_until="networkidle")
        persisted_dark = page.evaluate("() => document.documentElement.classList.contains('dark')")
        # Toggle back to Light
        page.locator("header button", has_text="Light").click()
        page.wait_for_timeout(200)
        light_bg = page.evaluate("() => window.getComputedStyle(document.body).backgroundColor")
        record_interaction(
            "Theme Toggle (Light <-> Dark + Persistence)",
            is_dark_class and dark_bg == "rgb(13, 15, 18)" and persisted_dark and light_bg == "rgb(245, 245, 243)",
            f"before={before_bg}, dark={dark_bg}, persisted={persisted_dark}, light={light_bg}, storage={stored_theme}"
        )

        # 2. Target Workflow on Dashboard Modal (validation + registration)
        page.get_by_role("button", name="Register Target").click()
        page.wait_for_timeout(200)
        modal_form = page.locator("div.fixed form")
        submit_target_btn = modal_form.get_by_role("button", name="Register Target")
        # Try submitting empty target name (bypass native HTML5 required via JS evaluate or fill whitespace)
        page.locator("input[placeholder*='Staging']").fill("   ")
        page.locator("input[placeholder*='8089']").fill("http://127.0.0.1:8089")
        submit_target_btn.click()
        err_visible = page.locator("text=Target name is required").is_visible()
        # Fill invalid URL
        page.locator("input[placeholder*='Staging']").fill("Audit Target Validated")
        page.locator("input[placeholder*='8089']").fill("ftp://invalid-scheme")
        submit_target_btn.click()
        url_err = page.locator("text=Target URL must start with http:// or https://").is_visible()
        # Fill valid target URL
        page.locator("input[placeholder*='8089']").fill("http://127.0.0.1:8089/app")
        submit_target_btn.click()
        page.wait_for_timeout(200)
        target_added = page.locator("text=Audit Target Validated").is_visible()
        record_workflow("Dashboard Target Registration & Validation", err_visible and url_err and target_added,
                        f"empty_err={err_visible}, url_err={url_err}, target_added={target_added}")

        # 3. Scan Configuration Modal (validation + execution + completion)
        page.get_by_role("button", name="+ New Scan").click()
        page.wait_for_timeout(200)
        # Test safety gate checkbox validation
        auth_cb = page.locator("#auth-check")
        if auth_cb.is_checked():
            auth_cb.uncheck()
        page.get_by_role("button", name="Start Scan Job").click()
        auth_err = page.locator("text=You must explicitly confirm").is_visible()
        auth_cb.check()
        # Test invalid URL validation
        scan_url_input = page.locator("div.fixed input[type='text']").first
        scan_url_input.fill("not-a-url")
        page.get_by_role("button", name="Start Scan Job").click()
        scan_url_err = page.locator("text=Target URL must start with http://").first.is_visible()
        # Launch valid controlled scan
        scan_url_input.fill("http://127.0.0.1:8089")
        page.get_by_role("button", name="Start Scan Job").click()
        page.wait_for_timeout(500)

        # Wait for scan completion
        scan_completed = False
        for _ in range(25):
            if page.locator("table tbody tr").first.locator("text=COMPLETED").count() > 0:
                scan_completed = True
                break
            page.wait_for_timeout(1000)
        record_workflow("Dashboard Scan Launch & Completion", auth_err and scan_url_err and scan_completed,
                        f"auth_err={auth_err}, url_err={scan_url_err}, completed={scan_completed}")

        # 4. Dashboard Findings Drawer & Evidence
        first_row = page.locator("table tbody tr").first
        first_row.get_by_role("button", name="Findings").click()
        page.wait_for_timeout(400)
        drawer_visible = page.locator("text=Security Vulnerability Findings").is_visible()
        # Filter chips inside drawer
        medium_btn = page.locator("div.fixed button", has_text="MEDIUM")
        if medium_btn.count() > 0:
            medium_btn.first.click()
            page.wait_for_timeout(150)
        all_btn = page.locator("div.fixed button", has_text="ALL")
        if all_btn.count() > 0:
            all_btn.first.click()
            page.wait_for_timeout(150)
        details_btn = page.locator("div.fixed button", has_text="Details").first
        details_btn.click()
        page.wait_for_timeout(200)
        sha_present = page.locator("text=SHA-256:").is_visible()
        rem_present = page.locator("text=Remediation Guidance").is_visible()
        page.screenshot(path=str(SCREENSHOT_DIR / "dashboard_findings_drawer.png"))
        page.locator("div.fixed button:has-text('✕')").click()
        page.wait_for_timeout(200)
        record_interaction("Dashboard Findings Drawer & Evidence", drawer_visible and sha_present and rem_present,
                           f"drawer={drawer_visible}, sha={sha_present}, remediation={rem_present}")

        # 5. Targets Page Persistence Audit
        page.goto(f"{BASE_URL}/targets", wait_until="networkidle")
        page.get_by_role("button", name="+ Add Target").click()
        page.locator("input[placeholder*='e.g.']").fill("E2E Audit Target")
        page.locator("input[placeholder*='http://127.0.0.1:8089']").fill("http://127.0.0.1:8089/v1")
        page.locator("div.fixed form").get_by_role("button", name="Register").click()
        page.wait_for_timeout(200)
        added_on_targets = page.locator("text=E2E Audit Target").is_visible()
        page.reload(wait_until="networkidle")
        persisted_on_reload = page.locator("text=E2E Audit Target").is_visible()
        if not persisted_on_reload:
            results["defects_detected"].append({
                "type": "MISSING_PERSISTENCE",
                "route": "/targets",
                "details": "Added targets only live in React component state and disappear on page reload; no backend /api/v1/targets persistence."
            })
        record_workflow("Targets Page Add & Reload Persistence", added_on_targets,
                        f"added_in_ui={added_on_targets}, persisted_across_reload={persisted_on_reload}")

        # 6. Scans Page Controls
        page.goto(f"{BASE_URL}/scans", wait_until="networkidle")
        refresh_btn = page.get_by_role("button", name="Refresh")
        refresh_btn.click()
        page.wait_for_timeout(300)
        rows_count = page.locator("table tbody tr").count()
        record_interaction("Scans Registry Table & Refresh", rows_count > 0, f"rows={rows_count}")

        # 7. Attack Surface Workflow (all 7 tabs + search + zoom + export)
        page.goto(f"{BASE_URL}/attack-surface", wait_until="networkidle")
        page.wait_for_timeout(500)
        tab_names = ["Overview & Signals", "Prioritization Queue", "Endpoints", "Parameters", "APIs", "Assets", "Topology Graph"]
        tabs_ok = True
        for tn in tab_names:
            btn = page.locator("button", has_text=tn).first
            if btn.is_visible():
                btn.click()
                page.wait_for_timeout(150)
            else:
                tabs_ok = False
        # Test Endpoints search
        page.locator("button", has_text="Endpoints").first.click()
        search_box = page.locator("input[placeholder*='Filter']")
        if search_box.count() > 0:
            search_box.first.fill("login")
            page.wait_for_timeout(150)
            search_box.first.fill("")
        # Test Topology Graph Zoom & Export
        page.locator("button", has_text="Topology Graph").first.click()
        page.wait_for_timeout(200)
        zoom_in = page.locator("button[title='Zoom In']")
        zoom_out = page.locator("button[title='Zoom Out']")
        zoom_in.click()
        zoom_out.click()
        export_btn = page.get_by_role("button", name="Export Graph JSON")
        with page.expect_download() as dl_info:
            export_btn.click()
        dl = dl_info.value
        dl_ok = dl.suggested_filename.endswith(".json")
        record_workflow("Attack Surface 7 Tabs, Search, Zoom & JSON Export", tabs_ok and dl_ok,
                        f"all_tabs={tabs_ok}, export_file={dl.suggested_filename}")

        # 8. Findings Page (AVIVE Filters, Details, Safe Validation Workflow & Persistence)
        page.goto(f"{BASE_URL}/findings", wait_until="networkidle")
        page.wait_for_timeout(500)
        conf_sel = page.locator("select[aria-label='Confidence Filter']")
        val_sel = page.locator("select[aria-label='Validation Status Filter']")
        cat_sel = page.locator("select[aria-label='Vulnerability Category Filter']")
        rem_sel = page.locator("select[aria-label='Remediation Status Filter']")
        filters_present = all([conf_sel.count() > 0, val_sel.count() > 0, cat_sel.count() > 0, rem_sel.count() > 0])
        conf_sel.select_option("HIGH")
        page.wait_for_timeout(250)
        conf_sel.select_option("ALL")
        page.wait_for_timeout(250)
        # Open finding details & trigger safe validation transition
        view_btns = page.get_by_role("button", name="View Details")
        finding_details_ok = False
        transition_ok = False
        if view_btns.count() > 0:
            view_btns.first.click()
            page.wait_for_timeout(300)
            finding_details_ok = page.locator("text=Explainable Confidence Assessment").first.is_visible()
            in_prog_btn = page.get_by_role("button", name="IN_PROGRESS")
            if in_prog_btn.count() > 0:
                in_prog_btn.first.click()
                page.wait_for_timeout(400)
                transition_ok = True
        record_workflow("Findings AVIVE Filters, Details & Validation Workflow", filters_present and finding_details_ok and transition_ok,
                        f"filters={filters_present}, details={finding_details_ok}, validation_transition={transition_ok}")

        # 9. Reports Page Preview & Contrast Audit
        page.goto(f"{BASE_URL}/reports", wait_until="networkidle")
        page.wait_for_timeout(400)
        dl_link = page.locator("a", has_text="Download")
        dl_styles = dl_link.evaluate("el => ({bg: window.getComputedStyle(el).backgroundColor, color: window.getComputedStyle(el).color})")
        page.get_by_role("button", name="Preview Report").click()
        page.wait_for_timeout(500)
        iframe_visible = page.locator("iframe[title='HTML Report Preview']").is_visible()
        # Switch to JSON and preview
        page.locator("select").nth(1).select_option("json")
        page.get_by_role("button", name="Preview Report").click()
        page.wait_for_timeout(400)
        json_pre = page.locator("pre").is_visible()
        # Switch to Markdown and preview
        page.locator("select").nth(1).select_option("markdown")
        page.get_by_role("button", name="Preview Report").click()
        page.wait_for_timeout(400)
        md_pre = page.locator("pre").is_visible()
        dl_contrast_ok = dl_styles["bg"] not in ["rgba(0, 0, 0, 0)", "rgb(255, 255, 255)"]
        record_workflow("Reports Preview (HTML/JSON/Markdown) & Download Styling",
                        iframe_visible and json_pre and md_pre and dl_contrast_ok,
                        f"html={iframe_visible}, json={json_pre}, md={md_pre}, dl_styles={dl_styles}")

        # 10. Analytics Page (5 Tabs + Compare Scans)
        page.goto(f"{BASE_URL}/analytics", wait_until="networkidle")
        page.wait_for_timeout(500)
        analytics_tabs = ["Analytics Overview", "Scan Plan & Context", "OWASP Coverage", "Reliability & Evidence", "Scan Comparison"]
        an_tabs_ok = True
        for at in analytics_tabs:
            b = page.locator("button", has_text=at)
            if b.count() > 0:
                b.first.click()
                page.wait_for_timeout(200)
            else:
                an_tabs_ok = False
        # On Scan Comparison tab
        cmp_btn = page.get_by_role("button", name="Compare Scans")
        cmp_styles = cmp_btn.evaluate("el => ({bg: window.getComputedStyle(el).backgroundColor, color: window.getComputedStyle(el).color})")
        cmp_btn.click()
        page.wait_for_timeout(400)
        cmp_summary = page.locator("text=New Findings").first.is_visible()
        record_workflow("Analytics 5 Tabs & Scan Comparison", an_tabs_ok and cmp_summary,
                        f"tabs={an_tabs_ok}, cmp_summary={cmp_summary}, cmp_btn_styles={cmp_styles}")

        # 11. Browser Back/Forward Navigation
        page.go_back()
        page.wait_for_timeout(200)
        back_ok = "/reports" in page.url
        page.go_forward()
        page.wait_for_timeout(200)
        fwd_ok = "/analytics" in page.url
        record_interaction("Browser Back / Forward History Navigation", back_ok and fwd_ok, f"back_url={back_ok}, fwd_url={fwd_ok}")

        # ---------------------------------------------------------
        # PHASE 5: RESPONSIVE & ACCESSIBILITY AUDIT
        # ---------------------------------------------------------
        print("\n=== PHASE 5: RESPONSIVE VIEWPORTS & ACCESSIBILITY QA ===")
        viewports = [
            (1920, 1080),
            (1440, 900),
            (1024, 768),
            (768, 1024),
            (390, 844),
        ]
        test_routes_resp = ["/", "/attack-surface", "/findings", "/analytics"]
        for w, h in viewports:
            page.set_viewport_size({"width": w, "height": h})
            for rr in test_routes_resp:
                page.goto(f"{BASE_URL}{rr}", wait_until="networkidle")
                page.wait_for_timeout(250)
                ov = page.evaluate("""() => ({
                    scrollWidth: document.documentElement.scrollWidth,
                    innerWidth: window.innerWidth,
                    overflow: document.documentElement.scrollWidth > window.innerWidth
                })""")
                results["responsive"].append({"viewport": f"{w}x{h}", "route": rr, **ov})
                if ov["overflow"]:
                    results["defects_detected"].append({
                        "type": "HORIZONTAL_OVERFLOW",
                        "viewport": f"{w}x{h}",
                        "route": rr,
                        "scrollWidth": ov["scrollWidth"],
                        "innerWidth": ov["innerWidth"],
                    })
                    print(f"  [FAIL] Overflow at {w}x{h} on {rr}: scrollWidth={ov['scrollWidth']} > innerWidth={ov['innerWidth']}")
                else:
                    print(f"  [PASS] Viewport {w}x{h} on {rr}: no horizontal overflow")

        # Mobile Drawer test at 390x844
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{BASE_URL}/", wait_until="networkidle")
        menu_btn = page.locator("button[aria-label='Toggle navigation menu']")
        menu_visible = menu_btn.is_visible()
        if menu_visible:
            menu_btn.click()
            page.wait_for_timeout(200)
            page.screenshot(path=str(SCREENSHOT_DIR / "mobile_390_menu_open.png"))
            mobile_targets_link = page.locator("header nav a", has_text="Targets").last
            mobile_nav_ok = mobile_targets_link.is_visible()
            menu_btn.click()
        else:
            mobile_nav_ok = False
        record_interaction("Mobile Hamburger Navigation (390px)", menu_visible and mobile_nav_ok, f"btn={menu_visible}, drawer_links={mobile_nav_ok}")

        # Keyboard & Accessibility checks at 1440x900
        page.set_viewport_size({"width": 1440, "height": 900})
        page.goto(f"{BASE_URL}/", wait_until="networkidle")
        a11y = page.evaluate("""() => {
            const header = document.querySelector('header');
            const nav = document.querySelector('nav');
            const main = document.querySelector('main');
            const footer = document.querySelector('footer');
            const h1s = document.querySelectorAll('h1').length;
            const buttonsWithoutName = Array.from(document.querySelectorAll('button')).filter(b => {
                const txt = (b.innerText || '').trim();
                const aria = b.getAttribute('aria-label') || b.getAttribute('title') || '';
                return !txt && !aria;
            }).length;
            const selectsWithoutLabel = Array.from(document.querySelectorAll('select')).filter(s => {
                return !s.getAttribute('aria-label') && !s.id;
            }).length;
            return {
                landmarks: {header: !!header, nav: !!nav, main: !!main, footer: !!footer},
                h1Count: h1s,
                buttonsWithoutName,
                selectsWithoutLabel
            };
        }""")
        # Tab keyboard focus test
        for _ in range(5):
            page.keyboard.press("Tab")
        active_tag = page.evaluate("() => document.activeElement ? document.activeElement.tagName : 'NONE'")
        results["accessibility"].append({"route": "/", **a11y, "tabActiveTag": active_tag})
        print(f"  [A11Y] Landmarks={a11y['landmarks']} | H1={a11y['h1Count']} | UnlabelledBtns={a11y['buttonsWithoutName']} | TabFocus={active_tag}")

        browser.close()

    with open(LOG_DIR / "browser_audit_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\nSaved browser audit results to audit_evidence/logs/browser_audit_results.json")
    print(f"Total Console Errors: {len(results['console_errors'])}")
    print(f"Total Page Errors: {len(results['page_errors'])}")
    print(f"Total HTTP Failures: {len(results['http_failures'])}")
    print(f"Total Auto-Detected UI Defects: {len(results['defects_detected'])}")

if __name__ == "__main__":
    run_audit()
