# Website Security Inspector

A defensive security tool for checking an organisation's website posture and analysing authentication logs. Built as Module Four.

---

## Quick Start

```bash
# Install dependencies
npm install

# Start the server (No-API mode — no API keys needed)
npm start
# → http://localhost:3000

# Run tests
npm test
```

---

## Architecture

```
.
├── backend/
│   ├── server.js              # Express server (all network activity)
│   ├── safe-fetch/            # Shared SSRF-safe fetch module (reusable)
│   │   └── index.js
│   └── checks/
│       ├── posture.js         # Orchestrates all posture checks
│       ├── dns.js             # DNS + email security record checks
│       ├── headers.js         # HTTP security header evaluation
│       ├── tls.js             # TLS certificate check
│       ├── reputation.js      # Domain reputation adapters
│       └── rate-limit.js      # Per-client rate limiting + concurrency
├── frontend/
│   ├── index.html             # Single-page UI (two tabs)
│   ├── style.css              # Light/dark-aware, responsive, accessible
│   ├── app.js                 # Frontend logic (no eval, all output escaped)
│   └── log-worker.js          # Web Worker: log parsing + detection rules
├── fixtures/
│   ├── demo-posture.json      # Synthetic DNS/TLS/header results (No-API demo)
│   ├── reputation-demo.json   # Synthetic reputation data
│   └── sample-auth.log.csv    # Synthetic auth log (clearly labeled)
└── tests/
    ├── safe-fetch.test.js     # IP classification, URL validation
    ├── redirect.test.js       # Redirect revalidation, SSRF blocking
    ├── spf-dmarc.test.js      # SPF + DMARC parsing
    ├── headers.test.js        # HTTP header evaluation
    ├── tls.test.js            # TLS result handling (mocked)
    ├── auth-gate.test.js      # Authorization gate enforcement
    └── log-analysis.test.js   # Log normalization + detection rules
```

The browser **never contacts the target** — all DNS, TLS, and HTTP activity runs server-side. Log analysis runs in the browser by default (Web Worker + File API); logs never leave the device.

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

```bash
PORT=3000
# Optional: enables real reputation lookups.
# Without these, the tool runs in No-API mode with clearly labeled SYNTHETIC demo data.
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
ALLOWED_ORIGINS=http://localhost:3000
```

### No-API Mode

If no API keys are configured, reputation checks return clearly labeled **SYNTHETIC demo data** from `fixtures/reputation-demo.json` — no network contact is made for demo entries, and the UI displays a prominent "SYNTHETIC demo data" label.

---

## Section A: Website Posture Check

### Check Tiers

| Tier | Name | Authorization | Target Contact | Max Requests |
|------|------|---------------|---------------|-------------|
| 0 | Passive | Not required | **None** (DNS only) | 0 |
| 1 | Low-impact active | **Required** | Yes | 6 |

### Tier 0 Checks (always available)
- URL and hostname validation (scheme, length, credentials, port, IP-literal rejection)
- Public DNS records (A, AAAA, NS, MX, TXT, CAA, DNSSEC presence)
- Email security records (SPF, DMARC, MTA-STS, TLS-RPT, BIMI, optional DKIM)
- Domain reputation via configured providers (hostname only — never contacts target)

### Tier 1 Checks (authorization confirmation required)
1. One TLS handshake (cert subject/SAN, issuer, expiry, protocol, cipher)
2. One HTTPS GET of the supplied URL (security headers from response)
3. One HTTP HEAD to observe HTTPS redirect
4. One GET of `/.well-known/security.txt`
5. One GET of `/robots.txt`

**Maximum 6 requests per run. Documented in the UI.**

### Out of Scope (never implemented)
Port scanning, directory/path brute-forcing, vulnerability exploitation, credential testing, form submission, crawling beyond the above, load testing, login endpoint probing.

### Authorization Gate
Before any Tier 1 check, the user must:
1. Tick a checkbox confirming they own or are authorised to assess the site.
2. The confirmation timestamp is included in the report (identity is not logged).
3. Without confirmation, Tier 1 checks remain server-side gated — they are not merely hidden in the UI.

---

## Section B: Authentication Log Analysis

### Purpose
Detect anomalous patterns in administrator-supplied authentication logs. The analysis runs entirely in the browser via a Web Worker; logs never leave the device unless you explicitly enable server mode.

### Formats Supported
CSV, JSON, NDJSON, OpenSSH `auth.log` style, `key=value` lines.

### Detection Rules

| Rule ID | Name | Default Threshold |
|---------|------|-------------------|
| RULE-01-A | Repeated failed logins (per account) | 5 failures / 10 min |
| RULE-01-I | Repeated failed logins (per source IP) | 5 failures / 10 min |
| RULE-02 | Success after repeated failures | 3 failures / 15 min |
| RULE-03 | Unusual login frequency | > 30 logins/hour |
| RULE-04-A | Spray-like pattern (one IP, many accounts) | 5 accounts / 5 min |
| RULE-04-B | Multi-account success from one IP | 4 accounts / 10 min |
| RULE-05 | New source IP (baseline comparison) | Requires ≥ 14 days & ≥ 20 events |

All thresholds are configurable in the UI.

### Output Structure
Every match has two clearly separated blocks:
- **Observed Facts** — directly present in the logs (counts, timestamps, values)
- **Inferred Suspicious Behavior (hypothesis, not proof)** — interpretation plus confidence and plain-language alternative explanations

Wording: "matches pattern consistent with…" — never "attack confirmed" or "account compromised."

### Important Limitations
- A website URL alone **cannot show whether unauthorized logins occurred**.
- Log analysis detects patterns, not intent.
- Results depend on log completeness, accuracy, and sanitization.
- Upload only sanitized logs (remove passwords, tokens, session IDs, unnecessary personal data).

---

## SSRF and Network Safety

All outbound network requests are made by the backend through the shared `safe-fetch` module:

- Hostnames are resolved server-side; all A/AAAA answers are validated.
- **Rejected ranges:** loopback, RFC1918, link-local (including 169.254.169.254), CGNAT (100.64/10), multicast, unspecified, ULA IPv6, IPv4-mapped non-public, documentation ranges.
- **DNS rebinding defence:** the validated IP is pinned; all connections use it with the correct Host header and SNI.
- **Redirects:** followed manually, max 5 hops; every hop revalidates the DNS result; HTTPS→HTTP downgrades are blocked; cross-domain hops are flagged.
- **Timeouts:** connect 3s, total 8s.
- **Response body cap:** 64 KB; remainder discarded.
- No cookies, no auth headers, fixed identifying User-Agent.
- Per-client rate limiting: one scan per target per minute, max 3 concurrent scans.

---

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| SSRF via user-supplied URL | `safe-fetch` rejects all non-public IPs; pinned IP connection |
| DNS rebinding | IP pinned after validation; never re-resolved mid-request |
| HTTPS→HTTP downgrade via redirect | Redirect follower explicitly blocks this |
| XSS via untrusted header/cert/DNS values | All values escaped before DOM insertion; strict CSP |
| Oversized responses | 64 KB cap; body discarded after limit |
| DoS via repeated scans | Per-target, per-client rate limit; concurrency cap |
| Log data exfiltration | Log analysis runs in Web Worker (browser only); no server transmission |
| Credential exposure | No form submissions, no auth headers forwarded, no login endpoint contact |
| Eval-based injection | No `eval()` anywhere in the codebase |

---

## Limitations

- **Passive checks are a point-in-time snapshot.** Configuration may change at any time.
- **Reputation data is not a compromise test.** Absence from a blocklist does not mean a site is safe or uncompromised.
- **Header and DNS checks cannot detect a breach.** A site can have perfect headers and still be compromised.
- **Log analysis detects patterns, not intent.** Every match has alternative benign explanations (e.g., user forgot password, shared NAT, load test traffic).
- **Results depend on log completeness and sanitization.** Missing or manipulated logs produce incomplete or misleading results.
- **This tool never brute-forces, exploits, bypasses authentication, or submits credentials.**
- **DKIM selectors are never guessed.** Only checked if the user supplies a selector.
- **Tier 1 sends at most 6 requests.** No crawling or additional probing is performed.

---

## Running Tests

```bash
npm test
# or with coverage:
npm run test:coverage
```

Tests cover:
- IPv4/IPv6/mapped IP classification
- SSRF blocking (private-IP DNS mock)
- Redirect revalidation and HTTPS→HTTP downgrade blocking
- Response body cap constant
- SPF and DMARC parsing (all severity levels)
- HTTP security header evaluation
- TLS result handling (mocked handshake)
- Authorization gate enforcement (Tier 1 server-side rejection)
- Log normalization (outcome, timestamp, timezone, truncation)
- Detection rules 1–5 (including insufficient-baseline case)
- Fact vs. inference separation

---

## Development

```bash
# Auto-restart on file changes
npm run dev
```

Requires Node.js ≥ 18.

---

## Disclaimer

This tool is for **defensive use only** — assessing configuration you own or are explicitly authorised to assess. It must not be used for offensive security testing, brute-forcing, exploitation, or any unauthorised access.
