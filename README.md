# Cloudflare WAF & DDoS Protection Tester

A comprehensive security testing tool for evaluating Cloudflare WAF configurations and DDoS protection mechanisms.

**Project Direction:** This WAF tester is being folded into the larger
[GCP lab consolidation effort](https://github.com/Dgilmore-CF/gcp-lab-consolidation).
This repository remains the source for the tester and isolated executor; the
consolidated lab provides infrastructure, orchestration, and dashboard controls.

⚠️ **WARNING: This tool is intended for authorized security testing only. Only use against systems you own or have explicit written permission to test. Unauthorized use may violate computer crime laws.**

## Features

### DDoS Protection Testing
- **Volumetric Attacks**: UDP Flood, ICMP Flood, DNS/NTP Amplification simulations
- **Protocol Attacks**: SYN Flood, SYN-ACK Flood, ACK Flood, RST Flood, Fragmentation
- **Application Layer Attacks**: HTTP GET/POST Flood, Slowloris, RUDY, Cache Bypass
- **Multi-Vector Attacks**: Combined attack simulations

### WAF Ruleset Testing
- **Cloudflare OWASP Core Ruleset**: Tests based on OWASP ModSecurity CRS
- **Cloudflare Managed Ruleset**: Tests for Cloudflare-specific protections
- **Attack Categories**:
  - SQL Injection (20+ payloads)
  - Cross-Site Scripting (20+ payloads)
  - Command Injection
  - Path Traversal / LFI
  - XML External Entity (XXE)
  - Server-Side Request Forgery (SSRF)
  - Server-Side Template Injection (SSTI)
  - Log4Shell / Log4j
  - Prototype Pollution
  - And more...

### HTTP Request Engines
| Engine | Description | Best For |
|--------|-------------|----------|
| `aiohttp` | Async HTTP client | Fast, high-volume testing |
| `httpx` | Modern async HTTP with HTTP/2 | Modern protocol support |
| `requests` | Synchronous HTTP | Simple testing |
| `selenium` | Browser automation | JS challenge bypass |
| `playwright` | Modern browser automation | JS challenge bypass |
| `curl_cffi` | curl with browser impersonation | TLS fingerprint bypass |
| `go-http` | Go HTTP client | Alternative fingerprint |

### Cloudflare Bypass Techniques
- User-Agent rotation
- Header manipulation
- Multiple encoding methods (URL, Base64, Unicode, etc.)
- TLS fingerprint manipulation
- Cache bypass techniques
- Rate limit evasion testing
- Origin IP discovery checks

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cf-tester.git
cd cf-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# For Playwright browser automation
playwright install chromium

# For Selenium (requires Chrome/ChromeDriver)
# Ensure chromedriver is in your PATH
```

## Usage

### Restricted WAF Lab

For bounded, plan-first WAF probes with per-run host/base-path scope, digest-bound
approval, read-only Cloudflare evidence, and a restricted OpenCode agent, see
[WAF Lab](docs/WAF_LAB.md). This workflow is separate from the CLI below; it
does not expose DDoS/bypass tools or promise universal rule coverage. Low-impact
probes are not harmless on vulnerable origins; use only authorized targets.

### Interactive Mode

```bash
python cf_waf_tester.py
```

This will guide you through:
1. Authorization confirmation
2. Test type selection (DDoS, WAF, or Combined)
3. Target hostname(s)
4. HTTP engine selection
5. Bypass technique options
6. Attack type selection (for DDoS)
7. Ruleset selection (for WAF)

### Command Line Mode

#### WAF Testing Only
```bash
python cf_waf_tester.py \
    --targets example.com \
    --waf-only \
    --waf-ruleset owasp \
    --engine aiohttp \
    --accept-responsibility
```

#### DDoS Testing Only
```bash
python cf_waf_tester.py \
    --targets example.com \
    --ddos-only \
    --ddos-type 10 \
    --requests 1000 \
    --concurrency 20 \
    --accept-responsibility
```

#### Automatic Redirects

The regular CLI follows 301/302/303/307/308 redirects automatically by default,
including cross-host redirects, without destination-by-destination prompts. The
non-browser engines honor a five-hop limit; redirect loops or a longer chain
produce a transport error instead of continuing indefinitely. TLS verification
remains enabled. Only use this mode when your authorization covers the redirect
destinations as well as the starting URL.

`--follow-redirects` explicitly enables the default; `--no-follow-redirects`
returns the original response without following it. `--max-redirects N` sets a
positive hop limit. These controls work with `aiohttp`, `httpx`, `requests`,
`curl_cffi`, and `go-http`. Browser engines retain their native navigation behavior
and reject unsupported custom redirect controls.

HTTP adapter responses retain the final URL and redirect count; saved WAF result
reports do not yet include those fields. A redirect can discard a query
or change POST to GET; a successful final response does not prove the original
payload reached that destination or that a managed WAF rule evaluated it.

At the hop boundary, aiohttp can also report a redirect-limit error for a terminal
3xx response without a `Location` header. It stops conservatively rather than
issuing an additional request.

This does **not** change the restricted WAF lab: its `waf_lab_*` tools still
require exact reviewed conditional requests before following any redirect. The
regular CLI is not an alternative execution backend for those approved plans.

#### Full Testing with Bypass Techniques
```bash
python cf_waf_tester.py \
    --targets example.com,api.example.com \
    --bypass \
    --engine curl_cffi \
    --requests 500 \
    --accept-responsibility
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-t, --targets` | Comma-separated target hostnames |
| `-e, --engine` | HTTP engine (aiohttp, httpx, requests, selenium, playwright, curl_cffi, go-http) |
| `-b, --bypass` | Enable Cloudflare bypass techniques |
| `-r, --requests` | Number of requests to generate |
| `-c, --concurrency` | Number of concurrent connections |
| `--follow-redirects / --no-follow-redirects` | Follow redirects automatically in non-browser engines (default: enabled) |
| `--max-redirects` | Maximum redirect hops in non-browser engines (default: 5) |
| `--ddos-only` | Only run DDoS protection tests |
| `--ddos-type` | DDoS attack type (1-15) |
| `--waf-only` | Only run WAF ruleset tests |
| `--waf-ruleset` | WAF ruleset to test (owasp, managed, both) |
| `-o, --output` | Output report file path |
| `--output-dir` | Create a unique run directory under this path |
| `--format` | Report format: text, JSON, JUnit, or SARIF |
| `--baseline` | Compare against a previous JSON report |
| `--min-protection-score` | Fail the quality gate below this score |
| `--max-bypasses` | Fail when successful bypasses exceed this count |
| `--max-transport-errors` | Fail when transport errors exceed this count |
| `--include-response-body` | Include potentially sensitive response bodies |
| `-v, --verbose` | Enable verbose output |
| `--accept-responsibility` | Required for CLI mode |

For the opt-in GCP control-plane integration, see
[GCP Integration](docs/GCP_INTEGRATION.md). The isolated executor and controller
integration were deployed and verified idle on 2026-10-02; no live WAF probes
were sent during rollout.

### DDoS Attack Types

| ID | Category | Attack Type |
|----|----------|-------------|
| 1 | Volumetric | UDP Flood |
| 2 | Volumetric | ICMP Flood |
| 3 | Volumetric | DNS Amplification |
| 4 | Volumetric | NTP Amplification |
| 5 | Protocol | SYN Flood |
| 6 | Protocol | SYN-ACK Flood |
| 7 | Protocol | ACK Flood |
| 8 | Protocol | RST Flood |
| 9 | Protocol | Fragmentation |
| 10 | Application | HTTP GET Flood |
| 11 | Application | HTTP POST Flood |
| 12 | Application | Slowloris |
| 13 | Application | RUDY |
| 14 | Application | Cache Bypass |
| 15 | Multi-Vector | Combined Attack |

## Remote Executor

`Dockerfile.executor` packages an idle, single-worker `remote-waf` API for a
dedicated non-WARP host. The related GCP controller adds **Evidence > WAF executor**
controls for smoke/full-catalogue runs, cancellation, history, and JSON downloads.
Use authenticated IAP forwarding to the controller, not a public dashboard proxy.

This mode runs only the fixed reduced-impact catalogue. It is separate from the
classic CLI and guarded `waf_lab` exact-request approval flow. An authorized
submission permits automatic public HTTPS redirects within shared request, rate,
runtime, and hop limits; TLS verification remains enabled. Responses are
observations, not exploit-success findings or managed-rule coverage scores.
Restarts never replay runs, and uncertain submissions are never automatically
retried. Reports exclude raw bodies, cookies, and redirect Location values.

See [Remote Service](docs/remote-service.md) for signing, storage, API, and offline
test contracts, and [GCP Integration](docs/GCP_INTEGRATION.md) for rollout boundaries.
The 2026-10-02 lab rollout verified image startup and signed idle status, not
target protection. Future publication, deployment, and authorized target tests
remain separate operations.

## Output

The tool generates:
- Real-time console output with rich formatting
- Summary statistics and protection scores
- Detailed results by category
- Bypass findings (if any)
- Security recommendations
- Optional JSON/text report export
- Versioned JSON, JUnit, and SARIF reports for CI systems
- Explicit blocked, allowed, challenged, error, and inconclusive outcomes
- Quality-gate exit status (`2` when configured thresholds fail)
- Run IDs, provenance, latency percentiles, and baseline deltas

Reports omit response bodies by default. Use `--include-response-body` only when the
resulting artifact can be handled as sensitive data. `--output - --format json`
writes machine-readable output to stdout. `--output-dir reports --format json`
creates `reports/<run-id>/report.json` atomically.

### Automated Testing

```bash
# Unit and local integration tests, including branch coverage
python -m pytest -m "not browser and not live and not destructive"

# Opt-in browser smoke tests
python -m pytest -m browser --run-browser --no-cov

# One authorized remote health check; never runs in normal CI
CF_TEST_TARGET=https://example.com python -m pytest -m live --run-live --no-cov
```

Normal CI only communicates with local test servers. Browser, live-target, and
high-volume tests require separate explicit switches. The initial branch coverage
gate is 50% and should be raised as the remaining attack simulators gain focused
contract tests.

The protocol and volumetric attack names describe HTTP-layer approximations in the
current implementation. They do not generate raw UDP, ICMP, SYN, or fragmented IP
traffic and should not be interpreted as protocol-level validation.

### Sample Output

```
╔═══════════════════════════════════════════════════════════════════╗
║           Cloudflare WAF & DDoS Protection Tester                 ║
╚═══════════════════════════════════════════════════════════════════╝

DDoS PROTECTION TEST RESULTS
┌─────────────────────┬─────────────────┬──────────┬─────────┐
│ Target              │ Attack Type     │ Requests │ Blocked │
├─────────────────────┼─────────────────┼──────────┼─────────┤
│ example.com         │ HTTP_GET_FLOOD  │ 1000     │ 847     │
└─────────────────────┴─────────────────┴──────────┴─────────┘

WAF RULESET TEST RESULTS
┌────────────────────────┬───────┬─────────┬──────────┐
│ Category               │ Total │ Blocked │ Bypassed │
├────────────────────────┼───────┼─────────┼──────────┤
│ SQL Injection          │ 20    │ 20      │ 0        │
│ Cross-Site Scripting   │ 20    │ 19      │ 1        │
└────────────────────────┴───────┴─────────┴──────────┘

Overall Protection Score: 94.5% (EXCELLENT)
```

## Project Structure

```
cf-tester/
├── cf_waf_tester.py      # Main entry point
├── modules/
│   ├── __init__.py
│   ├── config.py         # Configuration management
│   ├── http_engine.py    # HTTP request engines
│   ├── ddos_simulator.py # DDoS attack simulations
│   ├── waf_tester.py     # WAF ruleset testing
│   ├── bypass_techniques.py # Cloudflare bypass methods
│   └── reporter.py       # Report generation
├── requirements.txt
└── README.md
```

## References

### DDoS Attack Types
- [eSecurity Planet - Types of DDoS Attacks](https://www.esecurityplanet.com/networks/types-of-ddos-attacks/)
- [Imperva - DDoS Attacks](https://www.imperva.com/learn/ddos/ddos-attacks/)

### Cloudflare WAF Rulesets
- [Cloudflare OWASP Core Ruleset](https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/)
- [Cloudflare Managed Ruleset](https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/)

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users must:

1. Only test systems they own or have explicit written authorization to test
2. Comply with all applicable laws and regulations
3. Not use this tool for malicious purposes
4. Understand that unauthorized testing may result in legal consequences

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.
