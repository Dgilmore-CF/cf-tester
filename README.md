# Cloudflare WAF & DDoS Protection Tester

A comprehensive security testing tool for evaluating Cloudflare WAF configurations and DDoS protection mechanisms.

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
| `--ddos-only` | Only run DDoS protection tests |
| `--ddos-type` | DDoS attack type (1-15) |
| `--waf-only` | Only run WAF ruleset tests |
| `--waf-ruleset` | WAF ruleset to test (owasp, managed, both) |
| `-o, --output` | Output report file path |
| `-v, --verbose` | Enable verbose output |
| `--accept-responsibility` | Required for CLI mode |

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

## Output

The tool generates:
- Real-time console output with rich formatting
- Summary statistics and protection scores
- Detailed results by category
- Bypass findings (if any)
- Security recommendations
- Optional JSON/text report export

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
