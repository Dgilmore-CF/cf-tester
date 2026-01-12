"""Report generation module for WAF/DDoS test results."""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from .ddos_simulator import DDoSTestResult, DDoSAttackType
from .waf_tester import WAFTestResult

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class TestSummary:
    """Summary of all tests."""
    start_time: str
    end_time: str
    total_duration: float
    targets_tested: List[str]
    ddos_tests_run: int
    waf_tests_run: int
    overall_protection_score: float


class Reporter:
    """Generate and display test reports."""
    
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        self.ddos_results: List[DDoSTestResult] = []
        self.waf_results: List[WAFTestResult] = []
        self.start_time = datetime.now()
    
    def add_ddos_results(self, results: List[DDoSTestResult]):
        """Add DDoS test results."""
        self.ddos_results.extend(results)
    
    def add_waf_results(self, results: List[WAFTestResult]):
        """Add WAF test results."""
        self.waf_results.extend(results)
    
    def generate_report(self):
        """Generate and display the full report."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        console.print("\n")
        console.print(Panel("TEST RESULTS REPORT", style="bold green"))
        
        console.print(f"\n[bold]Test Duration:[/] {duration:.2f} seconds")
        console.print(f"[bold]Start Time:[/] {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print(f"[bold]End Time:[/] {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.ddos_results:
            self._display_ddos_results()
        
        if self.waf_results:
            self._display_waf_results()
        
        self._display_summary()
        
        if self.output_file:
            self._save_report()
    
    def _display_ddos_results(self):
        """Display DDoS test results."""
        console.print("\n")
        console.print(Panel("DDoS PROTECTION TEST RESULTS", style="bold cyan"))
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Target", style="cyan")
        table.add_column("Attack Type", style="yellow")
        table.add_column("Requests", justify="right")
        table.add_column("Blocked", justify="right", style="green")
        table.add_column("RPS", justify="right")
        table.add_column("Avg Time", justify="right")
        table.add_column("Protected", style="bold")
        
        for result in self.ddos_results:
            protected = "[green]YES[/]" if result.cf_protection_triggered else "[red]NO[/]"
            
            table.add_row(
                result.target[:30],
                result.attack_type.name,
                str(result.total_requests),
                str(result.blocked_requests),
                f"{result.requests_per_second:.1f}",
                f"{result.avg_response_time:.3f}s",
                protected
            )
        
        console.print(table)
        
        for result in self.ddos_results:
            if result.notes:
                console.print(f"\n[bold]Notes for {result.target}:[/]")
                for note in result.notes:
                    console.print(f"  • {note}")
            
            if result.status_code_distribution:
                console.print(f"\n[bold]Status Code Distribution:[/]")
                for code, count in sorted(result.status_code_distribution.items()):
                    console.print(f"  {code}: {count} requests")
    
    def _display_waf_results(self):
        """Display WAF test results."""
        console.print("\n")
        console.print(Panel("WAF RULESET TEST RESULTS", style="bold cyan"))
        
        categories: Dict[str, Dict[str, int]] = {}
        for result in self.waf_results:
            cat = result.test_case.category
            if cat not in categories:
                categories[cat] = {"total": 0, "blocked": 0, "bypassed": 0}
            categories[cat]["total"] += 1
            if result.blocked:
                categories[cat]["blocked"] += 1
            if result.bypass_successful:
                categories[cat]["bypassed"] += 1
        
        cat_table = Table(title="Results by Category", show_header=True, header_style="bold magenta")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Total Tests", justify="right")
        cat_table.add_column("Blocked", justify="right", style="green")
        cat_table.add_column("Bypassed", justify="right", style="red")
        cat_table.add_column("Block Rate", justify="right")
        
        for cat, stats in sorted(categories.items()):
            block_rate = stats["blocked"] / stats["total"] * 100 if stats["total"] > 0 else 0
            bypass_indicator = f"[red]{stats['bypassed']}[/]" if stats['bypassed'] > 0 else str(stats['bypassed'])
            
            cat_table.add_row(
                cat,
                str(stats["total"]),
                str(stats["blocked"]),
                bypass_indicator,
                f"{block_rate:.1f}%"
            )
        
        console.print(cat_table)
        
        bypasses = [r for r in self.waf_results if r.bypass_successful]
        if bypasses:
            console.print("\n")
            console.print(Panel("[bold red]WAF BYPASS FINDINGS[/]", style="red"))
            
            bypass_table = Table(show_header=True, header_style="bold red")
            bypass_table.add_column("Test Case", style="yellow")
            bypass_table.add_column("Category", style="cyan")
            bypass_table.add_column("Bypass Technique", style="red")
            bypass_table.add_column("Response Code", justify="right")
            
            for result in bypasses:
                bypass_table.add_row(
                    result.test_case.name[:40],
                    result.test_case.category,
                    result.bypass_technique or "N/A",
                    str(result.response_code)
                )
            
            console.print(bypass_table)
            console.print(f"\n[bold red]⚠️  {len(bypasses)} potential WAF bypasses found![/]")
        
        total_tests = len(self.waf_results)
        blocked = sum(1 for r in self.waf_results if r.blocked)
        overall_block_rate = blocked / total_tests * 100 if total_tests > 0 else 0
        
        console.print(f"\n[bold]Overall WAF Block Rate:[/] {overall_block_rate:.1f}%")
    
    def _display_summary(self):
        """Display overall summary."""
        console.print("\n")
        console.print(Panel("OVERALL SUMMARY", style="bold green"))
        
        targets = set()
        for r in self.ddos_results:
            targets.add(r.target)
        for r in self.waf_results:
            targets.add(r.target)
        
        ddos_protected = sum(1 for r in self.ddos_results if r.cf_protection_triggered)
        waf_blocked = sum(1 for r in self.waf_results if r.blocked and not r.bypass_successful)
        waf_bypassed = sum(1 for r in self.waf_results if r.bypass_successful)
        
        console.print(f"[bold]Targets Tested:[/] {len(targets)}")
        console.print(f"[bold]DDoS Tests:[/] {len(self.ddos_results)}")
        console.print(f"[bold]WAF Tests:[/] {len(self.waf_results)}")
        
        if self.ddos_results:
            ddos_protection_rate = ddos_protected / len(self.ddos_results) * 100
            console.print(f"[bold]DDoS Protection Rate:[/] {ddos_protection_rate:.1f}%")
        
        if self.waf_results:
            waf_effective_rate = waf_blocked / len(self.waf_results) * 100
            console.print(f"[bold]WAF Effective Block Rate:[/] {waf_effective_rate:.1f}%")
            
            if waf_bypassed > 0:
                console.print(f"[bold red]WAF Bypasses Found:[/] {waf_bypassed}")
        
        protection_score = self._calculate_protection_score()
        
        if protection_score >= 90:
            score_style = "bold green"
            rating = "EXCELLENT"
        elif protection_score >= 70:
            score_style = "bold yellow"
            rating = "GOOD"
        elif protection_score >= 50:
            score_style = "bold orange3"
            rating = "FAIR"
        else:
            score_style = "bold red"
            rating = "POOR"
        
        console.print(f"\n[{score_style}]Overall Protection Score: {protection_score:.1f}% ({rating})[/]")
        
        self._display_recommendations()
    
    def _calculate_protection_score(self) -> float:
        """Calculate overall protection score."""
        scores = []
        
        if self.ddos_results:
            ddos_protected = sum(1 for r in self.ddos_results if r.cf_protection_triggered)
            ddos_score = ddos_protected / len(self.ddos_results) * 100
            scores.append(ddos_score)
        
        if self.waf_results:
            waf_blocked = sum(1 for r in self.waf_results if r.blocked)
            waf_bypassed = sum(1 for r in self.waf_results if r.bypass_successful)
            
            waf_score = (waf_blocked - waf_bypassed) / len(self.waf_results) * 100
            waf_score = max(0, waf_score)
            scores.append(waf_score)
        
        return sum(scores) / len(scores) if scores else 0
    
    def _display_recommendations(self):
        """Display security recommendations based on results."""
        console.print("\n")
        console.print(Panel("RECOMMENDATIONS", style="bold blue"))
        
        recommendations = []
        
        ddos_not_protected = [r for r in self.ddos_results if not r.cf_protection_triggered]
        if ddos_not_protected:
            recommendations.append("• Enable or tune DDoS protection rules for better coverage")
            recommendations.append("• Consider enabling Under Attack Mode during testing")
            recommendations.append("• Review rate limiting rules configuration")
        
        waf_bypasses = [r for r in self.waf_results if r.bypass_successful]
        if waf_bypasses:
            bypass_techniques = set(r.bypass_technique for r in waf_bypasses if r.bypass_technique)
            recommendations.append("• Review WAF rules for encoding bypass vulnerabilities")
            if bypass_techniques:
                recommendations.append(f"  - Vulnerable to: {', '.join(bypass_techniques)}")
            recommendations.append("• Consider enabling additional paranoia levels in OWASP ruleset")
            recommendations.append("• Enable Cloudflare's advanced WAF features")
        
        categories_with_issues: Dict[str, int] = {}
        for r in self.waf_results:
            if not r.blocked or r.bypass_successful:
                cat = r.test_case.category
                categories_with_issues[cat] = categories_with_issues.get(cat, 0) + 1
        
        for cat, count in sorted(categories_with_issues.items(), key=lambda x: -x[1])[:5]:
            recommendations.append(f"• Strengthen protection for {cat} attacks ({count} tests not blocked)")
        
        if not recommendations:
            recommendations.append("• Protection appears comprehensive - continue monitoring")
            recommendations.append("• Consider regular security assessments")
            recommendations.append("• Keep WAF rules updated")
        
        for rec in recommendations:
            console.print(rec)
    
    def _save_report(self):
        """Save report to file."""
        report_data = {
            "metadata": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds()
            },
            "ddos_results": [
                {
                    "attack_type": r.attack_type.name,
                    "target": r.target,
                    "total_requests": r.total_requests,
                    "successful_requests": r.successful_requests,
                    "blocked_requests": r.blocked_requests,
                    "challenged_requests": r.challenged_requests,
                    "error_requests": r.error_requests,
                    "avg_response_time": r.avg_response_time,
                    "requests_per_second": r.requests_per_second,
                    "duration": r.duration,
                    "cf_protection_triggered": r.cf_protection_triggered,
                    "status_code_distribution": r.status_code_distribution,
                    "notes": r.notes
                }
                for r in self.ddos_results
            ],
            "waf_results": [
                {
                    "test_name": r.test_case.name,
                    "category": r.test_case.category,
                    "ruleset": r.test_case.ruleset,
                    "target": r.target,
                    "response_code": r.response_code,
                    "blocked": r.blocked,
                    "challenge_presented": r.challenge_presented,
                    "bypass_successful": r.bypass_successful,
                    "bypass_technique": r.bypass_technique,
                    "response_time": r.response_time
                }
                for r in self.waf_results
            ],
            "summary": {
                "protection_score": self._calculate_protection_score(),
                "ddos_tests": len(self.ddos_results),
                "waf_tests": len(self.waf_results),
                "waf_bypasses": sum(1 for r in self.waf_results if r.bypass_successful)
            }
        }
        
        output_path = Path(self.output_file)
        
        if output_path.suffix == ".json":
            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2)
        else:
            with open(output_path, "w") as f:
                f.write(self._generate_text_report(report_data))
        
        console.print(f"\n[bold green]Report saved to {self.output_file}[/]")
    
    def _generate_text_report(self, report_data: Dict) -> str:
        """Generate text format report."""
        lines = [
            "=" * 60,
            "CLOUDFLARE WAF/DDOS PROTECTION TEST REPORT",
            "=" * 60,
            "",
            f"Test Duration: {report_data['metadata']['duration_seconds']:.2f} seconds",
            f"Start Time: {report_data['metadata']['start_time']}",
            f"End Time: {report_data['metadata']['end_time']}",
            "",
            "-" * 60,
            "SUMMARY",
            "-" * 60,
            f"Protection Score: {report_data['summary']['protection_score']:.1f}%",
            f"DDoS Tests Run: {report_data['summary']['ddos_tests']}",
            f"WAF Tests Run: {report_data['summary']['waf_tests']}",
            f"WAF Bypasses Found: {report_data['summary']['waf_bypasses']}",
            "",
        ]
        
        if report_data['ddos_results']:
            lines.extend([
                "-" * 60,
                "DDOS TEST RESULTS",
                "-" * 60,
            ])
            for r in report_data['ddos_results']:
                lines.extend([
                    f"Target: {r['target']}",
                    f"  Attack Type: {r['attack_type']}",
                    f"  Total Requests: {r['total_requests']}",
                    f"  Blocked: {r['blocked_requests']}",
                    f"  Protected: {'Yes' if r['cf_protection_triggered'] else 'No'}",
                    ""
                ])
        
        if report_data['waf_results']:
            lines.extend([
                "-" * 60,
                "WAF TEST RESULTS",
                "-" * 60,
            ])
            
            bypasses = [r for r in report_data['waf_results'] if r['bypass_successful']]
            if bypasses:
                lines.append("BYPASSES FOUND:")
                for r in bypasses:
                    lines.append(f"  - {r['test_name']}: {r['bypass_technique']}")
                lines.append("")
        
        return "\n".join(lines)
