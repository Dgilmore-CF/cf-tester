"""Report generation module for WAF/DDoS test results."""

import json
import hashlib
import math
import time
import os
import platform
import sys
import uuid
import xml.etree.ElementTree as ET
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
from .waf_tester import CORPUS_WARNING, WAFOutcome, WAFTestResult
from .config import Config

logger = logging.getLogger(__name__)
console = Console()
TOOL_VERSION = "1.0.0"
SCORE_METHOD = "response-mitigation-v2"


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
    
    def __init__(
        self,
        output_file: Optional[str] = None,
        config: Optional[Config] = None,
        output_format: Optional[str] = None,
        baseline_file: Optional[str] = None,
        output_stream=None,
    ):
        self.output_file = output_file
        self.config = config
        self.output_format = output_format
        self.baseline_file = baseline_file
        self.output_stream = output_stream or sys.stdout
        self.ddos_results: List[DDoSTestResult] = []
        self.waf_results: List[WAFTestResult] = []
        self.start_time = datetime.now()
        self.run_id = str(uuid.uuid4())
    
    def add_ddos_results(self, results: List[DDoSTestResult]):
        """Add DDoS test results."""
        self.ddos_results.extend(results)
    
    def add_waf_results(self, results: List[WAFTestResult]):
        """Add WAF test results."""
        self.waf_results.extend(results)
    
    def generate_report(self) -> Dict[str, Any]:
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
        
        report_data = self._build_report_data(end_time)
        if report_data["quality_gate"]["status"] == "failed":
            console.print("\n[bold red]Quality gate failed:[/]")
            for reason in report_data["quality_gate"]["reasons"]:
                console.print(f"  - {reason}")
        if self.output_file:
            self._save_report(report_data)
        return report_data
    
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
        baseline_results = [r for r in self.waf_results if r.attempt_type == "baseline"]
        for result in baseline_results:
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
        
        total_tests = len(baseline_results)
        blocked = sum(1 for r in baseline_results if r.blocked)
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
        baseline_results = [r for r in self.waf_results if r.attempt_type == "baseline"]
        waf_blocked = sum(1 for r in baseline_results if r.blocked)
        waf_bypassed = sum(1 for r in self.waf_results if r.bypass_successful)
        
        console.print(f"[bold]Targets Tested:[/] {len(targets)}")
        console.print(f"[bold]DDoS Tests:[/] {len(self.ddos_results)}")
        console.print(f"[bold]WAF Tests:[/] {len(baseline_results)}")
        
        if self.ddos_results:
            ddos_protection_rate = ddos_protected / len(self.ddos_results) * 100
            console.print(f"[bold]DDoS Protection Rate:[/] {ddos_protection_rate:.1f}%")
        
        if baseline_results:
            waf_effective_rate = waf_blocked / len(baseline_results) * 100
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
        """Score observed mitigation, counting missing evidence as unprotected coverage."""
        scores = []
        
        if self.ddos_results:
            total_requests = sum(r.total_requests for r in self.ddos_results)
            mitigated_requests = sum(
                r.blocked_requests + r.challenged_requests for r in self.ddos_results
            )
            if total_requests:
                scores.append(min(mitigated_requests / total_requests * 100, 100))
        
        if self.waf_results:
            baseline = [r for r in self.waf_results if r.attempt_type == "baseline"]
            probes = [
                r for r in baseline if r.test_case.expected_block
            ]
            if probes:
                mitigated = sum(
                    1 for r in probes
                    if r.outcome in (WAFOutcome.BLOCKED, WAFOutcome.CHALLENGED)
                )
                # Successful controls add no credit; failed or unknown controls reduce confidence.
                control_failures = sum(
                    not r.test_case.expected_block and r.outcome != WAFOutcome.ALLOWED
                    for r in baseline
                )
                scores.append(mitigated / (len(probes) + control_failures) * 100)
            else:
                scores.append(0)
        
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
            recommendations.append("Review reported bypass evidence with application semantics and matched-rule logs before changing rules.")
        
        categories_with_issues: Dict[str, int] = {}
        for r in self.waf_results:
            if r.attempt_type == "baseline" and r.test_case.expected_block and r.outcome == WAFOutcome.ALLOWED:
                cat = r.test_case.category
                categories_with_issues[cat] = categories_with_issues.get(cat, 0) + 1
        
        for cat, count in sorted(categories_with_issues.items(), key=lambda x: -x[1])[:5]:
            recommendations.append(f"Review {cat} coverage ({count} allowed signatures); correlate rule logs and application semantics, not proof of a WAF vulnerability.")

        if any(r.outcome in (WAFOutcome.ERROR, WAFOutcome.INCONCLUSIVE) for r in self.waf_results):
            recommendations.append("Resolve transport errors or inconclusive responses and rerun; missing evidence is not a WAF vulnerability.")
        if any(not r.test_case.expected_block and r.blocked for r in self.waf_results):
            recommendations.append("Review benign control mitigation for possible false positives, not attack coverage gaps.")
        if any(r.attempt_type == "bypass" and r.outcome == WAFOutcome.ALLOWED and not r.bypass_successful for r in self.waf_results):
            recommendations.append("Allowed variants remain unverified without semantic equivalence and matched-rule evidence.")
        
        if not recommendations:
            recommendations.append("No confirmed vulnerability inferred; response observations alone do not establish comprehensive WAF coverage.")
        
        for rec in recommendations:
            console.print(rec)
    
    def _build_report_data(self, end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Build the canonical, versioned representation used by every format."""
        end_time = end_time or datetime.now()
        baseline_results = [r for r in self.waf_results if r.attempt_type == "baseline"]
        bypass_results = [r for r in self.waf_results if r.attempt_type == "bypass"]
        transport_errors = sum(1 for r in self.waf_results if r.outcome == WAFOutcome.ERROR)
        transport_errors += sum(r.error_requests for r in self.ddos_results)

        report_data = {
            "schema_version": "1.0.0",
            "run_id": self.run_id,
            "metadata": {
                "start_time": self.start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - self.start_time).total_seconds(),
                "git_sha": os.environ.get("GITHUB_SHA"),
                "tool_version": TOOL_VERSION,
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "http_engine": self.config.http_engine if self.config else None,
            },
            "configuration": self._report_configuration(),
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
                    "case_id": r.test_case.case_id,
                    "category": r.test_case.category,
                    "ruleset": r.test_case.ruleset,
                    "description": r.test_case.description,
                    "expected_block": r.test_case.expected_block,
                    "payload": r.test_case.payload,
                    "injection_point": r.test_case.injection_point,
                    "body_format": r.test_case.body_format,
                    "observation_scope": "response",
                    "cwe_id": r.test_case.cwe_id,
                    "owasp_category": r.test_case.owasp_category,
                    "cve_id": getattr(r.test_case, 'cve_id', None),
                    "target": r.target,
                    "method": r.test_case.method.value,
                    "response_code": r.response_code,
                    "outcome": r.outcome.value,
                    "blocked": r.blocked,
                    "challenge_presented": r.challenge_presented,
                    "bypass_successful": r.bypass_successful,
                    "bypass_technique": r.bypass_technique,
                    "response_time": r.response_time,
                    "cf_ray": r.cf_ray,
                    "error": r.error,
                    "attempt_type": r.attempt_type,
                    "parent_case_id": r.parent_case_id,
                    "raw_response": (
                        r.raw_response[:500]
                        if r.raw_response and self.config and self.config.include_response_body
                        else None
                    ),
                    "notes": r.notes,
                }
                for r in self.waf_results
            ],
            "summary": {
                "protection_score": self._calculate_protection_score(),
                "score_method": SCORE_METHOD,
                "ddos_tests": len(self.ddos_results),
                "waf_tests": len(baseline_results),
                "bypass_attempts": len(bypass_results),
                "waf_bypasses": sum(1 for r in bypass_results if r.bypass_successful),
                "transport_errors": transport_errors,
                "inconclusive": sum(1 for r in baseline_results if r.outcome == WAFOutcome.INCONCLUSIVE),
                "false_positives": sum(
                    1 for r in baseline_results if not r.test_case.expected_block and r.blocked
                ),
                "latency_ms": self._latency_percentiles(baseline_results),
            },
        }
        report_data["quality_gate"] = self._evaluate_quality_gate(report_data)
        report_data["warnings"] = [CORPUS_WARNING]
        report_data["baseline_comparison"] = self._compare_baseline(report_data)
        return report_data

    @staticmethod
    def _latency_percentiles(results: List[WAFTestResult]) -> Dict[str, float]:
        values = sorted(r.response_time * 1000 for r in results)
        if not values:
            return {"p50": 0, "p95": 0, "p99": 0}

        def percentile(fraction: float) -> float:
            index = round((len(values) - 1) * fraction)
            return round(values[index], 3)

        return {"p50": percentile(0.50), "p95": percentile(0.95), "p99": percentile(0.99)}

    def _report_configuration(self) -> Dict[str, Any]:
        if not self.config:
            return {}
        return {
            "targets": self.config.get_target_urls(),
            "http_engine": self.config.http_engine,
            "waf_ruleset": self.config.waf_ruleset.name,
            "waf_test_all_categories": self.config.waf_test_all_categories,
            "waf_categories": sorted(category.strip().casefold() for category in self.config.waf_categories),
            "bypass_enabled": self.config.use_bypass_techniques,
            "request_count": self.config.request_count,
            "concurrency": self.config.concurrency,
            "ddos_waves": self.config.ddos_waves,
            "ddos_attack_type": self.config.ddos_attack_type,
            "ddos_duration": self.config.ddos_duration,
            "ddos_rate_limit": self.config.ddos_rate_limit,
            "ddos_wave_delay": self.config.ddos_wave_delay,
            "ddos_burst_mode": self.config.ddos_burst_mode,
            "ddos_sustained": self.config.ddos_sustained,
            "ddos_ramp_up": self.config.ddos_ramp_up,
            "timeout": self.config.timeout,
            "ssl_verify": self.config.ssl_verify,
            "follow_redirects": self.config.follow_redirects,
            "max_redirects": self.config.max_redirects,
            "user_agent_rotation": self.config.user_agent_rotation,
            "retry_count": self.config.retry_count,
            "retry_delay": self.config.retry_delay,
            "request_context_hash": hashlib.sha256(json.dumps({
                "headers": {key.lower(): value for key, value in self.config.custom_headers.items()},
                "proxy": self.config.proxy,
                "proxy_list": self.config.proxy_list,
                "rotate_proxies": self.config.rotate_proxies,
            }, sort_keys=True).encode()).hexdigest(),
            "response_bodies_included": self.config.include_response_body,
        }

    def _evaluate_quality_gate(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        reasons = []
        summary = report_data["summary"]
        config = self.config
        if config and config.min_protection_score is not None:
            if summary["protection_score"] < config.min_protection_score:
                reasons.append(
                    f"Protection score {summary['protection_score']:.1f} is below {config.min_protection_score:.1f}"
                )
        if config and config.max_bypasses is not None:
            if summary["waf_bypasses"] > config.max_bypasses:
                reasons.append(f"WAF bypasses {summary['waf_bypasses']} exceed {config.max_bypasses}")
        if config and config.max_transport_errors is not None:
            if summary["transport_errors"] > config.max_transport_errors:
                reasons.append(
                    f"Transport errors {summary['transport_errors']} exceed {config.max_transport_errors}"
                )
        return {"status": "failed" if reasons else "passed", "reasons": reasons}

    def _compare_baseline(self, report_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.baseline_file:
            return None
        try:
            baseline = json.loads(Path(self.baseline_file).read_text())
            if not isinstance(baseline, dict) or not isinstance(baseline.get("summary"), dict):
                raise ValueError("Baseline must be a report object with a summary")
            previous = baseline["summary"]
            current = report_data["summary"]
            reasons = []
            if baseline.get("schema_version") != report_data["schema_version"]:
                reasons.append("Schema version differs or is missing")
            if previous.get("score_method") != current["score_method"]:
                reasons.append("Scoring method differs or is missing")
            previous_config = dict(baseline.get("configuration", {}))
            current_config = dict(report_data["configuration"])
            for config in (previous_config, current_config):
                config.pop("response_bodies_included", None)
            if not current_config or previous_config != current_config:
                reasons.append("Request configuration differs or is missing")
            # Preserve duplicate attempts, but do not require execution order to match.
            def case_set(report):
                waf = sorted((
                    r["case_id"], r["target"], r["attempt_type"], r.get("parent_case_id") or "",
                    r["expected_block"], r["ruleset"],
                ) for r in report["waf_results"])
                ddos = sorted((r["attack_type"], r["target"], r["total_requests"]) for r in report["ddos_results"])
                return waf, ddos

            if "waf_results" not in baseline or "ddos_results" not in baseline:
                reasons.append("Case set is missing")
            elif case_set(baseline) != case_set(report_data):
                reasons.append("Case set differs")
            if reasons:
                return {"status": "incompatible", "reasons": reasons}
            for key in ("protection_score", "waf_bypasses", "transport_errors"):
                value = previous[key]
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ValueError(f"Invalid baseline summary value: {key}")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return {"status": "unavailable", "error": str(exc)}
        return {
            "status": "compared",
            "protection_score_delta": current["protection_score"] - previous["protection_score"],
            "waf_bypasses_delta": current["waf_bypasses"] - previous.get("waf_bypasses", 0),
            "transport_errors_delta": current["transport_errors"] - previous.get("transport_errors", 0),
        }

    def _save_report(self, report_data: Dict[str, Any]):
        """Save a report atomically in the selected format."""
        output_path = Path(self.output_file)
        report_format = self.output_format or output_path.suffix.lstrip(".").lower() or "text"

        if report_format == "json":
            content = json.dumps(report_data, indent=2)
        elif report_format == "junit":
            content = self._generate_junit_report(report_data)
        elif report_format == "sarif":
            content = json.dumps(self._generate_sarif_report(report_data), indent=2)
        else:
            content = self._generate_text_report(report_data)

        if self.output_file == "-":
            self.output_stream.write(f"{content}\n")
            return

        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = output_path.with_suffix(f"{output_path.suffix}.tmp")
        temporary_path.write_text(content)
        temporary_path.replace(output_path)
        console.print(f"\n[bold green]Report saved to {self.output_file}[/]")

    def _generate_junit_report(self, report_data: Dict[str, Any]) -> str:
        baseline = [r for r in report_data["waf_results"] if r["attempt_type"] == "baseline"]
        failures = sum(
            1 for r in baseline
            if (r["expected_block"] and r["outcome"] == WAFOutcome.ALLOWED.value)
            or (
                not r["expected_block"]
                and r["outcome"] in (WAFOutcome.BLOCKED.value, WAFOutcome.CHALLENGED.value)
            )
        )
        suite = ET.Element(
            "testsuite",
            name="cf-tester",
            tests=str(len(baseline)),
            failures=str(failures),
            errors=str(sum(
                1 for r in baseline
                if r["outcome"] in (WAFOutcome.ERROR.value, WAFOutcome.INCONCLUSIVE.value)
            )),
        )
        for result in baseline:
            case = ET.SubElement(suite, "testcase", name=result["case_id"], classname=result["category"])
            unexpected = (
                result["expected_block"] and result["outcome"] == WAFOutcome.ALLOWED.value
            ) or (
                not result["expected_block"]
                and result["outcome"] in (WAFOutcome.BLOCKED.value, WAFOutcome.CHALLENGED.value)
            )
            if unexpected:
                ET.SubElement(case, "failure", message="Observed outcome did not match expectation")
            elif result["outcome"] in (WAFOutcome.ERROR.value, WAFOutcome.INCONCLUSIVE.value):
                ET.SubElement(case, "error", message=result["error"] or result["outcome"])
        return ET.tostring(suite, encoding="unicode", xml_declaration=True)

    def _generate_sarif_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        for result in report_data["waf_results"]:
            if (
                result["attempt_type"] == "baseline"
                and result["expected_block"]
                and result["outcome"] == WAFOutcome.ALLOWED.value
            ):
                findings.append({
                    "ruleId": result["case_id"],
                    "level": "warning",
                    "message": {"text": f"{result['test_name']} was allowed at response level; rule coverage and exploit semantics are unverified"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": result["target"]}}}],
                })
            elif result["attempt_type"] == "bypass" and result["bypass_successful"]:
                findings.append({
                    "ruleId": result["parent_case_id"] or result["case_id"],
                    "level": "error",
                    "message": {"text": f"{result['test_name']} reported as a bypass; review supporting semantic and rule evidence"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": result["target"]}}}],
                })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cf-tester"}}, "results": findings}],
        }
    
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
        lines.extend(f"Warning: {warning}" for warning in report_data.get("warnings", []))
        
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
                ""
            ])
            
            for i, r in enumerate(report_data['waf_results'], 1):
                status = r["outcome"].upper()
                lines.extend([
                    f"Test {i}/{len(report_data['waf_results'])}",
                    "",
                    "TEST CASE",
                    f"Name: {r['test_name']}",
                    f"Category: {r['category']}",
                    f"Description: {r.get('description', 'N/A')}",
                ])
                
                if r.get('cwe_id'):
                    cwe_url = f"https://cwe.mitre.org/data/definitions/{r['cwe_id'].replace('CWE-', '')}.html"
                    lines.append(f"CWE: {r['cwe_id']} - {cwe_url}")
                
                if r.get('owasp_category'):
                    lines.append(f"OWASP: {r['owasp_category']}")
                    owasp_map = {
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
                    owasp_key = r['owasp_category'].split('-')[0] if r['owasp_category'] else None
                    if owasp_key and owasp_key in owasp_map:
                        lines.append(f"OWASP Doc: {owasp_map[owasp_key]}")
                
                if r.get('cve_id'):
                    cve_url = f"https://nvd.nist.gov/vuln/detail/{r['cve_id']}"
                    lines.append(f"CVE: {r['cve_id']} - {cve_url}")
                
                lines.extend([
                    "",
                    "HTTP Request:",
                    f"  Method: {r['method']}",
                    f"  URL: {r['target']}",
                    f"  Payload: {r['payload'][:100]}{'...' if len(r['payload']) > 100 else ''}",
                    f"  Injection Point: {r.get('injection_point', 'N/A')}",
                    "",
                    f"Result: {status} (Status: {r['response_code']}, Time: {r['response_time']:.3f}s)",
                ])
                lines.extend(f"Note: {note}" for note in r.get("notes", []))
                
                if r.get('cf_ray'):
                    lines.append(f"CF-Ray: {r['cf_ray']}")
                
                lines.append("")
                lines.append("Server Response:")
                if r.get('raw_response'):
                    lines.append(r['raw_response'])
                else:
                    lines.append("(response body omitted)")
                
                lines.extend([
                    "",
                    "-" * 60,
                    ""
                ])
            
            bypasses = [r for r in report_data['waf_results'] if r['bypass_successful']]
            if bypasses:
                lines.extend([
                    "=" * 60,
                    "BYPASSES FOUND",
                    "=" * 60,
                ])
                for r in bypasses:
                    lines.append(f"  - {r['test_name']}: {r['bypass_technique']}")
                lines.append("")
        
        return "\n".join(lines)
