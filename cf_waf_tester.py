#!/usr/bin/env python3
"""
Cloudflare WAF/DDoS Testing Tool

A comprehensive security testing tool for evaluating Cloudflare WAF configurations
and DDoS protection mechanisms.

WARNING: This tool is intended for authorized security testing only.
Only use against systems you own or have explicit permission to test.
Unauthorized use may violate computer crime laws.
"""

import argparse
import sys
import asyncio
from contextlib import redirect_stdout
from typing import Optional, List
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from modules.ddos_simulator import DDoSSimulator, DDoSAttackType
from modules.waf_tester import WAFTester, WAFRuleset
from modules.http_engine import HTTPEngine, HTTPMethod
from modules.bypass_techniques import BypassTechniques
from modules.config import Config
from modules.reporter import Reporter

console = Console()

BANNER = """
╔═══════════════════════════════════════════════════════════════════╗
║           Cloudflare WAF & DDoS Protection Tester                 ║
║                                                                   ║
║  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY                         ║
║  Only test systems you own or have explicit permission to test    ║
╚═══════════════════════════════════════════════════════════════════╝
"""


def display_banner():
    console.print(Panel(BANNER, style="bold red"))


def get_ddos_attack_menu() -> Table:
    table = Table(title="DDoS Attack Types", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", width=4)
    table.add_column("Category", style="green", width=15)
    table.add_column("Attack Type", style="yellow", width=25)
    table.add_column("Description", style="white")
    
    attacks = [
        ("1", "Volumetric", "UDP Flood", "Overwhelm with UDP packets"),
        ("2", "Volumetric", "ICMP Flood", "Ping flood attack"),
        ("3", "Volumetric", "DNS Amplification", "Amplified DNS responses"),
        ("4", "Volumetric", "NTP Amplification", "Amplified NTP responses"),
        ("5", "Protocol", "SYN Flood", "TCP SYN packet flood"),
        ("6", "Protocol", "SYN-ACK Flood", "TCP SYN-ACK reflection"),
        ("7", "Protocol", "ACK Flood", "TCP ACK packet flood"),
        ("8", "Protocol", "RST Flood", "TCP RST packet flood"),
        ("9", "Protocol", "Fragmentation", "IP fragmentation attack"),
        ("10", "Application", "HTTP GET Flood", "HTTP GET request flood"),
        ("11", "Application", "HTTP POST Flood", "HTTP POST request flood"),
        ("12", "Application", "Slowloris", "Slow HTTP headers attack"),
        ("13", "Application", "RUDY", "R-U-Dead-Yet slow POST"),
        ("14", "Application", "Cache Bypass", "Cache-busting requests"),
        ("15", "Multi-Vector", "Combined Attack", "Multiple attack vectors"),
    ]
    
    for attack in attacks:
        table.add_row(*attack)
    
    return table


def get_waf_ruleset_menu() -> Table:
    table = Table(title="WAF Ruleset Options", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", width=4)
    table.add_column("Ruleset", style="green", width=30)
    table.add_column("Description", style="white")
    
    rulesets = [
        ("1", "Cloudflare OWASP Core Ruleset", "OWASP ModSecurity CRS implementation"),
        ("2", "Cloudflare Managed Ruleset", "Cloudflare's proprietary WAF rules"),
        ("3", "Both Rulesets", "Test against both rulesets"),
    ]
    
    for ruleset in rulesets:
        table.add_row(*ruleset)
    
    return table


def get_http_engine_menu() -> Table:
    table = Table(title="HTTP Request Engines", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", width=4)
    table.add_column("Engine", style="green", width=20)
    table.add_column("Description", style="white")
    
    engines = [
        ("1", "aiohttp", "Async HTTP client (fast, Python)"),
        ("2", "httpx", "Modern async HTTP client"),
        ("3", "requests", "Synchronous HTTP library"),
        ("4", "selenium", "Browser automation (bypasses JS challenges)"),
        ("5", "playwright", "Modern browser automation"),
        ("6", "curl_cffi", "curl with browser impersonation"),
        ("7", "go-http", "Go HTTP client via subprocess"),
    ]
    
    for engine in engines:
        table.add_row(*engine)
    
    return table


def interactive_mode():
    """Run the tool in interactive mode."""
    display_banner()
    
    if not Confirm.ask("\n[bold yellow]Do you have authorization to test the target systems?[/]"):
        console.print("[bold red]Exiting. Only test systems you have permission to test.[/]")
        sys.exit(1)
    
    console.print("\n[bold cyan]Select Test Type:[/]")
    console.print("  1. DDoS Protection Testing")
    console.print("  2. WAF Ruleset Testing")
    console.print("  3. Combined Testing")
    
    test_type = Prompt.ask("Enter selection", choices=["1", "2", "3"], default="2")
    
    targets = Prompt.ask("\n[bold cyan]Enter target hostname(s)[/] (comma-separated)")
    target_list = [t.strip() for t in targets.split(",")]
    
    console.print("\n")
    console.print(get_http_engine_menu())
    engine_choice = Prompt.ask("Select HTTP engine", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
    
    engine_map = {
        "1": "aiohttp",
        "2": "httpx", 
        "3": "requests",
        "4": "selenium",
        "5": "playwright",
        "6": "curl_cffi",
        "7": "go-http"
    }
    selected_engine = engine_map[engine_choice]
    
    use_bypass = Confirm.ask("\n[bold yellow]Enable Cloudflare bypass techniques?[/]", default=False)
    
    config = Config(
        targets=target_list,
        http_engine=selected_engine,
        use_bypass_techniques=use_bypass
    )
    
    if test_type in ["1", "3"]:
        console.print("\n")
        console.print(get_ddos_attack_menu())
        attack_choice = Prompt.ask("Select DDoS attack type", default="10")
        
        use_aggressive = Confirm.ask("\n[bold yellow]Use aggressive settings?[/] (10k requests, 200 concurrency, 5 waves)", default=True)
        
        if use_aggressive:
            request_count = 10000
            concurrency = 200
            waves = 5
            console.print("[yellow]Using aggressive settings for DDoS testing[/]")
        else:
            request_count = int(Prompt.ask("Requests per wave", default="5000"))
            concurrency = int(Prompt.ask("Concurrent connections", default="100"))
            waves = int(Prompt.ask("Number of attack waves", default="3"))
        
        config.ddos_attack_type = int(attack_choice)
        config.request_count = request_count
        config.concurrency = concurrency
        config.ddos_waves = waves
        config.ddos_ramp_up = True
    
    if test_type in ["2", "3"]:
        console.print("\n")
        console.print(get_waf_ruleset_menu())
        ruleset_choice = Prompt.ask("Select WAF ruleset to test", choices=["1", "2", "3"], default="3")
        
        ruleset_map = {
            "1": WAFRuleset.OWASP,
            "2": WAFRuleset.CLOUDFLARE_MANAGED,
            "3": WAFRuleset.BOTH
        }
        config.waf_ruleset = ruleset_map[ruleset_choice]
    
    run_tests(config, test_type, output_file=None)


def run_tests(config: Config, test_type: str, output_file: str = None, output_stream=None):
    """Execute the configured tests."""
    config.validate()
    reporter = Reporter(
        output_file=output_file,
        config=config,
        output_format=config.output_format,
        baseline_file=config.baseline_file,
        output_stream=output_stream,
    )
    if config.output_dir and not output_file:
        extension = {"text": "txt", "junit": "xml"}.get(config.output_format, config.output_format or "json")
        reporter.output_file = str(Path(config.output_dir) / reporter.run_id / f"report.{extension}")
    
    console.print("\n[bold green]Starting tests...[/]\n")
    
    http_engine = HTTPEngine(
        config.http_engine,
        config.use_bypass_techniques,
        request_options={
            "ssl_verify": config.ssl_verify,
            "follow_redirects": config.follow_redirects,
            "max_redirects": config.max_redirects,
        },
    )
    
    if config.use_bypass_techniques:
        bypass = BypassTechniques()
        http_engine.set_bypass_techniques(bypass)
    
    if test_type in ["1", "3"]:
        console.print("[bold cyan]Running DDoS Protection Tests...[/]")
        ddos_sim = DDoSSimulator(http_engine, config)
        ddos_results = asyncio.run(ddos_sim.run())
        reporter.add_ddos_results(ddos_results)
    
    if test_type in ["2", "3"]:
        console.print("[bold cyan]Running WAF Ruleset Tests...[/]")
        waf_tester = WAFTester(http_engine, config)
        waf_results = asyncio.run(waf_tester.run())
        reporter.add_waf_results(waf_results)
    
    report_data = reporter.generate_report()
    return 2 if report_data["quality_gate"]["status"] == "failed" else 0


def cli_mode(args, output_stream=None):
    """Run the tool in CLI mode."""
    display_banner()
    
    if not args.accept_responsibility:
        console.print("[bold red]You must accept responsibility with --accept-responsibility flag[/]")
        sys.exit(1)
    
    if args.aggressive:
        request_count = 10000
        concurrency = 200
        waves = 5
        console.print("[bold yellow]AGGRESSIVE MODE ENABLED[/]")
        console.print(f"[yellow]Requests: {request_count:,}, Concurrency: {concurrency}, Waves: {waves}[/]\n")
    else:
        request_count = args.requests
        concurrency = args.concurrency
        waves = args.ddos_waves
    
    config = Config(
        targets=args.targets.split(","),
        http_engine=args.engine,
        use_bypass_techniques=args.bypass,
        request_count=request_count,
        concurrency=concurrency,
        ddos_waves=waves,
        ddos_wave_delay=args.ddos_wave_delay,
        ddos_ramp_up=not args.no_ramp_up,
        output_file=args.output,
        output_format=args.output_format,
        output_dir=args.output_dir,
        baseline_file=args.baseline,
        include_response_body=args.include_response_body,
        min_protection_score=args.min_protection_score,
        max_bypasses=args.max_bypasses,
        max_transport_errors=args.max_transport_errors,
        follow_redirects=args.follow_redirects,
        max_redirects=args.max_redirects,
        verbose=args.verbose,
    )
    
    test_type = "3"
    if args.ddos_only:
        test_type = "1"
        config.ddos_attack_type = args.ddos_type
    elif args.waf_only:
        test_type = "2"
        ruleset_map = {
            "owasp": WAFRuleset.OWASP,
            "managed": WAFRuleset.CLOUDFLARE_MANAGED,
            "both": WAFRuleset.BOTH
        }
        config.waf_ruleset = ruleset_map.get(args.waf_ruleset, WAFRuleset.BOTH)
    else:
        config.ddos_attack_type = args.ddos_type
        ruleset_map = {
            "owasp": WAFRuleset.OWASP,
            "managed": WAFRuleset.CLOUDFLARE_MANAGED,
            "both": WAFRuleset.BOTH
        }
        config.waf_ruleset = ruleset_map.get(args.waf_ruleset, WAFRuleset.BOTH)
    
    return run_tests(config, test_type, output_file=args.output, output_stream=output_stream)


def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare WAF & DDoS Protection Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python cf_waf_tester.py
  
  # CLI mode - WAF testing only
  python cf_waf_tester.py --targets example.com --waf-only --waf-ruleset owasp --accept-responsibility
  
  # CLI mode - DDoS testing (default: 5k requests x 3 waves = 15k total)
  python cf_waf_tester.py --targets example.com --ddos-only --ddos-type 10 --accept-responsibility
  
  # CLI mode - Aggressive DDoS testing (10k requests x 5 waves = 50k total)
  python cf_waf_tester.py --targets example.com --ddos-only --aggressive --accept-responsibility
  
  # CLI mode - Custom DDoS settings
  python cf_waf_tester.py --targets example.com --ddos-only --requests 20000 --concurrency 500 --ddos-waves 5 --accept-responsibility
  
  # CLI mode - Full testing with bypass techniques
  python cf_waf_tester.py --targets example.com --bypass --engine selenium --accept-responsibility
        """
    )
    
    parser.add_argument("-t", "--targets", help="Comma-separated list of target hostnames")
    parser.add_argument("-e", "--engine", choices=["aiohttp", "httpx", "requests", "selenium", "playwright", "curl_cffi", "go-http"],
                        default="aiohttp", help="HTTP request engine to use")
    parser.add_argument("-b", "--bypass", action="store_true", help="Enable Cloudflare bypass techniques")
    parser.add_argument("-r", "--requests", type=int, default=5000, help="Number of requests per wave (default: 5000)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Number of concurrent connections (default: 100)")
    parser.add_argument("--follow-redirects", action=argparse.BooleanOptionalAction, default=True,
                        help="Automatically follow redirects, including across hosts (default: enabled)")
    parser.add_argument("--max-redirects", type=int, default=5,
                        help="Maximum redirect hops for non-browser engines (default: 5)")
    
    test_mode = parser.add_mutually_exclusive_group()
    test_mode.add_argument("--ddos-only", action="store_true", help="Only run DDoS protection tests")
    parser.add_argument("--ddos-type", type=int, default=10, help="DDoS attack type (1-15)")
    parser.add_argument("--ddos-waves", type=int, default=3, help="Number of attack waves (default: 3)")
    parser.add_argument("--ddos-wave-delay", type=float, default=2.0, help="Delay between waves in seconds (default: 2.0)")
    parser.add_argument("--no-ramp-up", action="store_true", help="Disable concurrency ramp-up between waves")
    parser.add_argument("--aggressive", action="store_true", help="Use aggressive settings (10k requests, 200 concurrency, 5 waves)")
    
    test_mode.add_argument("--waf-only", action="store_true", help="Only run WAF ruleset tests")
    parser.add_argument("--waf-ruleset", choices=["owasp", "managed", "both"], default="both",
                        help="WAF ruleset to test against")
    
    parser.add_argument("--accept-responsibility", action="store_true",
                        help="Acknowledge authorization to test the targets and any followed redirect destinations")
    
    parser.add_argument("-o", "--output", help="Output report file path")
    parser.add_argument("--output-dir", help="Create a run-ID report directory under this path")
    parser.add_argument("--format", choices=["text", "json", "junit", "sarif"], dest="output_format",
                        help="Report format (otherwise inferred from --output)")
    parser.add_argument("--baseline", help="Previous JSON report to compare against")
    parser.add_argument("--include-response-body", action="store_true",
                        help="Include truncated response bodies in reports (may contain sensitive data)")
    parser.add_argument("--min-protection-score", type=float, help="Fail if protection score is below this value")
    parser.add_argument("--max-bypasses", type=int, help="Fail if successful bypasses exceed this value")
    parser.add_argument("--max-transport-errors", type=int, help="Fail if transport errors exceed this value")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.targets:
        machine_stdout = args.output == "-" and args.output_format in ("json", "junit", "sarif")
        if machine_stdout:
            output_stream = sys.stdout
            with redirect_stdout(sys.stderr):
                return cli_mode(args, output_stream=output_stream)
        return cli_mode(args)
    else:
        return interactive_mode()


if __name__ == "__main__":
    sys.exit(main() or 0)
