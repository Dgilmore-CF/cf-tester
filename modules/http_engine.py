"""HTTP Request Engine module supporting multiple HTTP libraries."""

import asyncio
import random
import subprocess
import json
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class HTTPResponse:
    """Standardized HTTP response object."""
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float
    request_url: str
    final_url: Optional[str] = None
    redirected: bool = False
    redirect_count: int = 0
    cf_ray: Optional[str] = None
    cf_cache_status: Optional[str] = None
    blocked: bool = False
    challenge_presented: bool = False
    error: Optional[str] = None


class BaseHTTPEngine(ABC):
    """Abstract base class for HTTP engines."""
    
    def __init__(self):
        self.bypass_techniques = None
        self.default_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    
    def set_bypass_techniques(self, bypass):
        """Set bypass techniques handler."""
        self.bypass_techniques = bypass
    
    def prepare_headers(self, custom_headers: Optional[Dict] = None) -> Dict[str, str]:
        """Prepare headers with optional bypass techniques."""
        headers = self.default_headers.copy()
        
        if self.bypass_techniques:
            headers.update(self.bypass_techniques.get_headers())
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    @abstractmethod
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        """Make an HTTP request."""
        pass
    
    @abstractmethod
    async def close(self):
        """Close the HTTP client."""
        pass


class AiohttpEngine(BaseHTTPEngine):
    """aiohttp-based HTTP engine."""
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    async def _get_session(self):
        if self.session is None:
            import aiohttp
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            self.session = aiohttp.ClientSession(connector=connector)
        return self.session
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import aiohttp
        import time
        
        session = await self._get_session()
        prepared_headers = self.prepare_headers(headers)
        
        start_time = time.time()
        
        try:
            async with session.request(
                method.value,
                url,
                headers=prepared_headers,
                data=data,
                params=params,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=kwargs.get("ssl_verify", True),
                allow_redirects=kwargs.get("follow_redirects", True),
                max_redirects=kwargs.get("max_redirects", 10)
            ) as response:
                body = await response.text()
                elapsed = time.time() - start_time
                
                resp_headers = dict(response.headers)
                final_url = str(response.url)
                redirected = final_url != url
                redirect_count = len(response.history)
                
                http_response = HTTPResponse(
                    status_code=response.status,
                    headers=resp_headers,
                    body=body,
                    elapsed_time=elapsed,
                    request_url=url,
                    final_url=final_url,
                    redirected=redirected,
                    redirect_count=redirect_count,
                    cf_ray=resp_headers.get("CF-RAY"),
                    cf_cache_status=resp_headers.get("CF-Cache-Status")
                )
                
                http_response.blocked = self._detect_block(response.status, body)
                http_response.challenge_presented = self._detect_challenge(body)
                
                return http_response
                
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    def _detect_block(self, status: int, body: str) -> bool:
        """Detect if the request was blocked by Cloudflare."""
        if status in [403, 503, 429]:
            block_indicators = [
                "cloudflare",
                "cf-browser-verification",
                "blocked",
                "access denied",
                "ray id"
            ]
            body_lower = body.lower()
            return any(indicator in body_lower for indicator in block_indicators)
        return False
    
    def _detect_challenge(self, body: str) -> bool:
        """Detect if a Cloudflare challenge was presented."""
        challenge_indicators = [
            "cf-browser-verification",
            "challenge-platform",
            "turnstile",
            "hcaptcha",
            "recaptcha",
            "jschl_vc",
            "jschl_answer"
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in challenge_indicators)
    
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


class HttpxEngine(BaseHTTPEngine):
    """httpx-based HTTP engine."""
    
    def __init__(self):
        super().__init__()
        self.client = None
    
    async def _get_client(self):
        if self.client is None:
            import httpx
            self.client = httpx.AsyncClient(
                http2=True,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
            )
        return self.client
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import httpx
        import time
        
        client = await self._get_client()
        prepared_headers = self.prepare_headers(headers)
        
        start_time = time.time()
        
        try:
            response = await client.request(
                method.value,
                url,
                headers=prepared_headers,
                data=data,
                params=params,
                timeout=timeout
            )
            elapsed = time.time() - start_time
            
            resp_headers = dict(response.headers)
            final_url = str(response.url)
            redirected = final_url != url
            redirect_count = len(response.history)
            
            http_response = HTTPResponse(
                status_code=response.status_code,
                headers=resp_headers,
                body=response.text,
                elapsed_time=elapsed,
                request_url=url,
                final_url=final_url,
                redirected=redirected,
                redirect_count=redirect_count,
                cf_ray=resp_headers.get("cf-ray"),
                cf_cache_status=resp_headers.get("cf-cache-status")
            )
            
            http_response.blocked = response.status_code in [403, 503, 429]
            http_response.challenge_presented = "challenge" in response.text.lower()
            
            return http_response
            
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    async def close(self):
        if self.client:
            await self.client.aclose()
            self.client = None


class RequestsEngine(BaseHTTPEngine):
    """requests-based HTTP engine (sync, wrapped for async)."""
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    def _get_session(self):
        if self.session is None:
            import requests
            self.session = requests.Session()
        return self.session
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import time
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._sync_request,
            url, method, headers, data, params, timeout, kwargs
        )
    
    def _sync_request(self, url, method, headers, data, params, timeout, kwargs) -> HTTPResponse:
        import requests
        import time
        
        session = self._get_session()
        prepared_headers = self.prepare_headers(headers)
        
        start_time = time.time()
        
        try:
            response = session.request(
                method.value,
                url,
                headers=prepared_headers,
                data=data,
                params=params,
                timeout=timeout,
                verify=kwargs.get("ssl_verify", True),
                allow_redirects=kwargs.get("follow_redirects", True)
            )
            elapsed = time.time() - start_time
            
            resp_headers = dict(response.headers)
            final_url = response.url
            redirected = final_url != url
            redirect_count = len(response.history)
            
            return HTTPResponse(
                status_code=response.status_code,
                headers=resp_headers,
                body=response.text,
                elapsed_time=elapsed,
                request_url=url,
                final_url=final_url,
                redirected=redirected,
                redirect_count=redirect_count,
                cf_ray=resp_headers.get("CF-RAY"),
                cf_cache_status=resp_headers.get("CF-Cache-Status"),
                blocked=response.status_code in [403, 503, 429]
            )
            
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    async def close(self):
        if self.session:
            self.session.close()
            self.session = None


class SeleniumEngine(BaseHTTPEngine):
    """Selenium-based HTTP engine for browser automation."""
    
    def __init__(self):
        super().__init__()
        self.driver = None
    
    def _get_driver(self):
        if self.driver is None:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            
            options = Options()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("useAutomationExtension", False)
            
            if self.bypass_techniques:
                ua = self.bypass_techniques.get_user_agent()
                options.add_argument(f"--user-agent={ua}")
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": """
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                """
            })
        return self.driver
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import time
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._sync_request,
            url, method, timeout
        )
    
    def _sync_request(self, url, method, timeout) -> HTTPResponse:
        import time
        
        driver = self._get_driver()
        driver.set_page_load_timeout(timeout)
        
        start_time = time.time()
        
        try:
            driver.get(url)
            
            time.sleep(2)
            
            elapsed = time.time() - start_time
            body = driver.page_source
            
            challenge_presented = any(x in body.lower() for x in [
                "challenge", "captcha", "cf-browser-verification"
            ])
            
            return HTTPResponse(
                status_code=200,
                headers={},
                body=body,
                elapsed_time=elapsed,
                request_url=url,
                challenge_presented=challenge_presented
            )
            
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    async def close(self):
        if self.driver:
            self.driver.quit()
            self.driver = None


class PlaywrightEngine(BaseHTTPEngine):
    """Playwright-based HTTP engine for browser automation."""
    
    def __init__(self):
        super().__init__()
        self.browser = None
        self.context = None
        self.playwright = None
    
    async def _get_browser(self):
        if self.browser is None:
            from playwright.async_api import async_playwright
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled"
                ]
            )
            
            ua = None
            if self.bypass_techniques:
                ua = self.bypass_techniques.get_user_agent()
            
            self.context = await self.browser.new_context(
                user_agent=ua,
                viewport={"width": 1920, "height": 1080},
                locale="en-US"
            )
            
            await self.context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            """)
        
        return self.context
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import time
        
        context = await self._get_browser()
        page = await context.new_page()
        
        start_time = time.time()
        
        try:
            if headers:
                await page.set_extra_http_headers(headers)
            
            response = await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
            
            elapsed = time.time() - start_time
            body = await page.content()
            
            resp_headers = await response.all_headers() if response else {}
            status_code = response.status if response else 0
            
            http_response = HTTPResponse(
                status_code=status_code,
                headers=resp_headers,
                body=body,
                elapsed_time=elapsed,
                request_url=url,
                cf_ray=resp_headers.get("cf-ray"),
                cf_cache_status=resp_headers.get("cf-cache-status")
            )
            
            http_response.blocked = status_code in [403, 503, 429]
            http_response.challenge_presented = "challenge" in body.lower()
            
            await page.close()
            return http_response
            
        except Exception as e:
            await page.close()
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    async def close(self):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.context = None
        self.browser = None
        self.playwright = None


class CurlCffiEngine(BaseHTTPEngine):
    """curl_cffi-based HTTP engine with browser impersonation."""
    
    def __init__(self):
        super().__init__()
        self.session = None
    
    async def _get_session(self):
        if self.session is None:
            from curl_cffi.requests import AsyncSession
            self.session = AsyncSession(impersonate="chrome120")
        return self.session
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import time
        
        session = await self._get_session()
        prepared_headers = self.prepare_headers(headers)
        
        start_time = time.time()
        
        try:
            response = await session.request(
                method.value,
                url,
                headers=prepared_headers,
                data=data,
                params=params,
                timeout=timeout
            )
            elapsed = time.time() - start_time
            
            resp_headers = dict(response.headers)
            
            return HTTPResponse(
                status_code=response.status_code,
                headers=resp_headers,
                body=response.text,
                elapsed_time=elapsed,
                request_url=url,
                cf_ray=resp_headers.get("cf-ray"),
                cf_cache_status=resp_headers.get("cf-cache-status"),
                blocked=response.status_code in [403, 503, 429]
            )
            
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


class GoHTTPEngine(BaseHTTPEngine):
    """Go HTTP client engine via subprocess."""
    
    GO_CLIENT_CODE = '''
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
)

type Request struct {
    URL     string            `json:"url"`
    Method  string            `json:"method"`
    Headers map[string]string `json:"headers"`
    Body    string            `json:"body"`
    Timeout int               `json:"timeout"`
}

type Response struct {
    StatusCode  int               `json:"status_code"`
    Headers     map[string]string `json:"headers"`
    Body        string            `json:"body"`
    ElapsedTime float64           `json:"elapsed_time"`
    Error       string            `json:"error,omitempty"`
}

func main() {
    var req Request
    if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
        json.NewEncoder(os.Stdout).Encode(Response{Error: err.Error()})
        return
    }

    client := &http.Client{
        Timeout: time.Duration(req.Timeout) * time.Second,
    }

    httpReq, err := http.NewRequest(req.Method, req.URL, nil)
    if err != nil {
        json.NewEncoder(os.Stdout).Encode(Response{Error: err.Error()})
        return
    }

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    start := time.Now()
    resp, err := client.Do(httpReq)
    elapsed := time.Since(start).Seconds()

    if err != nil {
        json.NewEncoder(os.Stdout).Encode(Response{
            ElapsedTime: elapsed,
            Error:       err.Error(),
        })
        return
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    headers := make(map[string]string)
    for k, v := range resp.Header {
        if len(v) > 0 {
            headers[k] = v[0]
        }
    }

    json.NewEncoder(os.Stdout).Encode(Response{
        StatusCode:  resp.StatusCode,
        Headers:     headers,
        Body:        string(body),
        ElapsedTime: elapsed,
    })
}
'''
    
    def __init__(self):
        super().__init__()
        self.go_binary = None
    
    async def request(
        self,
        url: str,
        method: HTTPMethod = HTTPMethod.GET,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        timeout: int = 30,
        **kwargs
    ) -> HTTPResponse:
        import time
        
        prepared_headers = self.prepare_headers(headers)
        
        request_data = {
            "url": url,
            "method": method.value,
            "headers": prepared_headers,
            "body": data if isinstance(data, str) else "",
            "timeout": timeout
        }
        
        start_time = time.time()
        
        try:
            process = await asyncio.create_subprocess_exec(
                "go", "run", "-",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            input_data = self.GO_CLIENT_CODE + "\n"
            stdout, stderr = await process.communicate(
                input=json.dumps(request_data).encode()
            )
            
            if process.returncode != 0:
                raise Exception(f"Go process failed: {stderr.decode()}")
            
            result = json.loads(stdout.decode())
            elapsed = time.time() - start_time
            
            return HTTPResponse(
                status_code=result.get("status_code", 0),
                headers=result.get("headers", {}),
                body=result.get("body", ""),
                elapsed_time=result.get("elapsed_time", elapsed),
                request_url=url,
                cf_ray=result.get("headers", {}).get("Cf-Ray"),
                error=result.get("error")
            )
            
        except Exception as e:
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_time=time.time() - start_time,
                request_url=url,
                error=str(e)
            )
    
    async def close(self):
        pass


class HTTPEngine:
    """Factory class for HTTP engines."""
    
    ENGINES = {
        "aiohttp": AiohttpEngine,
        "httpx": HttpxEngine,
        "requests": RequestsEngine,
        "selenium": SeleniumEngine,
        "playwright": PlaywrightEngine,
        "curl_cffi": CurlCffiEngine,
        "go-http": GoHTTPEngine
    }
    
    def __init__(self, engine_name: str = "aiohttp", use_bypass: bool = False):
        if engine_name not in self.ENGINES:
            raise ValueError(f"Unknown engine: {engine_name}. Available: {list(self.ENGINES.keys())}")
        
        self.engine_name = engine_name
        self.engine = self.ENGINES[engine_name]()
        self.use_bypass = use_bypass
        self.bypass_techniques = None
    
    def set_bypass_techniques(self, bypass):
        """Set bypass techniques for the engine."""
        self.bypass_techniques = bypass
        self.engine.set_bypass_techniques(bypass)
    
    async def request(self, *args, **kwargs) -> HTTPResponse:
        """Make an HTTP request using the configured engine."""
        return await self.engine.request(*args, **kwargs)
    
    async def batch_request(
        self,
        requests: List[Tuple[str, HTTPMethod, Optional[Dict]]],
        concurrency: int = 10
    ) -> List[HTTPResponse]:
        """Make multiple HTTP requests with concurrency control."""
        semaphore = asyncio.Semaphore(concurrency)
        
        async def bounded_request(url, method, headers):
            async with semaphore:
                return await self.request(url, method, headers)
        
        tasks = [bounded_request(url, method, headers) for url, method, headers in requests]
        return await asyncio.gather(*tasks)
    
    async def close(self):
        """Close the HTTP engine."""
        await self.engine.close()
