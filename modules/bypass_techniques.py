"""Cloudflare bypass techniques module."""

import random
import string
import base64
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class BypassResult:
    """Result of a bypass attempt."""
    technique: str
    success: bool
    response_code: int
    details: str


class BypassTechniques:
    """Collection of Cloudflare bypass techniques for authorized penetration testing."""
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    ]
    
    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,es;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8",
    ]
    
    REFERERS = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "https://www.yahoo.com/",
        "https://search.brave.com/",
    ]
    
    def __init__(self, rotate_user_agents: bool = True, rotate_headers: bool = True):
        self.rotate_user_agents = rotate_user_agents
        self.rotate_headers = rotate_headers
        self.current_ua_index = 0
        self.request_count = 0
    
    def get_user_agent(self) -> str:
        """Get a user agent string."""
        if self.rotate_user_agents:
            return random.choice(self.USER_AGENTS)
        return self.USER_AGENTS[0]
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers with bypass techniques applied."""
        headers = {
            "User-Agent": self.get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGES) if self.rotate_headers else self.ACCEPT_LANGUAGES[0],
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Cache-Control": "max-age=0",
        }
        
        if random.random() > 0.5:
            headers["Referer"] = random.choice(self.REFERERS)
        
        return headers
    
    def get_origin_ip_headers(self, origin_ip: str) -> Dict[str, str]:
        """
        Headers that might reveal the origin IP if misconfigured.
        Used for testing origin IP exposure vulnerabilities.
        """
        return {
            "X-Forwarded-For": origin_ip,
            "X-Real-IP": origin_ip,
            "X-Originating-IP": origin_ip,
            "X-Remote-IP": origin_ip,
            "X-Remote-Addr": origin_ip,
            "X-Client-IP": origin_ip,
            "X-Host": origin_ip,
            "X-Forwarded-Host": origin_ip,
            "CF-Connecting-IP": origin_ip,
            "True-Client-IP": origin_ip,
            "Forwarded": f"for={origin_ip}",
        }
    
    def get_cache_bypass_params(self) -> Dict[str, str]:
        """Generate parameters to bypass Cloudflare cache."""
        return {
            "_": str(int(time.time() * 1000)),
            "cb": ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
            "nocache": "true",
            "rand": str(random.randint(100000, 999999)),
        }
    
    def get_cache_bypass_headers(self) -> Dict[str, str]:
        """Headers to attempt cache bypass."""
        return {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    
    def get_rate_limit_evasion_headers(self) -> Dict[str, str]:
        """
        Headers that might help evade rate limiting.
        Note: Effectiveness depends on target configuration.
        """
        fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        return {
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
            "CF-Connecting-IP": fake_ip,
        }
    
    def get_waf_evasion_encoding(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate various encodings of a payload to test WAF evasion.
        Returns list of (encoding_name, encoded_payload) tuples.
        """
        encodings = []
        
        encodings.append(("original", payload))
        
        url_encoded = ''.join(f'%{ord(c):02X}' for c in payload)
        encodings.append(("url_encoded", url_encoded))
        
        double_url = ''.join(f'%25{ord(c):02X}' for c in payload)
        encodings.append(("double_url_encoded", double_url))
        
        b64 = base64.b64encode(payload.encode()).decode()
        encodings.append(("base64", b64))
        
        unicode_enc = ''.join(f'\\u{ord(c):04x}' for c in payload)
        encodings.append(("unicode", unicode_enc))
        
        hex_enc = ''.join(f'\\x{ord(c):02x}' for c in payload)
        encodings.append(("hex", hex_enc))
        
        html_entities = ''.join(f'&#{ord(c)};' for c in payload)
        encodings.append(("html_entities", html_entities))
        
        html_hex = ''.join(f'&#x{ord(c):x};' for c in payload)
        encodings.append(("html_hex_entities", html_hex))
        
        mixed_case = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
        encodings.append(("mixed_case", mixed_case))
        
        with_nulls = '\x00'.join(payload)
        encodings.append(("null_bytes", with_nulls))
        
        with_comments = payload.replace(" ", "/**/")
        encodings.append(("sql_comments", with_comments))
        
        return encodings
    
    def get_protocol_bypass_urls(self, base_url: str) -> List[str]:
        """Generate URL variations for protocol-level bypass attempts."""
        from urllib.parse import urlparse, urlunparse
        
        parsed = urlparse(base_url)
        urls = [base_url]
        
        if parsed.path:
            doubled_slash = parsed._replace(path="//" + parsed.path.lstrip("/"))
            urls.append(urlunparse(doubled_slash))
        
        if parsed.path:
            dot_path = parsed._replace(path=parsed.path + "/.")
            urls.append(urlunparse(dot_path))
            
            dotdot_path = parsed._replace(path=parsed.path + "/..")
            urls.append(urlunparse(dotdot_path))
        
        if parsed.path:
            path_with_params = parsed._replace(path=parsed.path + ";")
            urls.append(urlunparse(path_with_params))
        
        if parsed.path:
            encoded_path = parsed._replace(path=parsed.path.replace("/", "%2f"))
            urls.append(urlunparse(encoded_path))
        
        return urls
    
    def get_http_method_override_headers(self, target_method: str) -> Dict[str, str]:
        """Headers to attempt HTTP method override."""
        return {
            "X-HTTP-Method-Override": target_method,
            "X-HTTP-Method": target_method,
            "X-Method-Override": target_method,
        }
    
    def get_content_type_variations(self) -> List[str]:
        """Content-Type variations that might bypass WAF inspection."""
        return [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "text/xml",
            "application/xml",
            "application/json; charset=utf-8",
            "application/x-www-form-urlencoded; charset=utf-8",
            "multipart/form-data; boundary=----WebKitFormBoundary",
            "application/octet-stream",
        ]
    
    def get_chunked_payload(self, payload: str, chunk_size: int = 5) -> str:
        """
        Generate chunked transfer encoding payload.
        Some WAFs have issues with chunked requests.
        """
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        return ''.join(chunks)
    
    def get_json_bypass_payloads(self, payload: str) -> List[Dict]:
        """Generate JSON payload variations for WAF bypass."""
        return [
            {"data": payload},
            {"data": [payload]},
            {"data": {"nested": payload}},
            {"data": {"nested": {"deep": payload}}},
            {f"data{i}": payload for i in range(5)},
            {"data": payload, "dummy": "A" * 1000},
            {"data": [payload] * 10},
        ]
    
    def get_header_injection_payloads(self) -> List[Tuple[str, str]]:
        """
        Header injection test payloads.
        Tests for CRLF injection and header manipulation.
        """
        return [
            ("X-Custom-Header", "value\r\nX-Injected: true"),
            ("X-Custom-Header", "value%0d%0aX-Injected: true"),
            ("X-Custom-Header", "value\nX-Injected: true"),
            ("X-Custom-Header", "value%0aX-Injected: true"),
            ("X-Forwarded-For", "127.0.0.1, 8.8.8.8"),
        ]
    
    def get_websocket_bypass_headers(self) -> Dict[str, str]:
        """Headers to attempt WebSocket upgrade (sometimes bypasses WAF)."""
        return {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(random.randbytes(16)).decode(),
            "Sec-WebSocket-Version": "13",
        }
    
    def apply_random_delay(self, min_delay: float = 0.1, max_delay: float = 2.0) -> float:
        """
        Apply random delay to mimic human behavior.
        Returns the delay applied in seconds.
        """
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        return delay
    
    def get_browser_fingerprint_headers(self) -> Dict[str, str]:
        """Generate realistic browser fingerprint headers."""
        canvas_hash = hashlib.md5(str(random.random()).encode()).hexdigest()[:16]
        
        return {
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
            "Sec-Ch-Ua-Platform-Version": f'"{random.randint(10, 14)}.0.0"',
            "Sec-Ch-Ua-Full-Version-List": '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.130", "Google Chrome";v="120.0.6099.130"',
            "Sec-Ch-Ua-Arch": '"x86"',
            "Sec-Ch-Ua-Bitness": '"64"',
            "Sec-Ch-Ua-Model": '""',
        }
    
    def dns_over_https_resolve(self, domain: str) -> Optional[List[str]]:
        """
        Resolve domain using DNS over HTTPS to find potential origin IPs.
        This helps identify if origin IP is exposed.
        """
        import urllib.request
        import json
        
        doh_providers = [
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
            f"https://dns.google/resolve?name={domain}&type=A",
        ]
        
        for provider in doh_providers:
            try:
                req = urllib.request.Request(provider, headers={"Accept": "application/dns-json"})
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    if "Answer" in data:
                        return [ans["data"] for ans in data["Answer"] if ans.get("type") == 1]
            except Exception:
                continue
        
        return None
    
    def check_origin_exposure(self, domain: str) -> Dict[str, any]:
        """
        Check various methods that might expose the origin IP.
        Useful for testing if Cloudflare is properly configured.
        """
        results = {
            "domain": domain,
            "potential_origins": [],
            "methods_checked": []
        }
        
        dns_results = self.dns_over_https_resolve(domain)
        if dns_results:
            results["methods_checked"].append("dns_resolution")
            results["potential_origins"].extend(dns_results)
        
        subdomains_to_check = [
            f"direct.{domain}",
            f"origin.{domain}",
            f"mail.{domain}",
            f"ftp.{domain}",
            f"cpanel.{domain}",
            f"webmail.{domain}",
            f"staging.{domain}",
            f"dev.{domain}",
            f"api.{domain}",
        ]
        
        results["subdomains_to_check"] = subdomains_to_check
        
        return results


class TLSFingerprintBypass:
    """TLS fingerprint manipulation for bypass attempts."""
    
    CHROME_CIPHER_SUITES = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384", 
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ]
    
    FIREFOX_CIPHER_SUITES = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ]
    
    @staticmethod
    def get_tls_config_for_browser(browser: str = "chrome") -> Dict:
        """Get TLS configuration mimicking a specific browser."""
        configs = {
            "chrome": {
                "cipher_suites": TLSFingerprintBypass.CHROME_CIPHER_SUITES,
                "extensions": ["server_name", "ec_point_formats", "supported_groups"],
                "alpn": ["h2", "http/1.1"],
            },
            "firefox": {
                "cipher_suites": TLSFingerprintBypass.FIREFOX_CIPHER_SUITES,
                "extensions": ["server_name", "ec_point_formats", "supported_groups"],
                "alpn": ["h2", "http/1.1"],
            }
        }
        return configs.get(browser, configs["chrome"])
