"""Configuration module for Cloudflare WAF Tester."""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum, auto


class WAFRuleset(Enum):
    OWASP = auto()
    CLOUDFLARE_MANAGED = auto()
    BOTH = auto()


@dataclass
class Config:
    """Configuration for the WAF/DDoS tester."""
    
    targets: List[str] = field(default_factory=list)
    http_engine: str = "aiohttp"
    use_bypass_techniques: bool = False
    request_count: int = 5000
    concurrency: int = 100
    timeout: int = 30
    
    ddos_attack_type: int = 10
    ddos_duration: int = 60
    ddos_rate_limit: Optional[int] = None
    ddos_waves: int = 3
    ddos_wave_delay: float = 2.0
    ddos_burst_mode: bool = True
    ddos_sustained: bool = False
    ddos_ramp_up: bool = True
    
    waf_ruleset: WAFRuleset = WAFRuleset.BOTH
    waf_test_all_categories: bool = True
    waf_categories: List[str] = field(default_factory=list)
    
    proxy: Optional[str] = None
    proxy_list: List[str] = field(default_factory=list)
    rotate_proxies: bool = False
    
    user_agent_rotation: bool = True
    custom_headers: dict = field(default_factory=dict)
    
    output_file: Optional[str] = None
    output_format: Optional[str] = None
    output_dir: Optional[str] = None
    baseline_file: Optional[str] = None
    include_response_body: bool = False
    verbose: bool = False
    debug: bool = False

    min_protection_score: Optional[float] = None
    max_bypasses: Optional[int] = None
    max_transport_errors: Optional[int] = None
    
    ssl_verify: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    
    retry_count: int = 3
    retry_delay: float = 1.0
    
    def validate(self) -> bool:
        """Validate the configuration."""
        if not self.targets:
            raise ValueError("At least one target must be specified")
        
        if self.request_count < 1:
            raise ValueError("Request count must be at least 1")
        
        if self.concurrency < 1:
            raise ValueError("Concurrency must be at least 1")
        
        if self.ddos_attack_type < 1 or self.ddos_attack_type > 15:
            raise ValueError("DDoS attack type must be between 1 and 15")

        if self.min_protection_score is not None and not 0 <= self.min_protection_score <= 100:
            raise ValueError("Minimum protection score must be between 0 and 100")

        if self.max_bypasses is not None and self.max_bypasses < 0:
            raise ValueError("Maximum bypasses cannot be negative")

        if self.max_transport_errors is not None and self.max_transport_errors < 0:
            raise ValueError("Maximum transport errors cannot be negative")
        
        return True
    
    def get_target_urls(self) -> List[str]:
        """Get properly formatted target URLs."""
        urls = []
        for target in self.targets:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            urls.append(target)
        return urls
