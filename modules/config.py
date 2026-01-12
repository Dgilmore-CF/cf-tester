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
    request_count: int = 100
    concurrency: int = 10
    timeout: int = 30
    
    ddos_attack_type: int = 10
    ddos_duration: int = 60
    ddos_rate_limit: Optional[int] = None
    
    waf_ruleset: WAFRuleset = WAFRuleset.BOTH
    waf_test_all_categories: bool = True
    waf_categories: List[str] = field(default_factory=list)
    
    proxy: Optional[str] = None
    proxy_list: List[str] = field(default_factory=list)
    rotate_proxies: bool = False
    
    user_agent_rotation: bool = True
    custom_headers: dict = field(default_factory=dict)
    
    output_file: Optional[str] = None
    verbose: bool = False
    debug: bool = False
    
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
        
        return True
    
    def get_target_urls(self) -> List[str]:
        """Get properly formatted target URLs."""
        urls = []
        for target in self.targets:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            urls.append(target)
        return urls
