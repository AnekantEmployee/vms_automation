"""Configuration settings for CVE search system."""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Timeout configurations
TIMEOUT_CONFIG = {
    'gemini_api': 30,
    'nist_api': 45,
    'cve_org_api': 45,
    'tavily_api': 30,
    'osv_api': 30,  # Add OSV timeout
    'default': 30
}

# Retry configurations
RETRY_CONFIG = {
    'max_retries': 3,
    'base_delay': 2,
    'max_delay': 60,
    'backoff_multiplier': 2
}


class CVESearchConfig:
    """Configuration management for CVE search system."""
    
    def __init__(self):
        self.rate_limits = {
            'gemini': {'max_requests': 15, 'time_window': 60},
            'nist': {'max_requests': 10, 'time_window': 60},
            'cve_org': {'max_requests': 5, 'time_window': 60},
            'tavily': {'max_requests': 20, 'time_window': 60}
        }
        
        self.timeouts = TIMEOUT_CONFIG.copy()
        self.retry_config = RETRY_CONFIG.copy()
    
    def update_rate_limit(self, service: str, max_requests: int, time_window: int):
        """Update rate limit for a specific service."""
        if service in self.rate_limits:
            self.rate_limits[service] = {
                'max_requests': max_requests,
                'time_window': time_window
            }
            print(f"Updated rate limit for {service}: {max_requests} requests per {time_window} seconds")
        else:
            print(f"Unknown service: {service}")
    
    def update_timeout(self, api: str, timeout: int):
        """Update timeout for a specific API."""
        if api in self.timeouts:
            self.timeouts[api] = timeout
            print(f"Updated timeout for {api}: {timeout} seconds")
        else:
            print(f"Unknown API: {api}")
    
    def get_config(self):
        """Get current configuration."""
        return {
            'rate_limits': self.rate_limits,
            'timeouts': self.timeouts,
            'retry_config': self.retry_config
        }


# Initialize global config
cve_config = CVESearchConfig()