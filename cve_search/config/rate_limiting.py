"""Rate limiting configuration and management."""

import time
from datetime import datetime
from threading import Lock


class RateLimiter:
    """Rate limiter implementation for API calls."""
    
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self.lock = Lock()
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        with self.lock:
            now = datetime.now()
            # Remove old requests outside the time window
            self.requests = [req_time for req_time in self.requests 
                           if (now - req_time).total_seconds() < self.time_window]
            
            if len(self.requests) >= self.max_requests:
                oldest_request = min(self.requests)
                wait_time = self.time_window - (now - oldest_request).total_seconds()
                if wait_time > 0:
                    print(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
                    time.sleep(wait_time + 1)  # Add 1 second buffer
                    # Clean up again after waiting
                    now = datetime.now()
                    self.requests = [req_time for req_time in self.requests 
                                   if (now - req_time).total_seconds() < self.time_window]
            
            self.requests.append(now)


# Initialize rate limiters for different services
gemini_rate_limiter = RateLimiter(max_requests=15, time_window=60)  # 15 requests per minute
nist_rate_limiter = RateLimiter(max_requests=10, time_window=60)     # 10 requests per minute  
cve_org_rate_limiter = RateLimiter(max_requests=5, time_window=60)   # 5 requests per minute
tavily_rate_limiter = RateLimiter(max_requests=20, time_window=60)   # 20 requests per minute


def get_rate_limiter_status():
    """Get current status of all rate limiters."""
    now = datetime.now()
    status = {
        "gemini": {
            "requests_in_window": len([req for req in gemini_rate_limiter.requests 
                                     if (now - req).total_seconds() < gemini_rate_limiter.time_window]),
            "max_requests": gemini_rate_limiter.max_requests,
            "time_window": gemini_rate_limiter.time_window
        },
        "nist": {
            "requests_in_window": len([req for req in nist_rate_limiter.requests 
                                     if (now - req).total_seconds() < nist_rate_limiter.time_window]),
            "max_requests": nist_rate_limiter.max_requests,
            "time_window": nist_rate_limiter.time_window
        },
        "cve_org": {
            "requests_in_window": len([req for req in cve_org_rate_limiter.requests 
                                     if (now - req).total_seconds() < cve_org_rate_limiter.time_window]),
            "max_requests": cve_org_rate_limiter.max_requests,
            "time_window": cve_org_rate_limiter.time_window
        },
        "tavily": {
            "requests_in_window": len([req for req in tavily_rate_limiter.requests 
                                     if (now - req).total_seconds() < tavily_rate_limiter.time_window]),
            "max_requests": tavily_rate_limiter.max_requests,
            "time_window": tavily_rate_limiter.time_window
        }
    }
    return status


def reset_rate_limiters():
    """Reset all rate limiters (useful for testing)."""
    global gemini_rate_limiter, nist_rate_limiter, cve_org_rate_limiter, tavily_rate_limiter
    
    gemini_rate_limiter = RateLimiter(max_requests=15, time_window=60)
    nist_rate_limiter = RateLimiter(max_requests=10, time_window=60)
    cve_org_rate_limiter = RateLimiter(max_requests=5, time_window=60)
    tavily_rate_limiter = RateLimiter(max_requests=20, time_window=60)
    
    print("All rate limiters have been reset.")