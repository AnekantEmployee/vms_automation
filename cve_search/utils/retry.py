"""Retry mechanism utilities for CVE search system."""

import time
import random
from ..config.settings import RETRY_CONFIG


def exponential_backoff_retry(func, max_retries=None, base_delay=None, max_delay=None, backoff_multiplier=None):
    """Decorator for exponential backoff retry logic."""
    
    # Use default config if not specified
    max_retries = max_retries or RETRY_CONFIG['max_retries']
    base_delay = base_delay or RETRY_CONFIG['base_delay']
    max_delay = max_delay or RETRY_CONFIG['max_delay']
    backoff_multiplier = backoff_multiplier or RETRY_CONFIG['backoff_multiplier']
    
    def wrapper(*args, **kwargs):
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt == max_retries:
                    print(f"Max retries ({max_retries}) reached for {func.__name__}")
                    raise last_exception
                
                # Calculate delay with jitter
                delay = min(base_delay * (backoff_multiplier ** attempt), max_delay)
                jitter = random.uniform(0.1, 0.3) * delay
                total_delay = delay + jitter
                
                print(f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}")
                print(f"Retrying in {total_delay:.2f} seconds...")
                time.sleep(total_delay)
        
        raise last_exception
    
    return wrapper