"""Enhanced quota management for API services."""

import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class QuotaInfo:
    """Track quota usage for an API key."""
    daily_requests: int = 0
    last_reset: str = ""
    is_exhausted: bool = False
    retry_after: Optional[int] = None
    last_error: Optional[str] = None

class QuotaManager:
    """Manage API quotas across multiple keys."""
    
    def __init__(self, quota_file: str = "quota_status.json"):
        self.quota_file = Path(__file__).parent / quota_file
        self.quotas: Dict[str, QuotaInfo] = {}
        self.daily_limit = 20  # Gemini free tier limit
        self.load_quota_data()
    
    def load_quota_data(self):
        """Load quota data from file."""
        if self.quota_file.exists():
            try:
                with open(self.quota_file, 'r') as f:
                    data = json.load(f)
                    for key_hash, quota_data in data.items():
                        self.quotas[key_hash] = QuotaInfo(**quota_data)
            except Exception as e:
                print(f"Error loading quota data: {e}")
    
    def save_quota_data(self):
        """Save quota data to file."""
        try:
            data = {key_hash: asdict(quota) for key_hash, quota in self.quotas.items()}
            with open(self.quota_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving quota data: {e}")
    
    def _hash_key(self, api_key: str) -> str:
        """Create a hash of the API key for storage."""
        import hashlib
        return hashlib.md5(api_key.encode()).hexdigest()[:8]
    
    def _is_new_day(self, last_reset: str) -> bool:
        """Check if it's a new day since last reset."""
        if not last_reset:
            return True
        try:
            last_date = datetime.fromisoformat(last_reset).date()
            return datetime.now().date() > last_date
        except:
            return True
    
    def reset_daily_quota_if_needed(self, api_key: str):
        """Reset daily quota if it's a new day."""
        key_hash = self._hash_key(api_key)
        
        if key_hash not in self.quotas:
            self.quotas[key_hash] = QuotaInfo()
        
        quota = self.quotas[key_hash]
        if self._is_new_day(quota.last_reset):
            quota.daily_requests = 0
            quota.is_exhausted = False
            quota.retry_after = None
            quota.last_reset = datetime.now().isoformat()
            quota.last_error = None
            self.save_quota_data()
    
    def can_use_key(self, api_key: str) -> bool:
        """Check if an API key can be used."""
        self.reset_daily_quota_if_needed(api_key)
        key_hash = self._hash_key(api_key)
        
        if key_hash not in self.quotas:
            return True
        
        quota = self.quotas[key_hash]
        
        # Check if retry period has passed
        if quota.retry_after:
            if time.time() < quota.retry_after:
                return False
            else:
                quota.retry_after = None
                quota.is_exhausted = False
        
        return not quota.is_exhausted and quota.daily_requests < self.daily_limit
    
    def record_request(self, api_key: str):
        """Record a successful request."""
        self.reset_daily_quota_if_needed(api_key)
        key_hash = self._hash_key(api_key)
        
        if key_hash not in self.quotas:
            self.quotas[key_hash] = QuotaInfo()
        
        self.quotas[key_hash].daily_requests += 1
        self.save_quota_data()
    
    def record_quota_error(self, api_key: str, error_msg: str, retry_delay: int = 3600):
        """Record a quota exceeded error."""
        key_hash = self._hash_key(api_key)
        
        if key_hash not in self.quotas:
            self.quotas[key_hash] = QuotaInfo()
        
        quota = self.quotas[key_hash]
        quota.is_exhausted = True
        quota.retry_after = time.time() + retry_delay
        quota.last_error = error_msg
        self.save_quota_data()
    
    def get_available_keys(self, all_keys: List[str]) -> List[str]:
        """Get list of available API keys."""
        available = []
        for key in all_keys:
            if self.can_use_key(key):
                available.append(key)
        return available
    
    def get_quota_status(self, all_keys: List[str]) -> Dict:
        """Get quota status for all keys."""
        status = {
            "total_keys": len(all_keys),
            "available_keys": 0,
            "exhausted_keys": 0,
            "keys": []
        }
        
        for i, key in enumerate(all_keys):
            self.reset_daily_quota_if_needed(key)
            key_hash = self._hash_key(key)
            
            if key_hash in self.quotas:
                quota = self.quotas[key_hash]
                is_available = self.can_use_key(key)
                
                if is_available:
                    status["available_keys"] += 1
                else:
                    status["exhausted_keys"] += 1
                
                key_info = {
                    "index": i + 1,
                    "masked_key": f"{key[:6]}...{key[-4:]}",
                    "daily_requests": quota.daily_requests,
                    "is_available": is_available,
                    "is_exhausted": quota.is_exhausted,
                    "retry_after": quota.retry_after,
                    "last_error": quota.last_error
                }
            else:
                status["available_keys"] += 1
                key_info = {
                    "index": i + 1,
                    "masked_key": f"{key[:6]}...{key[-4:]}",
                    "daily_requests": 0,
                    "is_available": True,
                    "is_exhausted": False,
                    "retry_after": None,
                    "last_error": None
                }
            
            status["keys"].append(key_info)
        
        return status

# Global instance
_quota_manager = None

def get_quota_manager() -> QuotaManager:
    """Get global quota manager instance."""
    global _quota_manager
    if _quota_manager is None:
        _quota_manager = QuotaManager()
    return _quota_manager