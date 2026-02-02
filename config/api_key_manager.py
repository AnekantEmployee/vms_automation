import os
import time
import logging
import warnings
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

# Suppress all FutureWarnings
warnings.filterwarnings("ignore", category=FutureWarning)

import google.generativeai as genai
from dotenv import load_dotenv

# Suppress ALTS credentials warnings
os.environ['GRPC_VERBOSITY'] = 'ERROR'
os.environ['GRPC_TRACE'] = ''

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

@dataclass
class APIKeyStatus:
    """Track API key status and quota information"""
    key: str
    is_active: bool = True
    quota_reset_time: Optional[datetime] = None
    error_count: int = 0
    last_error: Optional[str] = None
    last_success: Optional[datetime] = None

class APIKeyManager:
    """Centralized API key management with intelligent fallback"""

    def __init__(self):
        self.gemini_keys = self._load_gemini_keys()
        self.current_key_index = self._find_best_starting_key()
        self.key_status: Dict[str, APIKeyStatus] = {}
        self._initialize_key_status()
        self._test_keys_on_init()

    def _load_gemini_keys(self) -> List[str]:
        """Load all available Gemini API keys"""
        keys = [
            os.getenv("GOOGLE_API_KEY_1", os.getenv("GOOGLE_API_KEY")),
            os.getenv("GOOGLE_API_KEY_2"),
            os.getenv("GOOGLE_API_KEY_3"),
            os.getenv("GOOGLE_API_KEY_4"),
            os.getenv("GOOGLE_API_KEY_5"),
            os.getenv("GOOGLE_API_KEY_6"),
            os.getenv("GOOGLE_API_KEY_7"),
            os.getenv("GOOGLE_API_KEY_8"),
            os.getenv("GOOGLE_API_KEY_9"),
        ]
        return [key for key in keys if key]

    def _initialize_key_status(self):
        """Initialize status tracking for all keys"""
        for key in self.gemini_keys:
            self.key_status[key] = APIKeyStatus(key=key)

    def _find_best_starting_key(self) -> int:
        """Find the best key to start with (skip known bad keys)"""
        if not self.gemini_keys:
            return 0

        # Try a quick test on key 9 first (often working)
        if len(self.gemini_keys) >= 9:
            try:
                import os
                model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash")
                test_key = self.gemini_keys[8]  # Index 8 = Key 9
                genai.configure(api_key=test_key)
                model = genai.GenerativeModel(model_name)
                model.generate_content("test", generation_config=genai.types.GenerationConfig(
                    max_output_tokens=1, temperature=0
                ))
                logger.info(f"Starting with working key 9")
                return 8  # Start with key 9
            except:
                pass

        return 0  # Default to first key

    def _test_keys_on_init(self):
        """Test keys on initialization to mark bad ones"""
        logger.info("Testing API keys on startup...")

        for i, key in enumerate(self.gemini_keys):
            try:
                import os
                model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash")
                genai.configure(api_key=key)
                model = genai.GenerativeModel(model_name)
                model.generate_content("test", generation_config=genai.types.GenerationConfig(
                    max_output_tokens=1, temperature=0
                ))
                self._mark_key_success(key)
                logger.info(f"Key {i+1}: Working")
            except Exception as e:
                if self._is_quota_error(e):
                    self._mark_key_quota_exceeded(key, e)
                    logger.warning(f"Key {i+1}: Rate limited")
                else:
                    logger.warning(f"Key {i+1}: {str(e)[:50]}")

    def _is_quota_error(self, error: Exception) -> bool:
        """Check if error is quota/rate limit related"""
        error_str = str(error).lower()
        return any(code in error_str for code in [
            "429", "quota", "rate limit", "resource_exhausted",
            "quota exceeded", "requests per day"
        ])

    def _is_server_error(self, error: Exception) -> bool:
        """Check if error is server-side (503, 504, etc.)"""
        error_str = str(error).lower()
        return any(code in error_str for code in [
            "503", "504", "500", "502", "overloaded", 
            "unavailable", "timeout", "internal error"
        ])

    def _extract_retry_delay(self, error: Exception) -> int:
        """Extract retry delay from error message if available"""
        import re
        error_str = str(error)

        # Look for "retry in X seconds" patterns
        patterns = [
            r"retry in (\d+\.?\d*)s",
            r"please retry in (\d+\.?\d*) seconds",
            r"retry_delay.*?(\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, error_str, re.IGNORECASE)
            if match:
                return int(float(match.group(1)))

        return 0

    def _mark_key_quota_exceeded(self, key: str, error: Exception):
        """Mark key as quota exceeded with retry time"""
        if key in self.key_status:
            status = self.key_status[key]
            status.is_active = False
            status.error_count += 1
            status.last_error = str(error)

            # Extract retry delay or use default
            retry_delay = self._extract_retry_delay(error)
            if retry_delay > 0:
                status.quota_reset_time = datetime.now() + timedelta(seconds=retry_delay)
                logger.warning(f"Key {self._mask_key(key)} quota exceeded, retry in {retry_delay}s")
            else:
                # Default to 60 seconds if no retry time specified
                status.quota_reset_time = datetime.now() + timedelta(seconds=60)
                logger.warning(f"Key {self._mask_key(key)} quota exceeded, retry in 60s")

    def _mark_key_success(self, key: str):
        """Mark key as successful"""
        if key in self.key_status:
            status = self.key_status[key]
            status.is_active = True
            status.last_success = datetime.now()
            status.error_count = 0
            status.quota_reset_time = None

    def _check_key_recovery(self, key: str) -> bool:
        """Check if a quota-exceeded key can be retried"""
        if key not in self.key_status:
            return True

        status = self.key_status[key]
        if status.is_active:
            return True

        if status.quota_reset_time and datetime.now() >= status.quota_reset_time:
            logger.info(f"Key {self._mask_key(key)} quota reset time reached, reactivating")
            status.is_active = True
            status.quota_reset_time = None
            return True

        return False

    def _mask_key(self, key: str) -> str:
        """Mask API key for logging"""
        if not key or len(key) < 8:
            return "***"
        return f"{key[:6]}...{key[-2:]}"

    def get_next_available_key(self) -> Optional[str]:
        """Get next available API key with intelligent rotation"""
        if not self.gemini_keys:
            return None

        # First, check if any quota-exceeded keys have recovered
        for key in self.gemini_keys:
            self._check_key_recovery(key)

        # Try to find an active key starting from current index
        attempts = 0
        while attempts < len(self.gemini_keys):
            key = self.gemini_keys[self.current_key_index]

            if self.key_status[key].is_active:
                return key

            # Move to next key
            self.current_key_index = (self.current_key_index + 1) % len(self.gemini_keys)
            attempts += 1

        # If no active keys, return the one with earliest reset time
        available_keys = []
        for key in self.gemini_keys:
            status = self.key_status[key]
            if status.quota_reset_time:
                available_keys.append((key, status.quota_reset_time))

        if available_keys:
            # Sort by reset time and return the earliest
            available_keys.sort(key=lambda x: x[1])
            earliest_key = available_keys[0][0]
            logger.info(f"All keys exhausted, using earliest reset key: {self._mask_key(earliest_key)}")
            return earliest_key

        # Fallback to current key
        return self.gemini_keys[self.current_key_index]

    def execute_with_fallback(self, 
                            operation: Callable[[str], Any], 
                            max_attempts: int = None) -> Any:
        """Execute operation with automatic API key fallback"""
        if max_attempts is None:
            max_attempts = len(self.gemini_keys)

        last_error = None

        for attempt in range(max_attempts):
            key = self.get_next_available_key()
            if not key:
                raise Exception("No API keys available")

            try:
                logger.info(f"Trying Gemini key {self.current_key_index + 1}/{len(self.gemini_keys)}")

                # Execute the operation with current key
                result = operation(key)

                # Mark success and return result
                self._mark_key_success(key)
                logger.info(f"Success with Gemini key {self.current_key_index + 1}")
                return result

            except Exception as e:
                last_error = e
                error_str = str(e)

                if self._is_quota_error(e):
                    logger.warning(f"Key {self.current_key_index + 1} quota exceeded, trying next key")
                    self._mark_key_quota_exceeded(key, e)

                elif self._is_server_error(e):
                    logger.warning(f"Key {self.current_key_index + 1} server error, trying next key")
                    # Don't mark as quota exceeded for server errors

                else:
                    logger.warning(f"Key {self.current_key_index + 1} failed: {error_str[:100]}")

                # Move to next key for next attempt
                self.current_key_index = (self.current_key_index + 1) % len(self.gemini_keys)

                # Add delay for server errors
                if self._is_server_error(e) and attempt < max_attempts - 1:
                    time.sleep(2)

        # All attempts failed
        raise Exception(f"All {max_attempts} API key attempts failed. Last error: {last_error}")

    def get_status_report(self) -> Dict[str, Any]:
        """Get detailed status report of all API keys"""
        active_keys = sum(1 for status in self.key_status.values() if status.is_active)

        report = {
            "total_keys": len(self.gemini_keys),
            "active_keys": active_keys,
            "current_key_index": self.current_key_index + 1,
            "keys_status": []
        }

        for i, key in enumerate(self.gemini_keys):
            status = self.key_status[key]
            key_info = {
                "index": i + 1,
                "masked_key": self._mask_key(key),
                "is_active": status.is_active,
                "error_count": status.error_count,
                "last_error": status.last_error,
                "quota_reset_time": status.quota_reset_time.isoformat() if status.quota_reset_time else None,
                "last_success": status.last_success.isoformat() if status.last_success else None
            }
            report["keys_status"].append(key_info)

        return report

# Global instance
_api_key_manager = None

def get_api_key_manager() -> APIKeyManager:
    """Get global API key manager instance"""
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager()
    return _api_key_manager

def create_gemini_model_with_fallback(model_name: str = "gemini-2.5-flash") -> Any:
    """Create Gemini model with automatic key fallback"""
    manager = get_api_key_manager()
    import os
    model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash")
    
    def _create_model(api_key: str):
        genai.configure(api_key=api_key)
        return genai.GenerativeModel(model_name)
    
    return manager.execute_with_fallback(_create_model)

def generate_content_with_fallback(prompt: str, 
                                 model_name: str = "gemini-2.5-flash",
                                 generation_config: dict = None,
                                 **kwargs) -> str:
    """Generate content with automatic API key fallback"""
    manager = get_api_key_manager()
    
    import os
    model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash")
    
    def _generate_content(api_key: str):
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        
        # Handle generation_config parameter
        if generation_config:
            config = genai.types.GenerationConfig(**generation_config)
            response = model.generate_content(prompt, generation_config=config, **kwargs)
        else:
            response = model.generate_content(prompt, **kwargs)
            
        # Safely extract text from response
        if response and hasattr(response, 'text') and response.text:
            return response.text
        elif response and hasattr(response, 'candidates') and response.candidates:
            # Try to get text from first candidate
            candidate = response.candidates[0]
            if hasattr(candidate, 'content') and candidate.content:
                if hasattr(candidate.content, 'parts') and candidate.content.parts:
                    return candidate.content.parts[0].text
        return "No response generated"
    
    return manager.execute_with_fallback(_generate_content)
