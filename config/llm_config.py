"""
LLM Configuration for Rate Limiting and Timeouts
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Rate limiting configuration
RATE_LIMIT_PER_MINUTE = int(os.getenv("LLM_RATE_LIMIT_PER_MINUTE", "15"))

# Timeout configuration (in seconds)
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
RISK_ASSESSMENT_TIMEOUT = int(os.getenv("RISK_ASSESSMENT_TIMEOUT", "20"))
REMEDIATION_TIMEOUT = int(os.getenv("REMEDIATION_TIMEOUT", "25"))

# Retry configuration
MAX_RETRY_ATTEMPTS = int(os.getenv("LLM_MAX_RETRY_ATTEMPTS", "3"))
