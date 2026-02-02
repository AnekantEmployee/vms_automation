import os
import logging
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from crewai import LLM

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable verbose LiteLLM logging
os.environ["LITELLM_LOG"] = "ERROR"
logging.getLogger("LiteLLM").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Gemini Configuration
GEMINI_MODEL_DEFAULT = os.getenv("MODEL_NAME", "gemini-2.5-flash")
GEMINI_LLM_MODEL = f"gemini/{GEMINI_MODEL_DEFAULT}"
GEMINI_TEMPERATURE = 0.7
GEMINI_TIMEOUT = 300  # 5 minutes
GEMINI_MAX_RETRIES = 3  # Increased retries for better reliability


# API Keys - Load from environment
GEMINI_API_KEYS = [
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
GEMINI_API_KEYS = [key for key in GEMINI_API_KEYS if key]  # Filter out None values
SERPER_API_KEY = os.getenv("SERPER_API_KEY")

# ============================================================================
# GLOBAL STATE
# ============================================================================

# Import API key manager
_has_api_key_manager = False
_api_key_manager = None

try:
    from config.api_key_manager import get_api_key_manager
    _has_api_key_manager = True
    _api_key_manager = get_api_key_manager()
    logger.info("✅ Enhanced API key manager available")
except ImportError:
    logger.warning("⚠️ Enhanced API key manager not available, using basic rotation")


# ============================================================================
# GEMINI API FUNCTIONS WITH ENHANCED KEY MANAGEMENT
# ============================================================================


def get_gemini_llm(
    api_key: Optional[str] = None,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
) -> LLM:
    """
    Get or create a Gemini LLM instance with intelligent key management.

    Args:
        api_key: Optional API key to use. If None, uses enhanced key manager.
        temperature: Optional temperature override. If None, uses default (0.7).
        model: Optional model override. If None, uses default (gemini-2.5-flash).

    Returns:
        LLM instance configured for Gemini

    Example:
        llm = get_gemini_llm()
        llm = get_gemini_llm(temperature=0.3)
    """
    if api_key is None:
        if _has_api_key_manager and _api_key_manager:
            # Use API key manager for intelligent rotation
            api_key = _api_key_manager.get_next_available_key()
            if not api_key:
                raise ValueError("No working Gemini API keys available")
            logger.info(f"Using API key from manager (key index: {_api_key_manager.current_key_index + 1})")
        else:
            # Fallback to basic approach
            if not GEMINI_API_KEYS:
                raise ValueError("No Gemini API keys available")
            api_key = GEMINI_API_KEYS[0]
            logger.info("Using first available API key (no manager)")

    temp = temperature if temperature is not None else GEMINI_TEMPERATURE
    llm_model = model if model is not None else GEMINI_LLM_MODEL

    return LLM(
        model=llm_model,
        temperature=temp,
        api_key=api_key,
        timeout=GEMINI_TIMEOUT,
        max_retries=GEMINI_MAX_RETRIES,
    )


def execute_llm_with_fallback(operation, max_attempts: int = None):
    """
    Execute LLM operation with automatic API key fallback.
    
    This is a wrapper around the API key manager's execute_with_fallback
    for CrewAI/LangGraph operations.
    
    Args:
        operation: Function that takes an API key and returns a result
        max_attempts: Maximum number of API keys to try (default: all keys)
    
    Returns:
        Result from the operation
    
    Example:
        def my_llm_operation(api_key):
            llm = get_gemini_llm(api_key=api_key)
            return llm.generate("Hello")
        
        result = execute_llm_with_fallback(my_llm_operation)
    """
    if _has_api_key_manager and _api_key_manager:
        return _api_key_manager.execute_with_fallback(operation, max_attempts)
    else:
        # Fallback: just try with first key
        if not GEMINI_API_KEYS:
            raise ValueError("No Gemini API keys available")
        return operation(GEMINI_API_KEYS[0])


def get_current_gemini_key_index() -> int:
    """Get the current Gemini API key index."""
    if _has_api_key_manager and _api_key_manager:
        return _api_key_manager.current_key_index
    return 0


def get_gemini_keys_count() -> int:
    """Get the number of available Gemini API keys."""
    return len(GEMINI_API_KEYS)


def get_all_gemini_keys() -> List[str]:
    """Get all available Gemini API keys."""
    return GEMINI_API_KEYS.copy()


# ============================================================================
# DIRECT GENAI API FUNCTIONS (for google.generativeai usage)
# ============================================================================


def initialize_genai_model(
    api_key: Optional[str] = None,
    model_name: str = GEMINI_MODEL_DEFAULT,
) -> Any:
    """
    Initialize and return a google.generativeai GenerativeModel instance.

    DEPRECATED: Use config.api_key_manager.create_gemini_model_with_fallback() instead
    for automatic API key fallback handling.

    This is useful for direct google.generativeai API calls instead of using CrewAI LLM.

    Args:
        api_key: Optional API key to use. If None, uses API key manager.
        model_name: Optional model name. If None, uses default (gemini-2.5-flash).

    Returns:
        genai.GenerativeModel instance

    Example:
        import google.generativeai as genai
        model = initialize_genai_model()
        response = model.generate_content("Hello")
    """
    import google.generativeai as genai

    if api_key is None:
        if _has_api_key_manager and _api_key_manager:
            api_key = _api_key_manager.get_next_available_key()
        elif GEMINI_API_KEYS:
            api_key = GEMINI_API_KEYS[0]
        else:
            raise ValueError("No Gemini API keys available")

    genai.configure(api_key=api_key)
    return genai.GenerativeModel(model_name)


def generate_with_gemini(
    prompt: str,
    api_key: Optional[str] = None,
    model_name: str = GEMINI_MODEL_DEFAULT,
    temperature: float = 0.1,
    max_output_tokens: Optional[int] = None,
) -> str:
    """
    Generate content using Gemini API directly.

    DEPRECATED: Use config.api_key_manager.generate_content_with_fallback() instead
    for automatic API key fallback handling.

    This is a convenience function that handles genai configuration and generation.

    Args:
        prompt: The prompt to send to Gemini
        api_key: Optional API key. If None, uses API key manager.
        model_name: Model to use (default: gemini-2.5-flash)
        temperature: Temperature setting (default: 0.1)
        max_output_tokens: Max tokens in response (optional)

    Returns:
        Generated text response

    Raises:
        Exception: If API call fails

    Example:
        response = generate_with_gemini("Analyze this alert: ...")
        print(response)
    """
    import google.generativeai as genai

    if api_key is None:
        if _has_api_key_manager and _api_key_manager:
            api_key = _api_key_manager.get_next_available_key()
        elif GEMINI_API_KEYS:
            api_key = GEMINI_API_KEYS[0]
        else:
            raise ValueError("No Gemini API keys available")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)

    config_kwargs = {
        "temperature": temperature,
    }
    if max_output_tokens is not None:
        config_kwargs["max_output_tokens"] = max_output_tokens

    generation_config = genai.types.GenerationConfig(**config_kwargs)

    response = model.generate_content(prompt, generation_config=generation_config)

    return response.text if response else ""


# ============================================================================
# LLM INITIALIZATION HELPER
# ============================================================================


def initialize_multiple_llms(
    use_gemini: bool = True,
    temperature: Optional[float] = None,
) -> Dict[str, LLM]:
    """
    Initialize multiple LLM instances (Gemini).

    Args:
        use_gemini: Whether to initialize Gemini LLMs (default: True)
        temperature: Optional temperature override for all LLMs

    Returns:
        Dictionary with keys 'gemini' containing LLM instances

    Example:
        llms = initialize_multiple_llms()
        if 'gemini' in llms:
            # Use Gemini
            pass
    """
    llms = {}

    if use_gemini and GEMINI_API_KEYS:
        try:
            llms["gemini"] = get_gemini_llm(temperature=temperature)
            logger.info("✅ Gemini LLM initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Gemini: {str(e)}")
    return llms


# ============================================================================
# STATUS AND INFO FUNCTIONS
# ============================================================================


def get_llm_status() -> Dict[str, Any]:
    """
    Get current status of LLM configuration.

    Returns:
        Dictionary with information about available models and keys

    Example:
        status = get_llm_status()
        print(f"Gemini keys available: {status['gemini_keys_available']}")
    """
    current_index = 0
    if _has_api_key_manager and _api_key_manager:
        current_index = _api_key_manager.current_key_index
    
    return {
        "gemini_keys_available": len(GEMINI_API_KEYS),
        "gemini_current_key_index": current_index,
        "gemini_model": GEMINI_LLM_MODEL,
        "serper_available": bool(SERPER_API_KEY),
        "has_api_key_manager": _has_api_key_manager,
    }


def print_llm_status():
    """Print current LLM configuration status."""
    status = get_llm_status()
    print("\n" + "=" * 60)
    print("LLM CONFIGURATION STATUS")
    print("=" * 60)
    print(f"Gemini Keys Available: {status['gemini_keys_available']}")
    print(f"Gemini Current Key Index: {status['gemini_current_key_index'] + 1}")
    print(f"Gemini Model: {status['gemini_model']}")
    print(f"Serper Available: {status['serper_available']}")
    print(f"API Key Manager: {'✅ Active' if status['has_api_key_manager'] else '❌ Not Available'}")
    print("=" * 60 + "\n")


def get_api_key_manager_status() -> Dict[str, Any]:
    """Get detailed status from API key manager if available"""
    if _has_api_key_manager and _api_key_manager:
        return _api_key_manager.get_status_report()
    return {"error": "API key manager not available"}


# ============================================================================
# INITIALIZATION
# ============================================================================

# Print status on module load (optional - comment out if too verbose)
logger.info(
    f"LLM Config loaded: {len(GEMINI_API_KEYS)} Gemini keys, "
    f"API Key Manager: {'Active' if _has_api_key_manager else 'Not Available'}"
)