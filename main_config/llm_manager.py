import os
import logging
from typing import Optional, Dict, Any, List, Tuple
from dotenv import load_dotenv
from crewai import LLM
from main_config.llm_logger import get_session_logger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

os.environ["LITELLM_LOG"] = "ERROR"
logging.getLogger("LiteLLM").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)

load_dotenv()

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Gemini models ordered by preference (fastest/cheapest first)
GEMINI_MODELS: List[str] = [
    "gemini-2.5-flash-lite",   # Priority 1 - Fastest
    "gemini-2.5-flash",        # Priority 2 - Balanced
    "gemini-3-flash-preview",  # Priority 3 - Latest
]

GROQ_MODELS: List[str] = [
    "groq/llama-3.3-70b-versatile",                    # TPD 100k — best quality
    "groq/meta-llama/llama-4-scout-17b-16e-instruct",  # TPD 100k — Llama 4
    "groq/moonshotai/kimi-k2-instruct",                # latest Kimi K2
    "groq/qwen/qwen3-32b",                             # Qwen 32B
    "groq/llama-3.1-8b-instant",                       # TPD 500k — high quota fallback
]

GEMINI_TEMPERATURE = 0.7
GEMINI_TIMEOUT = 300
GEMINI_MAX_RETRIES = 2

GROQ_TEMPERATURE = 0.7
GROQ_TIMEOUT = 60
GROQ_MAX_RETRIES = 2

# ============================================================================
# API KEY LOADING — all keys from .env
# ============================================================================

# GOOGLE_API_KEY + GOOGLE_API_KEY_1 through GOOGLE_API_KEY_37
_raw_gemini_keys: List[Optional[str]] = [
    os.getenv("GOOGLE_API_KEY"),
    *[os.getenv(f"GOOGLE_API_KEY_{i}") for i in range(1, 38)],
]
_seen: set = set()
GEMINI_API_KEYS: List[str] = []
for _k in _raw_gemini_keys:
    if _k and _k not in _seen:
        _seen.add(_k)
        GEMINI_API_KEYS.append(_k)

# GROQ_API_KEY + GROQ_API_KEY_1 through GROQ_API_KEY_4
_raw_groq_keys: List[Optional[str]] = [
    os.getenv("GROQ_API_KEY"),
    *[os.getenv(f"GROQ_API_KEY_{i}") for i in range(1, 5)],
]
GROQ_API_KEYS: List[str] = [k for k in _raw_groq_keys if k]

SERPER_API_KEY: Optional[str] = os.getenv("SERPER_API_KEY")

# Provider toggles — set USE_GEMINI=false in .env to disable Gemini entirely
USE_GEMINI: bool = os.getenv("USE_GEMINI", "true").strip().lower() == "true"
USE_GROQ: bool = os.getenv("USE_GROQ", "true").strip().lower() == "true"

logger.info(
    f"LLM Config loaded: {len(GEMINI_API_KEYS)} Gemini keys, "
    f"{len(GROQ_API_KEYS)} Groq keys"
)

_llm_log = get_session_logger()

# ============================================================================
# GLOBAL ROTATION STATE
# ============================================================================

_current_gemini_key_index: int = 0
_current_gemini_model_index: int = 0
_current_groq_key_index: int = 0
_current_groq_model_index: int = 0

# ============================================================================
# RATE LIMIT DETECTION
# ============================================================================

_RATE_LIMIT_SIGNALS = (
    "429",
    "quota",
    "resource_exhausted",
    "rate_limit",
    "over_capacity",
    "overloaded",
    "capacity",
    "too many requests",
    "service unavailable",
    "tool_use_failed",
    "failed to call a function",
    "model_decommissioned",       # model removed — rotate to next
    "decommissioned",
    "no longer supported",
)


def _is_rate_limit_error(error: Exception) -> bool:
    msg = str(error).lower()
    return any(signal in msg for signal in _RATE_LIMIT_SIGNALS)


# ============================================================================
# LOW-LEVEL BUILDERS
# ============================================================================


def _build_gemini_llm(api_key: str, model: str, temperature: float) -> LLM:
    return LLM(
        model=model,
        temperature=temperature,
        api_key=api_key,
        timeout=GEMINI_TIMEOUT,
        max_retries=GEMINI_MAX_RETRIES,
    )


def _build_groq_llm(api_key: str, model: str, temperature: float) -> LLM:
    return LLM(
        model=model,
        temperature=temperature,
        api_key=api_key,
        timeout=GROQ_TIMEOUT,
        max_retries=GROQ_MAX_RETRIES,
    )


# ============================================================================
# GEMINI — public interface
# ============================================================================


def get_gemini_llm(
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> LLM:
    """
    Return a Gemini LLM at the current rotation position.
    Does NOT validate the LLM. Use get_gemini_llm_with_fallback() for
    automatic rotation on errors.
    """
    if not GEMINI_API_KEYS:
        raise ValueError("No Gemini API keys loaded. Check your .env file.")
    key = api_key or GEMINI_API_KEYS[_current_gemini_key_index]
    mdl = model or GEMINI_MODELS[_current_gemini_model_index]
    temp = temperature if temperature is not None else GEMINI_TEMPERATURE
    return _build_gemini_llm(key, mdl, temp)


def get_gemini_llm_with_fallback(
    temperature: Optional[float] = None,
    test_prompt: str = "hi",
    probe: bool = True,
) -> LLM:
    """
    Return a validated Gemini LLM, rotating through ALL model x key combinations.

    Rotation order: for each model, try every key. When all keys for a model
    fail, advance to the next model. Global indices are updated on success so
    the next call continues from the same working position.

    Args:
        probe: When True (default), fires a lightweight test call to confirm the
               LLM works before returning it. Set False to skip the probe and
               return the LLM immediately (faster startup, errors surface later).

    Raises RuntimeError when every combination is exhausted.
    """
    global _current_gemini_key_index, _current_gemini_model_index

    if not GEMINI_API_KEYS:
        raise ValueError("No Gemini API keys loaded. Check your .env file.")

    temp = temperature if temperature is not None else GEMINI_TEMPERATURE
    n_models = len(GEMINI_MODELS)
    n_keys = len(GEMINI_API_KEYS)

    # When probe is disabled, just return the LLM at the current rotation position
    if not probe:
        model = GEMINI_MODELS[_current_gemini_model_index]
        key = GEMINI_API_KEYS[_current_gemini_key_index]
        logger.info(f"Gemini LLM (no probe): model={model}, key #{_current_gemini_key_index + 1}/{n_keys}")
        return _build_gemini_llm(key, model, temp)

    for attempt in range(n_models * n_keys):
        model = GEMINI_MODELS[_current_gemini_model_index]
        key = GEMINI_API_KEYS[_current_gemini_key_index]

        try:
            llm = _build_gemini_llm(key, model, temp)
            llm.call(test_prompt)
            logger.info(
                f"Gemini ready: model={model}, "
                f"key #{_current_gemini_key_index + 1}/{n_keys}"
            )
            return llm
        except Exception as e:
            label = "rate-limit" if _is_rate_limit_error(e) else "error"
            logger.warning(
                f"Gemini {label} [{model}, key #{_current_gemini_key_index + 1}]: "
                f"{e} — rotating ({attempt + 1}/{n_models * n_keys})"
            )
            prev_key_idx = _current_gemini_key_index
            prev_model = model
            # Rotate key first; when all keys tried, move to next model
            _current_gemini_key_index = (_current_gemini_key_index + 1) % n_keys
            if _current_gemini_key_index == 0:
                _current_gemini_model_index = (
                    _current_gemini_model_index + 1
                ) % n_models
            _llm_log.log_rotation(
                provider="gemini",
                reason=label,
                from_model=prev_model,
                to_model=GEMINI_MODELS[_current_gemini_model_index],
                from_key=prev_key_idx,
                to_key=_current_gemini_key_index,
            )

    raise RuntimeError(
        f"All {n_models} Gemini models x {n_keys} keys exhausted."
    )


def rotate_gemini_key() -> str:
    """Manually advance to the next Gemini API key."""
    global _current_gemini_key_index
    prev = _current_gemini_key_index
    _current_gemini_key_index = (_current_gemini_key_index + 1) % len(GEMINI_API_KEYS)
    logger.info(
        f"Rotated Gemini key -> #{_current_gemini_key_index + 1}/{len(GEMINI_API_KEYS)}"
    )
    _llm_log.log_rotation(provider="gemini", reason="manual", from_key=prev, to_key=_current_gemini_key_index)
    return GEMINI_API_KEYS[_current_gemini_key_index]


def rotate_gemini_model() -> str:
    """Manually advance to the next Gemini model."""
    global _current_gemini_model_index
    prev_model = GEMINI_MODELS[_current_gemini_model_index]
    _current_gemini_model_index = (
        _current_gemini_model_index + 1
    ) % len(GEMINI_MODELS)
    new_model = GEMINI_MODELS[_current_gemini_model_index]
    logger.info(
        f"Rotated Gemini model -> {new_model} "
        f"(#{_current_gemini_model_index + 1}/{len(GEMINI_MODELS)})"
    )
    _llm_log.log_rotation(provider="gemini", reason="manual", from_model=prev_model, to_model=new_model)
    return new_model


def get_current_gemini_model() -> str:
    return GEMINI_MODELS[_current_gemini_model_index]


def get_current_gemini_key_index() -> int:
    return _current_gemini_key_index


def get_current_gemini_model_index() -> int:
    return _current_gemini_model_index


def get_gemini_keys_count() -> int:
    return len(GEMINI_API_KEYS)


def get_gemini_models_count() -> int:
    return len(GEMINI_MODELS)


def get_all_gemini_keys() -> List[str]:
    return GEMINI_API_KEYS.copy()


def get_all_gemini_models() -> List[str]:
    return GEMINI_MODELS.copy()


# ============================================================================
# GROQ — public interface
# ============================================================================


def get_groq_llm(
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> LLM:
    """
    Return a Groq LLM at the current rotation position.
    Does NOT validate the LLM. Use get_groq_llm_with_fallback() for
    automatic rotation on errors.
    """
    if not GROQ_API_KEYS:
        raise ValueError("No Groq API keys loaded. Check your .env file.")
    key = api_key or GROQ_API_KEYS[_current_groq_key_index]
    mdl = model or GROQ_MODELS[_current_groq_model_index]
    temp = temperature if temperature is not None else GROQ_TEMPERATURE
    return _build_groq_llm(key, mdl, temp)


def get_groq_llm_with_fallback(
    temperature: Optional[float] = None,
    test_prompt: str = "hi",
    probe: bool = True,
) -> LLM:
    """
    Return a validated Groq LLM, rotating through ALL model x key combinations.

    Rotation order: for each model, try every key. When all keys for a model
    fail, advance to the next model. Global indices are updated on success so
    the next call continues from the same working position.

    Args:
        probe: When True (default), fires a lightweight test call to confirm the
               LLM works before returning it. Set False to skip the probe and
               return the LLM immediately (faster startup, errors surface later).

    Raises RuntimeError when every combination is exhausted.
    """
    global _current_groq_key_index, _current_groq_model_index

    if not GROQ_API_KEYS:
        raise ValueError("No Groq API keys loaded. Check your .env file.")

    temp = temperature if temperature is not None else GROQ_TEMPERATURE
    n_models = len(GROQ_MODELS)
    n_keys = len(GROQ_API_KEYS)

    # When probe is disabled, just return the LLM at the current rotation position
    if not probe:
        model = GROQ_MODELS[_current_groq_model_index]
        key = GROQ_API_KEYS[_current_groq_key_index]
        logger.info(f"Groq LLM (no probe): model={model}, key #{_current_groq_key_index + 1}/{n_keys}")
        return _build_groq_llm(key, model, temp)

    for attempt in range(n_models * n_keys):
        model = GROQ_MODELS[_current_groq_model_index]
        key = GROQ_API_KEYS[_current_groq_key_index]

        try:
            llm = _build_groq_llm(key, model, temp)
            llm.call(test_prompt)
            logger.info(
                f"Groq ready: model={model}, "
                f"key #{_current_groq_key_index + 1}/{n_keys}"
            )
            return llm
        except Exception as e:
            label = "rate-limit" if _is_rate_limit_error(e) else "error"
            logger.warning(
                f"Groq {label} [{model}, key #{_current_groq_key_index + 1}]: "
                f"{e} — rotating ({attempt + 1}/{n_models * n_keys})"
            )
            prev_key_idx = _current_groq_key_index
            prev_model = model
            # Rotate key first; when all keys tried, move to next model
            _current_groq_key_index = (_current_groq_key_index + 1) % n_keys
            if _current_groq_key_index == 0:
                _current_groq_model_index = (
                    _current_groq_model_index + 1
                ) % n_models
            _llm_log.log_rotation(
                provider="groq",
                reason=label,
                from_model=prev_model,
                to_model=GROQ_MODELS[_current_groq_model_index],
                from_key=prev_key_idx,
                to_key=_current_groq_key_index,
            )

    raise RuntimeError(
        f"All {n_models} Groq models x {n_keys} keys exhausted."
    )


def rotate_groq_key() -> str:
    """Manually advance to the next Groq API key."""
    global _current_groq_key_index
    prev = _current_groq_key_index
    _current_groq_key_index = (_current_groq_key_index + 1) % len(GROQ_API_KEYS)
    logger.info(
        f"Rotated Groq key -> #{_current_groq_key_index + 1}/{len(GROQ_API_KEYS)}"
    )
    _llm_log.log_rotation(provider="groq", reason="manual", from_key=prev, to_key=_current_groq_key_index)
    return GROQ_API_KEYS[_current_groq_key_index]


def rotate_groq_model() -> str:
    """Manually advance to the next Groq model."""
    global _current_groq_model_index
    prev_model = GROQ_MODELS[_current_groq_model_index]
    _current_groq_model_index = (_current_groq_model_index + 1) % len(GROQ_MODELS)
    new_model = GROQ_MODELS[_current_groq_model_index]
    logger.info(
        f"Rotated Groq model -> {new_model} "
        f"(#{_current_groq_model_index + 1}/{len(GROQ_MODELS)})"
    )
    _llm_log.log_rotation(provider="groq", reason="manual", from_model=prev_model, to_model=new_model)
    return new_model


def get_current_groq_model() -> str:
    return GROQ_MODELS[_current_groq_model_index]


def get_current_groq_key_index() -> int:
    return _current_groq_key_index


def get_groq_models_count() -> int:
    return len(GROQ_MODELS)


def get_all_groq_keys() -> List[str]:
    return GROQ_API_KEYS.copy()


def get_all_groq_models() -> List[str]:
    return GROQ_MODELS.copy()


# ============================================================================
# MASTER FUNCTION — Groq primary, Gemini fallback
# ============================================================================


def get_master_llm(
    temperature: Optional[float] = None,
    test_prompt: str = "hi",
    prefer_groq: bool = True,
    probe: bool = True,
) -> Tuple[LLM, str]:
    """
    Return the best available LLM with full automatic fallback.

    Strategy:
      1. Try Groq first — cycles through all 5 models x all 5 keys (up to 25 attempts).
      2. If Groq is completely exhausted, fall back to Gemini — cycles through
         all 4 models x all ~37 keys.
      3. Raise RuntimeError only when both providers are fully exhausted.

    Args:
        temperature:  Temperature applied to both providers.
        test_prompt:  Lightweight prompt used to validate each candidate LLM.
        prefer_groq:  Set False to try Gemini first instead.

    Returns:
        Tuple of (LLM instance, provider_name) where provider_name is
        "groq" or "gemini".

    Example:
        llm, provider = get_master_llm()
        # pass llm to your CrewAI agents
    """
    if not USE_GROQ and not USE_GEMINI:
        raise RuntimeError("Both USE_GROQ and USE_GEMINI are disabled in .env.")

    # Build ordered provider list based on flags and preference
    providers = []
    if prefer_groq:
        if USE_GROQ:
            providers.append((get_groq_llm_with_fallback, "groq"))
        if USE_GEMINI:
            providers.append((get_gemini_llm_with_fallback, "gemini"))
    else:
        if USE_GEMINI:
            providers.append((get_gemini_llm_with_fallback, "gemini"))
        if USE_GROQ:
            providers.append((get_groq_llm_with_fallback, "groq"))

    if not providers:
        raise RuntimeError("No providers enabled. Set USE_GROQ=true or USE_GEMINI=true in .env.")

    last_err: Optional[Exception] = None
    for fn, name in providers:
        try:
            llm = fn(temperature=temperature, test_prompt=test_prompt, probe=probe)
            logger.info(f"Master LLM: using {name}")
            return llm, name
        except RuntimeError as e:
            logger.warning(f"Master LLM: {name} exhausted — {e}")
            last_err = e

    raise RuntimeError(f"All enabled providers exhausted. Last error: {last_err}")


# ============================================================================
# DIRECT GENAI API HELPERS (google.generativeai — not CrewAI LLM)
# ============================================================================


def initialize_genai_model(
    api_key: Optional[str] = None,
    model_name: str = GEMINI_MODELS[0],
) -> Any:
    """
    Initialize a google.generativeai GenerativeModel.
    For direct API use — prefer get_gemini_llm_with_fallback() for CrewAI agents.
    """
    import google.generativeai as genai  # type: ignore

    key = api_key or (
        GEMINI_API_KEYS[_current_gemini_key_index] if GEMINI_API_KEYS else None
    )
    if not key:
        raise ValueError("No Gemini API key available.")
    genai.configure(api_key=key)
    return genai.GenerativeModel(model_name)


def generate_with_gemini(
    prompt: str,
    api_key: Optional[str] = None,
    model_name: str = GEMINI_MODELS[0],
    temperature: float = 0.1,
    max_output_tokens: Optional[int] = None,
) -> str:
    """
    Generate text via google.generativeai directly (not CrewAI).
    Automatically rotates through all Gemini API keys on rate-limit errors.
    """
    import google.generativeai as genai  # type: ignore

    keys_to_try = [api_key] if api_key else GEMINI_API_KEYS
    if not keys_to_try:
        raise ValueError("No Gemini API keys available.")

    last_error: Optional[Exception] = None
    for key in keys_to_try:
        try:
            genai.configure(api_key=key)
            model = genai.GenerativeModel(model_name)
            cfg: Dict[str, Any] = {"temperature": temperature}
            if max_output_tokens is not None:
                cfg["max_output_tokens"] = max_output_tokens
            generation_config = genai.types.GenerationConfig(**cfg)
            response = model.generate_content(
                prompt, generation_config=generation_config
            )
            return response.text if response else ""
        except Exception as e:
            last_error = e
            if _is_rate_limit_error(e):
                logger.warning(
                    "generate_with_gemini: rate-limit hit, trying next key."
                )
                continue
            raise

    raise RuntimeError(
        f"All Gemini keys failed in generate_with_gemini. Last error: {last_error}"
    )


# ============================================================================
# STATUS AND INFO
# ============================================================================


def get_llm_status() -> Dict[str, Any]:
    """Return a snapshot of the current LLM configuration state."""
    return {
        "gemini_keys_available": len(GEMINI_API_KEYS),
        "gemini_current_key_index": _current_gemini_key_index,
        "gemini_current_model": get_current_gemini_model(),
        "gemini_models": GEMINI_MODELS,
        "groq_keys_available": len(GROQ_API_KEYS),
        "groq_current_key_index": _current_groq_key_index,
        "groq_current_model": get_current_groq_model(),
        "groq_models": GROQ_MODELS,
        "serper_available": bool(SERPER_API_KEY),
    }


def print_llm_status() -> None:
    """Print a human-readable summary of the LLM configuration."""
    s = get_llm_status()
    print("\n" + "=" * 60)
    print("LLM CONFIGURATION STATUS")
    print("=" * 60)
    print(f"Gemini keys loaded : {s['gemini_keys_available']}")
    print(f"Gemini active key  : #{s['gemini_current_key_index'] + 1}")
    print(f"Gemini active model: {s['gemini_current_model']}")
    print(f"Gemini all models  : {', '.join(s['gemini_models'])}")
    print()
    print(f"Groq keys loaded   : {s['groq_keys_available']}")
    print(f"Groq active key    : #{s['groq_current_key_index'] + 1}")
    print(f"Groq active model  : {s['groq_current_model']}")
    print(f"Groq all models    : {', '.join(s['groq_models'])}")
    print()
    print(f"Serper available   : {s['serper_available']}")
    print("=" * 60 + "\n")


def initialize_multiple_llms(
    use_gemini: bool = True,
    use_groq: bool = True,
    temperature: Optional[float] = None,
) -> Dict[str, LLM]:
    """
    Initialize LLM instances without validation.
    Returns a dict with 'gemini' and/or 'groq' keys.
    For validated instances use get_master_llm() instead.
    """
    llms: Dict[str, LLM] = {}
    if use_gemini and GEMINI_API_KEYS:
        try:
            llms["gemini"] = get_gemini_llm(temperature=temperature)
            logger.info("Gemini LLM initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
    if use_groq and GROQ_API_KEYS:
        try:
            llms["groq"] = get_groq_llm(temperature=temperature)
            logger.info("Groq LLM initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Groq: {e}")
    return llms
