"""
llm_logger.py  –  Session-based LLM call logger

Hooks into LiteLLM's callback system to automatically capture every
LLM call (prompt, response, tokens, cost, latency, model, provider).

Each run creates two files under  logs/
  session_YYYYMMDD_HHMMSS.jsonl       – one JSON line per event (append-only)
  session_YYYYMMDD_HHMMSS_summary.json – written / updated on each call + at end
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Storage
# ─────────────────────────────────────────────────────────────────────────────

LOG_DIR = Path("logs")


# ─────────────────────────────────────────────────────────────────────────────
# SessionLogger
# ─────────────────────────────────────────────────────────────────────────────

class SessionLogger:
    """
    One instance per Python process lifetime.
    Registers itself into LiteLLM so EVERY llm call is captured automatically.
    Also provides log_rotation() and log_manual() for extra events.
    """

    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        LOG_DIR.mkdir(exist_ok=True)
        self.jsonl_file    = LOG_DIR / f"session_{self.session_id}.jsonl"
        self.summary_file  = LOG_DIR / f"session_{self.session_id}_summary.json"
        self._lock         = threading.Lock()

        self._stats = {
            "session_id":               self.session_id,
            "session_start":            datetime.now().isoformat(),
            "session_end":              None,
            "total_calls":              0,
            "successful_calls":         0,
            "failed_calls":             0,
            "rotation_events":          0,
            "total_prompt_tokens":      0,
            "total_completion_tokens":  0,
            "total_tokens":             0,
            "total_cost_usd":           0.0,
            "total_latency_seconds":    0.0,
            "avg_latency_seconds":      0.0,
            "providers":                {},   # provider → {calls, tokens, cost}
            "models":                   {},   # model    → {calls, tokens, cost}
        }

        self._register_litellm_hook()
        logger.info(f"[LLMLogger] Session started → {self.jsonl_file}")

    # ── LiteLLM hook ─────────────────────────────────────────────────────────

    def _register_litellm_hook(self):
        try:
            import litellm
            from litellm.integrations.custom_logger import CustomLogger

            outer = self

            class _Hook(CustomLogger):

                def log_success_event(self, kwargs, response_obj, start_time, end_time):
                    outer._handle_success(kwargs, response_obj, start_time, end_time)

                def log_failure_event(self, kwargs, response_obj, start_time, end_time):
                    outer._handle_failure(kwargs, response_obj, start_time, end_time)

                async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
                    outer._handle_success(kwargs, response_obj, start_time, end_time)

                async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
                    outer._handle_failure(kwargs, response_obj, start_time, end_time)

            litellm.callbacks = [_Hook()]
            logger.info("[LLMLogger] LiteLLM callback registered — all calls will be logged")
        except ImportError:
            logger.warning("[LLMLogger] litellm not installed — automatic logging unavailable; use log_manual()")

    # ── internal handlers ────────────────────────────────────────────────────

    def _handle_success(self, kwargs, response_obj, start_time, end_time):
        try:
            import litellm

            latency = (end_time - start_time).total_seconds()
            model   = kwargs.get("model", "unknown")
            msgs    = kwargs.get("messages", [])

            # Prompt text = last user message
            prompt = ""
            for m in reversed(msgs):
                if isinstance(m, dict) and m.get("role") == "user":
                    prompt = m.get("content", "")
                    break

            # Response text
            response_text = ""
            try:
                response_text = response_obj.choices[0].message.content or ""
            except Exception:
                pass

            # Token usage
            usage             = getattr(response_obj, "usage", None)
            prompt_tokens     = int(getattr(usage, "prompt_tokens",     0) or 0)
            completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
            total_tokens      = int(getattr(usage, "total_tokens",      0) or 0) or (prompt_tokens + completion_tokens)

            # Cost (USD)
            cost_usd = 0.0
            try:
                cost_usd = float(litellm.completion_cost(completion_response=response_obj) or 0.0)
            except Exception:
                pass

            provider = model.split("/")[0] if "/" in model else model

            event = {
                "event":              "llm_success",
                "timestamp":          datetime.now().isoformat(),
                "session_id":         self.session_id,
                "model":              model,
                "provider":           provider,
                "prompt":             prompt,
                "response":           response_text,
                "prompt_tokens":      prompt_tokens,
                "completion_tokens":  completion_tokens,
                "total_tokens":       total_tokens,
                "cost_usd":           round(cost_usd, 8),
                "latency_seconds":    round(latency, 3),
                "messages_count":     len(msgs),
            }
            self._write(event)
            self._update_stats(event, success=True)

        except Exception as exc:
            logger.debug(f"[LLMLogger] _handle_success error: {exc}")

    def _handle_failure(self, kwargs, exception, start_time, end_time):
        try:
            latency  = (end_time - start_time).total_seconds() if (start_time and end_time) else 0.0
            model    = kwargs.get("model", "unknown")
            msgs     = kwargs.get("messages", [])
            prompt   = ""
            for m in reversed(msgs):
                if isinstance(m, dict) and m.get("role") == "user":
                    prompt = m.get("content", "")
                    break
            provider = model.split("/")[0] if "/" in model else model

            event = {
                "event":             "llm_failure",
                "timestamp":         datetime.now().isoformat(),
                "session_id":        self.session_id,
                "model":             model,
                "provider":          provider,
                "prompt":            prompt,
                "response":          None,
                "error":             str(exception),
                "prompt_tokens":     0,
                "completion_tokens": 0,
                "total_tokens":      0,
                "cost_usd":          0.0,
                "latency_seconds":   round(latency, 3),
            }
            self._write(event)
            self._update_stats(event, success=False)

        except Exception as exc:
            logger.debug(f"[LLMLogger] _handle_failure error: {exc}")

    # ── public helpers ────────────────────────────────────────────────────────

    def log_rotation(
        self,
        provider: str,
        reason: str,
        from_model: Optional[str] = None,
        to_model:   Optional[str] = None,
        from_key:   Optional[int] = None,
        to_key:     Optional[int] = None,
    ):
        """Log a key or model rotation event."""
        event = {
            "event":      "rotation",
            "timestamp":  datetime.now().isoformat(),
            "session_id": self.session_id,
            "provider":   provider,
            "reason":     reason,
            "from_model": from_model,
            "to_model":   to_model,
            "from_key":   from_key,
            "to_key":     to_key,
        }
        self._write(event)
        with self._lock:
            self._stats["rotation_events"] += 1
        self._flush_summary()

    def log_manual(
        self,
        prompt: str,
        response: str,
        model: str,
        provider: str,
        key_index: int       = 0,
        prompt_tokens: int   = 0,
        completion_tokens: int = 0,
        cost_usd: float      = 0.0,
        latency_seconds: float = 0.0,
        success: bool        = True,
        error: Optional[str] = None,
    ):
        """Manually log a call (for cases not captured by the LiteLLM callback)."""
        total = prompt_tokens + completion_tokens
        event = {
            "event":             "llm_success" if success else "llm_failure",
            "timestamp":         datetime.now().isoformat(),
            "session_id":        self.session_id,
            "model":             model,
            "provider":          provider,
            "key_index":         key_index,
            "prompt":            prompt,
            "response":          response if success else None,
            "error":             error if not success else None,
            "prompt_tokens":     prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens":      total,
            "cost_usd":          round(cost_usd, 8),
            "latency_seconds":   round(latency_seconds, 3),
        }
        self._write(event)
        self._update_stats(event, success=success)

    # ── internal write / stats ────────────────────────────────────────────────

    def _write(self, event: dict):
        with self._lock:
            try:
                with open(self.jsonl_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
            except Exception as exc:
                logger.error(f"[LLMLogger] write failed: {exc}")

    def _update_stats(self, event: dict, success: bool):
        with self._lock:
            s = self._stats
            s["total_calls"]             += 1
            s["successful_calls" if success else "failed_calls"] += 1
            s["total_prompt_tokens"]     += event.get("prompt_tokens",     0)
            s["total_completion_tokens"] += event.get("completion_tokens", 0)
            s["total_tokens"]            += event.get("total_tokens",      0)
            s["total_cost_usd"]          += event.get("cost_usd",          0.0)
            s["total_latency_seconds"]   += event.get("latency_seconds",   0.0)
            if s["total_calls"] > 0:
                s["avg_latency_seconds"] = round(s["total_latency_seconds"] / s["total_calls"], 3)

            model    = event.get("model",    "unknown")
            provider = event.get("provider", "unknown")

            for bucket, key in ((s["models"], model), (s["providers"], provider)):
                if key not in bucket:
                    bucket[key] = {"calls": 0, "tokens": 0, "cost_usd": 0.0,
                                   "success": 0, "failure": 0}
                bucket[key]["calls"]   += 1
                bucket[key]["tokens"]  += event.get("total_tokens", 0)
                bucket[key]["cost_usd"] = round(bucket[key]["cost_usd"] + event.get("cost_usd", 0.0), 8)
                bucket[key]["success" if success else "failure"] += 1

        self._flush_summary()

    def _flush_summary(self):
        """Write/overwrite the summary JSON after every event."""
        try:
            with self._lock:
                data = dict(self._stats)
            with open(self.summary_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as exc:
            logger.debug(f"[LLMLogger] summary flush failed: {exc}")

    # ── public reporting ──────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def finalize(self):
        """Call at program end to stamp session_end and flush summary."""
        with self._lock:
            self._stats["session_end"] = datetime.now().isoformat()
        self._flush_summary()
        logger.info(f"[LLMLogger] Session finalized → {self.summary_file}")

    def print_summary(self):
        s = self.get_stats()
        calls = s["total_calls"]
        print("\n" + "═" * 62)
        print(f"  SESSION SUMMARY  [{s['session_id']}]")
        print("═" * 62)
        print(f"  Log file        : {self.jsonl_file}")
        print(f"  Summary file    : {self.summary_file}")
        print(f"  Total calls     : {calls}  "
              f"(✓ {s['successful_calls']}  ✗ {s['failed_calls']}  "
              f"↺ {s['rotation_events']} rotations)")
        print(f"  Tokens          : {s['total_tokens']:,}  "
              f"(prompt {s['total_prompt_tokens']:,} + "
              f"completion {s['total_completion_tokens']:,})")
        print(f"  Cost            : ${s['total_cost_usd']:.6f} USD")
        print(f"  Latency         : {s['total_latency_seconds']:.2f}s total  "
              f"| avg {s['avg_latency_seconds']:.2f}s/call")

        if s.get("providers"):
            print("\n  By provider:")
            for p, d in s["providers"].items():
                print(f"    {p:20s}  calls={d['calls']}  "
                      f"tokens={d['tokens']:,}  cost=${d['cost_usd']:.6f}")

        if s.get("models"):
            print("\n  By model:")
            for m, d in s["models"].items():
                print(f"    {m}")
                print(f"      calls={d['calls']}  tokens={d['tokens']:,}  "
                      f"cost=${d['cost_usd']:.6f}  "
                      f"✓{d['success']} ✗{d['failure']}")
        print("═" * 62 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────────────────────────────────────

_session_logger: Optional[SessionLogger] = None


def get_session_logger() -> SessionLogger:
    global _session_logger
    if _session_logger is None:
        _session_logger = SessionLogger()
    return _session_logger


def init_logging() -> SessionLogger:
    """Initialize (or return) the session logger. Safe to call multiple times."""
    return get_session_logger()
