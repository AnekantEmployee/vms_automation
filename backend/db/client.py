import os
import threading
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

_client: Client | None = None
_lock = threading.Lock()


def _make_client() -> Client:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    return create_client(url, key)


def get_db() -> Client:
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = _make_client()
    return _client


def reset_db() -> Client:
    """Force-recreate the Supabase client after a connection error."""
    global _client
    with _lock:
        _client = _make_client()
    return _client
