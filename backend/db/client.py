import os
import threading
import socket
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

_client: Client | None = None
_lock = threading.Lock()


def check_db_connectivity(url: str) -> tuple[bool, str]:
    """
    Test if we can resolve the Supabase hostname.
    
    Returns (success: bool, message: str)
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]  # Extract hostname without port
        
        # Try DNS resolution
        ip = socket.gethostbyname(hostname)
        return True, f"✓ DNS resolved {hostname} → {ip}"
    except socket.gaierror as e:
        return False, f"✗ DNS resolution failed for {hostname}: {e}"
    except Exception as e:
        return False, f"✗ Connectivity check failed: {e}"


def _make_client() -> Client:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    
    # Diagnostic check before attempting connection
    success, msg = check_db_connectivity(url)
    print(f"[db] {msg}")
    if not success:
        raise RuntimeError(
            f"Cannot reach Supabase: {msg}\n"
            f"Check: 1) Internet connection, 2) DNS resolution, 3) Firewall rules"
        )
    
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
