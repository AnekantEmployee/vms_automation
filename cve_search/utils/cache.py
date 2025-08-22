"""Cache management utilities for CVE search system."""

from threading import Lock

# Cache storage and locks
_nist_cache = {}
_cve_org_cache = {}
_cache_lock = Lock()


def get_nist_cache():
    """Get NIST cache dictionary."""
    return _nist_cache


def get_cve_org_cache():
    """Get CVE.org cache dictionary."""
    return _cve_org_cache


def get_cache_lock():
    """Get the cache lock for thread-safe operations."""
    return _cache_lock


def clear_caches():
    """Clear all caches."""
    global _nist_cache, _cve_org_cache
    
    with _cache_lock:
        _nist_cache.clear()
        _cve_org_cache.clear()
    
    print("All caches have been cleared.")


def cache_nist_results(query: str, results):
    """Cache NIST results for a query."""
    with _cache_lock:
        _nist_cache[query] = results


def get_cached_nist_results(query: str):
    """Get cached NIST results for a query."""
    with _cache_lock:
        return _nist_cache.get(query)


def cache_cve_org_results(query: str, results):
    """Cache CVE.org results for a query."""
    with _cache_lock:
        _cve_org_cache[query] = results


def get_cached_cve_org_results(query: str):
    """Get cached CVE.org results for a query."""
    with _cache_lock:
        return _cve_org_cache.get(query)