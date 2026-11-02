#!/usr/bin/env python
"""
test_db_connection.py — Diagnose Supabase connectivity issues.

Checks:
  1. Environment variables are loaded
  2. DNS can resolve Supabase hostname
  3. TCP connection to Supabase API
  4. Supabase client can be created
  5. Database query executes (ping)
"""

import os
import socket
import sys
from urllib.parse import urlparse
from dotenv import load_dotenv

# Colours
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def fail(msg): print(f"  {RED}✗{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")

print(f"\n{'='*60}")
print(f"  Supabase Connectivity Diagnostic")
print(f"{'='*60}\n")

# 1. Load .env
print("1. Loading environment...")
load_dotenv()
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

if not url or not key:
    fail("SUPABASE_URL or SUPABASE_KEY not set in .env")
    sys.exit(1)

ok(f"Loaded SUPABASE_URL: {url[:40]}...")
ok(f"Loaded SUPABASE_KEY: {key[:20]}...")

# 2. Parse and validate URL
print("\n2. Parsing URL...")
try:
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    ok(f"Hostname: {hostname}")
except Exception as e:
    fail(f"Failed to parse URL: {e}")
    sys.exit(1)

# 3. DNS resolution
print("\n3. Testing DNS resolution...")
try:
    ip = socket.gethostbyname(hostname)
    ok(f"Resolved {hostname} → {ip}")
except socket.gaierror as e:
    fail(f"DNS resolution failed: {e}")
    warn("Possible causes: No internet, DNS not responding, firewall blocking")
    sys.exit(1)

# 4. TCP connection
print("\n4. Testing TCP connection...")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((ip, 443))
    sock.close()
    if result == 0:
        ok(f"TCP connection successful to {ip}:443")
    else:
        fail(f"TCP connection failed (code {result})")
        warn("Possible causes: Firewall blocking, port 443 not accessible")
        sys.exit(1)
except Exception as e:
    fail(f"TCP test error: {e}")
    sys.exit(1)

# 5. Supabase client creation
print("\n5. Creating Supabase client...")
try:
    from supabase import create_client
    client = create_client(url, key)
    ok("Supabase client created successfully")
except Exception as e:
    fail(f"Failed to create client: {e}")
    sys.exit(1)

# 6. Test database query
print("\n6. Testing database query (ping)...")
try:
    result = client.table("asset_scanning").select("id").limit(1).execute()
    ok(f"Database query successful ({len(result.data)} rows returned)")
except Exception as e:
    error_msg = str(e)
    if "does not exist" in error_msg.lower() or "relation" in error_msg.lower():
        warn(f"Table 'asset_scanning' not found (table may not exist yet): {error_msg[:80]}")
    else:
        fail(f"Database query failed: {error_msg[:100]}")
    sys.exit(1)

print(f"\n{'='*60}")
print(f"  {GREEN}All checks passed!{RESET}")
print(f"{'='*60}\n")
