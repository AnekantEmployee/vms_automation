# 10 — Operations, Monitoring & Troubleshooting Runbook

This guide covers production operations, error triage, logging, and performance tuning for engineers supporting the platform.

---

## 1. Structured Logging & Auditing

The system uses structured session logging to record every network request, CVE lookup, and LLM call.

### 1.1 Log Destinations
- **Console Log**: Human-readable stdout/stderr formatted by `utils/logger.py`.
- **Session JSONL Logs (`logs/session_<timestamp>.jsonl`)**: Machine-readable JSON Lines logging each discrete step, token counts, and execution durations.
- **Session Summary (`logs/session_<timestamp>_summary.json`)**: Post-run summary recording:
  - Total elapsed time.
  - Total LLM prompts processed.
  - Failures and fallbacks invoked.
  - Cache hit vs cache miss rates.

### 1.2 Inspecting Logs
To inspect recent runs:
```bash
# View latest log files
Get-ChildItem logs/ | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

---

## 2. Troubleshooting Matrix & Common Failure Modes

| Symptom / Error | Root Cause | Solution / Fix |
|-----------------|------------|----------------|
| **`ResourceExhausted: 429 Resource has been exhausted (e.g. check quota)`** | Google Gemini API per-minute or daily quota exceeded on active key. | 1. Add backup Gemini keys in `.env` (`GOOGLE_API_KEY_1` to `10`).<br>2. Enable Groq fallback by setting `USE_GROQ=True` and providing `GROQ_API_KEY`.<br>3. Lower `LLM_RATE_LIMIT_PER_MINUTE` to `30`. |
| **`nmap.PortScannerError: 'nmap program was not found in path'`** | Nmap binary is not installed or not in system PATH. | Install Nmap and add `C:\Program Files (x86)\Nmap` to Windows System PATH. Restart terminal. |
| **`supabase.exceptions.PostgrestAPIError: relation "qualys_scans" does not exist`** | Supabase database is connected but table migrations have not been applied. | Run `python test_db_connection.py` to inspect connectivity and apply table schema from [`08_DATABASE_AND_STORAGE.md`](08_DATABASE_AND_STORAGE.md). |
| **`GitHub API rate limit exceeded (403 Forbidden)`** | Anonymous GitHub API calls are limited to 60/hour. | Set `GITHUB_TOKEN=ghp_...` in `.env` to raise limit to 5,000 requests/hour. |
| **`WebSocket connection to 'ws://localhost:8001/ws' failed`** | FastAPI backend is not running or blocked by local firewall. | 1. Ensure `python main.py` is running.<br>2. Verify port 8001 is listening (`netstat -ano \| findstr 8001`).<br>3. Check CORS origins in `main.py`. |
| **`Excel parsing error / BadZipFile: File is not a zip file`** | Uploaded file is corrupted or is a legacy binary `.xls` rather than modern `.xlsx`. | Re-save the file as standard `.xlsx` (Excel Workbook) or `.csv` before uploading. |
| **NVD API requests timing out (504 Gateway Timeout)** | NVD NIST API is experiencing public degradation. | Add `NVD_API_KEY` in `.env` (guarantees priority SLA), or allow fallback to Tavily/OSV DB. |

---

## 3. Maintenance & Periodic Housekeeping

### 3.1 Cleaning Cache Files
If stale vulnerability data or outdated PoC links persist:
```bash
# Clear local disk caches
python -c "
import glob, os
for f in glob.glob('cache/*.json') + glob.glob('backend/core/cache/*.json'):
    print('Removing:', f)
    os.remove(f)
"
```

### 3.2 Database Backup & Retention
For high-volume scanning environments:
- Archive older `qualys_scans` and `qualys_rows` older than 180 days.
- Regularly monitor Supabase project storage quotas.

---

## 4. API Key Verification Utility (`check_api_limit.py`)

A built-in script validates key health and measures API round-trip times:

```bash
python check_api_limit.py
```

**Output Breakdown**:
- Iterates over all declared `GOOGLE_API_KEY_*` variables in `.env`.
- Sends a minimal probe request (`"ping"`).
- Displays response time in milliseconds and quota status.
- Validates Groq and Tavily tokens.

---

## 5. Security Best Practices & Secrets Hygiene

> [!WARNING]
> **Never commit your `.env` file to Git.**
> Ensure `.env`, `.env.local`, and sensitive credential files remain in `.gitignore`.
> Rotate API tokens immediately if accidental exposure occurs.

- **Supabase Service Keys**: Keep administrative service keys restricted to the backend service. Only expose `anon` public keys to the frontend Next.js application.
- **Nmap Execution Safety**: Ensure Nmap scans are only directed at authorized IP ranges and assets within your organization's scope of work.
