# 03 — Backend Architecture, Services & API Reference

The backend of VMS Automation is built using **FastAPI** (`main.py`) paired with **Uvicorn**, providing asynchronous REST endpoints, WebSocket real-time progress notifications, and modular service business logic.

---

## 1. Application Architecture & Middleware

- **Application Factory**: Instantiated in `main.py` with custom OpenAPI tags (`Scans`, `Assets`, `Exploits`, `Qualys`, `Recon`, `Health`).
- **CORS Middleware**: Preconfigured to allow access from local and network frontend clients (`http://localhost:3000`, `http://localhost:3001`, and internal IP subnets).
- **Service Layering**:
  - `backend/routes/`: Thin controller layer validating payloads with Pydantic.
  - `backend/services/`: Thick orchestration layer managing CrewAI, LangChain, threads, and Excel parsing.
  - `backend/core/`: Domain logic for asset criticality, Nmap execution, and exploit searches.
  - `backend/db/`: Supabase query layer with thread-safe client caching.

---

## 2. API Endpoints Catalog

### 2.1 Health Check
- **`GET /`**
  - **Tags**: `Health`
  - **Description**: Returns `{ "status": "ok" }`. Used by load balancers and container probes.

---

### 2.2 Upload & File Ingestion
- **`POST /api/upload`**
  - **Description**: Accepts an uploaded Excel (`.xlsx`) or CSV file (`file: UploadFile`).
  - **Process**: Reads binary content via `excel_processor.py`, parses columns, persists scan session metadata into Supabase, and schedules background row processing.
  - **Returns**: `{ "scan_id": "uuid", "total_assets": 120, "filename": "BSIRaw.xlsx" }`.

---

### 2.3 Qualys Management & Assessment
- **`GET /api/qualys/scans`**
  - **Description**: Lists all historical Qualys scan sessions with progress metrics, total rows, and status.
- **`GET /api/qualys/scans/{scan_id}`**
  - **Description**: Retrieves detailed overview of a scan session, including high/critical counts and row list.
- **`GET /api/qualys/scans/{scan_id}/rows/{row_id}`**
  - **Description**: Retrieves single row full assessment, including:
    - Enriched CVE details (NVD CVSS, summary, references)
    - AI Risk Assessment (risk score, category, immediate actions)
    - AI Remediation Plan (step-by-step instructions, rollback plan, verification)
    - Exploit intelligence references.
- **`DELETE /api/qualys/scans/{scan_id}/rows/{row_id}`**
  - **Description**: Deletes an individual vulnerability row from the session.
- **`DELETE /api/qualys/scans/{scan_id}`**
  - **Description**: Cascading delete for an entire scan session and all child vulnerability rows.
- **`GET /api/qualys/attack-chain?ip={ip}`**
  - **Description**: Dynamically generates an AI Attack Chain for a specified IP address based on all vulnerabilities associated with that asset in the database.

---

### 2.4 Asset Criticality & Scanning
- **`POST /api/assets/analyze`**
  - **Description**: Runs on-demand Asset Criticality & Risk Agent on a given IP.
  - **Request Body**:
    ```json
    {
      "ip": "192.168.1.50",
      "declared_role": "Database Server",
      "data_classification": "confidential",
      "environment": "production",
      "owner": "devops@company.com"
    }
    ```
  - **Response**:
    ```json
    {
      "ip": "192.168.1.50",
      "inferred_role": "PostgreSQL Primary Cluster",
      "criticality_score": 8.7,
      "criticality_tier": "CRITICAL",
      "open_ports": [22, 5432],
      "ip_intel": {
        "abuse_score": 0,
        "is_internet_facing": false,
        "asn": "AS13335"
      },
      "risk_summary": "High value asset handling confidential database records."
    }
    ```
- **`GET /api/scans`**
  - **Description**: Retrieves all asset scan jobs.
- **`GET /api/scans/search?ip={ip}`**
  - **Description**: Search asset records across scans matching an IP.

---

### 2.5 CVE Exploitability Analysis
- **`GET /api/exploits/{cve_id}`**
  - **Description**: Live exploitability intelligence for a specific CVE ID.
  - **Parameters**: `force_refresh` (boolean, optional — bypasses disk cache).
  - **Response Payload**:
    ```json
    {
      "cve_id": "CVE-2021-44228",
      "exploitability_tier": "WEAPONIZED",
      "exploitability_score": 9.8,
      "public_poc_available": true,
      "exploits_count": 45,
      "sources": {
        "github": [...],
        "exploitdb": [...],
        "packetstorm": [...],
        "vulners": [...]
      },
      "llm_analysis": {
        "summary": "Actively exploited RCE vulnerability in Apache Log4j...",
        "attack_vector": "Network, unauthenticated",
        "reliability": "Extremely high"
      }
    }
    ```

---

### 2.6 Passive Domain Reconnaissance
- **`POST /api/recon/start`**
  - **Request Body**: `{ "domain": "example.com" }`
  - **Process**: Launches passive DNS queries, certificate transparency scraping, and subdomain brute checks.
- **`GET /api/recon`**
  - **Description**: Lists all submitted domain reconnaissance jobs.
- **`GET /api/recon/{job_id}`**
  - **Description**: Retrieves discovered IP addresses, hostnames, and asset classifications for the target domain.
- **`POST /api/recon/import`**
  - **Description**: Imports discovered IPs from a recon job directly into an asset scan session for vulnerability testing.

---

### 2.7 WebSocket Real-Time Progress (`ws_router`)
- **`WebSocket /ws`**
  - **Protocol**: Standard WebSocket connection.
  - **Event Types Broadcasted**:
    - `ROW_START`: `{ "type": "ROW_START", "scan_id": "...", "row_index": 3, "total": 50 }`
    - `ROW_PROGRESS`: `{ "type": "ROW_PROGRESS", "step": "cve_search" | "risk_assessment" | "remediation" }`
    - `ROW_COMPLETE`: `{ "type": "ROW_COMPLETE", "row_id": "...", "result": { ... } }`
    - `SCAN_COMPLETE`: `{ "type": "SCAN_COMPLETE", "scan_id": "...", "status": "completed" }`
    - `SCAN_ERROR`: `{ "type": "SCAN_ERROR", "scan_id": "...", "error": "Reason" }`

---

## 3. Core Service Components

### `backend/services/qualys_processor.py`
The orchestration engine for vulnerability reports:
- Parses Excel/CSV into normalized Python dictionaries.
- Invokes `run_risk_agent(row)` which uses CrewAI to synthesize risk profiles.
- Executes `ImprovedRemediationAgent` to create customized mitigation paths.
- Writes real-time updates directly into Supabase while emitting WebSocket events.

### `backend/services/attack_chain_service.py`
- Groups all vulnerabilities discovered on a given target IP.
- Prompts an LLM Cyber Threat Intelligence Agent to map a step-by-step kill chain:
  1. **Initial Access**: Vulnerability exploited for entry.
  2. **Privilege Escalation**: Exploitation of local weaknesses.
  3. **Lateral Movement**: Potential network pivoting to adjacent subnets.
  4. **Data Exfiltration / Impact**: Ultimate target disruption.

### `backend/services/excel_processor.py`
- Safely decodes multi-format uploaded files (handling legacy Windows Excel codecs, `openpyxl`, and CSV delimiters).
- Sanitizes column names to standard internal keys (`IP`, `Vulnerability Title`, `CVSS`, `Port`, `Solution`, `Results`).

