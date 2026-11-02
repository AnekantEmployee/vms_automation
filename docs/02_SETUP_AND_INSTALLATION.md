# 02 — Setup, Installation & Environment Configuration

This runbook guides a new engineer through setting up the VMS Automation development and production environments from scratch.

---

## 1. System Prerequisites

Ensure your host machine or container has the following dependencies installed:

| Tool / Dependency | Minimum Version | Recommended Version | Verification Command | Notes |
|-------------------|-----------------|---------------------|----------------------|-------|
| **Python** | 3.10 | 3.11+ | `python --version` | Virtual environment mandatory |
| **Node.js** | 18.0.0 | 20.x LTS | `node -v` | Required for Next.js frontend |
| **npm** | 9.0.0 | 10.x | `npm -v` | Installed with Node.js |
| **Nmap** | 7.90 | 7.94+ | `nmap --version` | Must be added to system PATH |
| **Redis** *(Optional)* | 6.0 | 7.x | `redis-cli ping` | Needed for background queue |
| **Git** | 2.30 | Latest | `git --version` | Version control |

> [!IMPORTANT]
> **Windows Users**: Install Nmap using the official Windows installer and ensure `C:\Program Files (x86)\Nmap` is added to your system `PATH`. Python's `python-nmap` module requires the native `nmap.exe` binary.

---

## 2. Repository Setup & Virtual Environment

Clone the repository and prepare the isolated Python virtual environment:

```bash
# Clone the repository
git clone https://github.com/AnekantEmployee/vms_automation.git
cd vms_automation

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (CMD):
.\venv\Scripts\activate.bat
# Linux / macOS:
source venv/bin/activate

# Upgrade pip and install core dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 3. Environment Variables Configuration (`.env`)

Create a `.env` file in the project root directory (`d:\vms_automation\.env`). The platform utilizes multi-provider fallbacks and multi-key rotation.

### Sample Configuration Template

```dotenv
# ==========================================
# 1. CORE LLM PROVIDERS & KEYS
# ==========================================
# Primary Google Gemini Key
GOOGLE_API_KEY=AIzaSy...

# Optional multi-key rotation pool for high-throughput batch scanning
GOOGLE_API_KEY_1=AIzaSy...
GOOGLE_API_KEY_2=AIzaSy...
GOOGLE_API_KEY_3=AIzaSy...
GOOGLE_API_KEY_4=AIzaSy...
GOOGLE_API_KEY_5=AIzaSy...
GOOGLE_API_KEY_6=AIzaSy...
GOOGLE_API_KEY_7=AIzaSy...
GOOGLE_API_KEY_8=AIzaSy...
GOOGLE_API_KEY_9=AIzaSy...
GOOGLE_API_KEY_10=AIzaSy...

# Groq LLM Key (Fallback & Fast inference)
GROQ_API_KEY=gsk_...
GROQ_API_KEY_1=gsk_...
GROQ_API_KEY_2=gsk_...

# LLM Selection Flags (True/False)
USE_GEMINI=True
USE_GROQ=True
MODEL_NAME=gemini-2.0-flash

# LLM Rate Limiting & Timeouts
LLM_RATE_LIMIT_PER_MINUTE=60
LLM_TIMEOUT_SECONDS=45
RISK_ASSESSMENT_TIMEOUT=60
REMEDIATION_TIMEOUT=60

# ==========================================
# 2. THREAT INTEL & SCANNING API KEYS
# ==========================================
# NIST National Vulnerability Database API Key (Accelerates NVD lookups from 6s to 0.6s)
NVD_API_KEY=

# GitHub Personal Access Token (Increases rate limit from 60 to 5000 requests/hr for PoC scraping)
GITHUB_TOKEN=ghp_...

# Tavily AI Search (For intelligent web CVE and vulnerability research)
TAVILY_API_KEY=tvly-...

# Shodan API Key (For asset reconnaissance and open port intelligence)
SHODAN_API_KEY=

# AbuseIPDB API Key (For IP reputation and malicious confidence score)
ABUSEIPDB_API_KEY=

# Vulners API Key (Exploit and security advisory lookup)
VULNERS_API_KEY=

# ==========================================
# 3. DATABASE & PERSISTENCE
# ==========================================
# Supabase PostgreSQL API Endpoint & Service Key
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=eyJh...

# Redis Connection URL (For background job queues)
REDIS_URL=redis://localhost:6379/0

# ==========================================
# 4. QUALYS INTEGRATION (Optional)
# ==========================================
QUALYS_USERNAME=
QUALYS_PASSWORD=
```

---

## 4. Frontend Setup (Next.js 15)

The frontend lives under `/frontend`. It is built with Next.js 15, React 18, and Tailwind CSS.

```bash
cd frontend

# Install Node dependencies
npm install

# Setup frontend environment file (.env.local)
# Set your backend API URL and Supabase URL/Key
```

`frontend/.env.local`:
```dotenv
NEXT_PUBLIC_API_URL=http://localhost:8001/api
NEXT_PUBLIC_WS_URL=ws://localhost:8001/ws
NEXT_PUBLIC_SUPABASE_URL=https://your-project-id.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJh...
```

---

## 5. Verification & Health Checks

Verify your environment configuration before running jobs:

### 1. Database Connection Check
```bash
python test_db_connection.py
```
*Expected Output: Confirms DNS resolution and successful authentication with Supabase tables.*

### 2. API Key Quota & Verification Check
```bash
python check_api_limit.py
```
*Expected Output: Validates which Gemini and Groq keys are active, their remaining quota status, and latency.*

### 3. Nmap Local Scanner Check
```bash
python test_nmap_results.py
```
*Expected Output: Tests the parsing of Nmap service banners and XML outputs.*

---

## 6. Running the Applications

### Starting the FastAPI Backend Service
```bash
# From repository root
python main.py
# Server will listen on http://0.0.0.0:8001
# OpenAPI interactive docs available at http://localhost:8001/docs
```

### Starting the Next.js Frontend Development Server
```bash
cd frontend
npm run dev
# Web application available at http://localhost:3000
```

### Starting the Streamlit Orchestrator UI
```bash
# Alternative UI for standalone batch report enrichment
streamlit run report.py --server.address 0.0.0.0 --server.port 8502
# UI available at http://localhost:8502
```
