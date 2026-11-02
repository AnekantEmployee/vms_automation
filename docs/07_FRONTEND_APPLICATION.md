# 07 — Frontend Application Architecture

The user interface of VMS Automation is a web application located in `/frontend`, built with **Next.js 15 (App Router)**, **React 18**, **Tailwind CSS 4**, and **Zustand** state stores.

---

## 1. Directory Structure & App Routing

```
frontend/
├── app/
│   ├── globals.css                       # Global styles and Tailwind configuration
│   ├── layout.tsx                        # Master RootLayout containing Sidebar and WSListener
│   ├── page.tsx                          # Root index redirecting to dashboard
│   ├── dashboard/                        # Primary Qualys Scan Management
│   │   ├── page.tsx                      # All Qualys Scans list & aggregated metrics
│   │   ├── [scan_id]/                    # Specific Qualys Scan Overview
│   │   │   ├── page.tsx                  # Filterable table of all vulnerability rows
│   │   │   └── [row_id]/                 # Deep dive into a single vulnerability row
│   │   │       └── page.tsx              # AI Risk, Remediation, Attack Chain & PoCs
│   ├── asset-scanning/                   # Asset Discovery & Criticality module
│   │   ├── page.tsx                      # Asset scan sessions and manual asset addition
│   │   └── [scan_id]/                    # Asset scan inventory
│   │       ├── page.tsx                  # Table of assets, inferred roles, and scores
│   │       └── [row_id]/                 # Single asset inspection (Nmap, Ports, Intel)
│   │           └── page.tsx
│   ├── cve-exploitability/               # CVE Exploitability Lookup tool
│   │   ├── page.tsx                      # CVE search bar & recent exploit lookups
│   │   └── [cve_id]/                     # Exploitability intelligence detail view
│   │       └── page.tsx                  # PoC links, GitHub repos, and exploit scripts
│   └── results/                          # Global aggregated results
├── components/
│   ├── FileUpload.tsx                    # Drag-and-drop Excel/CSV upload with progress
│   ├── ResultsTable.tsx                  # High-performance virtualized vulnerability table
│   ├── Sidebar.tsx                       # Navigation sidebar across all platform modules
│   └── WSListener.tsx                    # Global headless WebSocket event listener
├── lib/
│   └── api.ts                            # Typed HTTP fetch client for FastAPI backend
└── store/
    ├── useQualysStore.ts                 # Zustand store for Qualys sessions & active scan
    ├── useAssetStore.ts                  # Zustand store for Asset inventory & analysis
    ├── useExploitStore.ts                # Zustand store for CVE exploitability states
    └── useJobStore.ts                    # Zustand store for live WebSocket row processing
```

---

## 2. Layout & Global Navigation

### `frontend/app/layout.tsx`
The root layout wraps every route with:
1. **Sidebar Navigation** (`components/Sidebar.tsx`): Persistent left rail providing links to:
   - **Dashboard**: Qualys vulnerability scans.
   - **Asset Scanning**: Nmap scans, asset roles, and criticality scores.
   - **CVE Exploitability**: Dedicated exploit intelligence explorer.
   - **Passive Recon**: Domain discovery jobs.
2. **Global WebSocket Listener** (`components/WSListener.tsx`): Initializes a persistent WebSocket connection to `ws://localhost:8001/ws` on application load. When scanning jobs are running, incoming WebSocket frames automatically update Zustand stores without requiring manual page refreshes.

---

## 3. Key Pages & Features

### 3.1 Dashboard & Qualys Scan Detail (`/dashboard/[scan_id]`)
- **Executive Summary Cards**:
  - Total Vulnerabilities, Critical Count, High Count, Average CVSS Score.
- **Search & Filtering**:
  - Filter by Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Search by CVE, Asset IP, Vulnerability Title, Port, or Service.
- **Attack Chain Visualizer**:
  - Renders a multi-hop kill chain button next to any IP address. Clicking queries `/api/qualys/attack-chain?ip={ip}` and displays an interactive modal explaining the attacker progression across the asset's vulnerabilities.

### 3.2 Single Vulnerability Row Inspection (`/dashboard/[scan_id]/[row_id]`)
Provides a comprehensive view of the vulnerability:
- **Header**: Vulnerability title, asset IP, port, protocol, scanner severity.
- **AI Risk Assessment Panel**:
  - Risk category badge, risk score meter (0–100), and business impact statement.
  - Exploitation methods and urgent triage actions.
- **AI Remediation Guidance**:
  - Step-by-step resolution commands, verification commands, and rollback strategy.
- **Live PoC & Exploitability Panel**:
  - Public PoC indicator (`WEAPONIZED` / `ACTIVE_POC` / `NONE`).
  - Direct hyperlinks to GitHub exploit repositories and Exploit-DB entries.

### 3.3 Asset Scanning & Inferred Criticality (`/asset-scanning`)
- Lists scanned IP assets with:
  - Criticality Score badge (1.0 – 10.0) with color coding.
  - Inferred Role (e.g., `Linux Edge Proxy (Nginx)`).
  - Open Ports pills (`22`, `80`, `443`, `3306`).
  - AbuseIPDB reputation score.
- **Detailed Asset View (`/asset-scanning/[scan_id]/[row_id]`)**:
  - Full Nmap port list with service versions.
  - Whois / ASN / Geolocation data.
  - Vulnerability list associated with this specific asset.

---

## 4. State Management with Zustand

The UI uses Zustand for lightweight, boilerplate-free state management:

### `useJobStore.ts`
Coordinates live WebSocket events:
```typescript
interface JobStore {
  activeJobs: Record<string, RowResult>;
  currentScanProgress: { processed: number; total: number; percentage: number };
  handleWSEvent: (event: WSEvent) => void;
}
```
When `components/WSListener.tsx` receives a message, it dispatches to `handleWSEvent`, updating row states and progress meters in the UI.

### `useQualysStore.ts` & `useAssetStore.ts`
Cache API payloads for scan sessions, preventing redundant network requests when switching tabs.

---

## 5. Development & Production Build Commands

```bash
cd frontend

# Development server with Turbopack / Fast Refresh
npm run dev

# Production build
npm run build

# Start production server
npm run start
```
By default, the frontend binds to port 3000 (`http://localhost:3000`).
