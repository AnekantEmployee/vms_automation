const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

export async function uploadExcel(file: File, scanName?: string): Promise<{ job_id: string; filename: string }> {
  const fd = new FormData();
  fd.append("file", file);
  if (scanName) fd.append("scan_name", scanName);
  const res = await fetch(`${BASE}/api/upload`, { method: "POST", body: fd });
  if (!res.ok) throw new Error("Upload failed");
  return res.json();
}

export async function listScans(): Promise<ScanSession[]> {
  const res = await fetch(`${BASE}/api/scans`);
  if (!res.ok) throw new Error("Failed to fetch scans");
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const res = await fetch(`${BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error("Failed to fetch scan");
  return res.json();
}

export async function getAssetDetail(scanId: string, rowId: string): Promise<AssetRow> {
  const res = await fetch(`${BASE}/api/scans/${scanId}/${rowId}`);
  if (!res.ok) throw new Error("Failed to fetch asset");
  return res.json();
}

export async function deleteScan(scanId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/scans/${scanId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete scan");
}

export async function deleteAsset(scanId: string, rowId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/scans/${scanId}/${rowId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete asset");
}

export async function addManualAssets(scanId: string, assets: ManualAsset[]): Promise<void> {
  const res = await fetch(`${BASE}/api/scans/${scanId}/add/manual`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(assets),
  });
  if (!res.ok) throw new Error("Failed to add assets");
}

export async function addExcelAssets(scanId: string, file: File): Promise<void> {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch(`${BASE}/api/scans/${scanId}/add/excel`, { method: "POST", body: fd });
  if (!res.ok) throw new Error("Failed to add assets from file");
}

// ── CVE Exploitability ────────────────────────────────────────────────────────

export async function listExploits(): Promise<ExploitRecord[]> {
  const res = await fetch(`${BASE}/api/exploits`);
  if (!res.ok) throw new Error("Failed to fetch exploits");
  return res.json();
}

export async function analyseExploit(cveId: string, forceRefresh = false): Promise<ExploitResult> {
  const url = `${BASE}/api/exploit?cve_id=${encodeURIComponent(cveId)}&force_refresh=${forceRefresh}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error("Failed to analyse CVE");
  return res.json();
}

export async function getExploit(cveId: string): Promise<ExploitRecord> {
  const res = await fetch(`${BASE}/api/exploits/${encodeURIComponent(cveId)}`);
  if (!res.ok) throw new Error("CVE not found");
  return res.json();
}

export async function deleteExploit(cveId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/exploits/${encodeURIComponent(cveId)}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete CVE record");
}

export function duration(start: string | null, end: string | null): string {
  if (!start || !end) return "—";
  const secs = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000);
  return formatSecs(secs);
}

export function formatSecs(secs: number): string {
  if (!secs) return "—";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60), s = secs % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

// ── Qualys ────────────────────────────────────────────────────────────────────────────────

export async function uploadQualys(file: File, scanName?: string): Promise<{ job_id: string; filename: string }> {
  const fd = new FormData();
  fd.append("file", file);
  if (scanName) fd.append("scan_name", scanName);
  const res = await fetch(`${BASE}/api/qualys/upload`, { method: "POST", body: fd });
  if (!res.ok) throw new Error("Upload failed");
  return res.json();
}

export async function listQualysScans(): Promise<QualysScanSession[]> {
  const res = await fetch(`${BASE}/api/qualys/scans`);
  if (!res.ok) throw new Error("Failed to fetch qualys scans");
  return res.json();
}

export async function getQualysScan(scanId: string): Promise<QualysScanDetail> {
  const res = await fetch(`${BASE}/api/qualys/scans/${scanId}`);
  if (!res.ok) throw new Error("Failed to fetch qualys scan");
  return res.json();
}

export async function searchByIp(ip: string): Promise<AssetRow[]> {
  const res = await fetch(`${BASE}/api/scans/search?ip=${encodeURIComponent(ip)}`);
  if (res.status === 404) return [];
  if (!res.ok) throw new Error("Search failed");
  return res.json();
}

export async function deleteQualysRow(scanId: string, rowId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/qualys/scans/${scanId}/${rowId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete row");
}

export async function deleteQualysScan(scanId: string): Promise<void> {
  const res = await fetch(`${BASE}/api/qualys/scans/${scanId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete qualys scan");
}

export function createWebSocket(jobId: string): WebSocket {
  const WS = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8001";
  return new WebSocket(`${WS}/ws/${jobId}`);
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type ManualAsset = {
  ip: string;
  declared_role?: string;
  data_classification?: string;
  environment?: string;
  owner?: string;
};

export type ScanSession = {
  id: string;
  filename: string;
  scan_name: string | null;
  total_assets: number;
  total_asset_secs: number;
  status: "processing" | "done" | "error";
  created_at: string;
  completed_at: string | null;
};

export type AssetRow = {
  id: string;
  scan_id: string;
  row_index: number;
  ip: string;
  declared_role: string;
  data_classification: string;
  environment: string;
  owner: string;
  status: "pending" | "done" | "error";
  result: Record<string, unknown> | null;
  started_at: string | null;
  scanned_at: string | null;
};

export type ScanDetail = ScanSession & { assets: AssetRow[] };

// ── CVE Exploitability types ────────────────────────────────────────────────────

export type UniqueExploit = {
  name: string;
  url: string;
  source: string;
  reliability: number;
  weaponization: number;
  skill_required: number;
  exploit_type: string;
  notes: string;
};

export type ExploitResult = {
  cve_id: string;
  analysed_at: string;
  description?: string;
  cvss_v3_score?: number;
  cvss_v3_vector?: string;
  cvss_v2_score?: number;
  severity?: string;
  cwe?: string[];
  affected_products?: string[];
  references?: string[];
  published?: string;
  raw_exploit_count: number;
  sources_searched: string[];
  raw_exploits_by_source: Record<string, number>;
  exploit_count?: number;
  unique_exploits?: UniqueExploit[];
  most_dangerous_url?: string;
  most_dangerous_notes?: string;
  has_metasploit?: boolean;
  has_full_exploit?: boolean;
  analysis_notes?: string;
  exploitability_score?: number;
  exploitability_tier?: string;
  tier_label?: string;
  epss_estimate?: number;
  attacker_profile?: string;
  attack_complexity?: string;
  exploit_maturity?: string;
  in_the_wild?: boolean;
  patch_priority?: string;
  mitigations?: string[];
  executive_summary?: string;
  [key: string]: unknown;
};

export type ExploitRecord = {
  id: string;
  cve_id: string;
  analysed_at: string;
  result: ExploitResult;
};

export type QualysScanSession = {
  id: string;
  filename: string;
  scan_name: string | null;
  total_rows: number;
  total_asset_secs: number;
  status: "processing" | "done" | "error";
  created_at: string;
  completed_at: string | null;
};

export type QualysRow = {
  id: string;
  scan_id: string;
  row_index: number;
  status: "pending" | "done" | "error";
  result: {
    cve: string;
    cve_description: string;
    cvss_v2: string;
    cvss_v3: string;
    qid: string;
    title: string;
    severity: string;
    kb_severity: string;
    type_detected: string;
    last_detected: string;
    first_detected: string;
    protocol: string;
    port: string;
    vuln_status: string;
    asset_id: string;
    asset_name: string;
    asset_ipv4: string;
    asset_ipv6: string;
    solution: string;
    asset_tags: string;
    disabled: string;
    ignored: string;
    qvs_score: string;
    detection_age: string;
    published_date: string;
    patch_released: string;
    category: string;
    cvss_rating_label: string;
    rti: string;
    operating_system: string;
    last_fixed: string;
    last_reopened: string;
    times_detected: string;
    threat: string;
    vuln_patchable: string;
    asset_critical_score: string;
    trurisk_score: string;
    vulnerability_tags: string;
    results: string;
    kb?: {
      qid: string;
      vuln_type: string;
      severity: string;
      title: string;
      category: string;
      sub_category: string;
      published: string;
      last_modified: string;
      patchable: string;
      patch_published: string;
      cvss_base: string;
      cvss_temporal: string;
      cvss_vector: string;
      cvss3_base: string;
      cvss3_temporal: string;
      cvss3_vector: string;
      cvss3_attack_vector: string;
      cve_ids: string[];
      threat_intel: string;
      affected_software: string[];
      affected_products: string;
      diagnosis: string;
      consequence: string;
      solution: string;
      exploitability: string;
      associated_malware: string;
      discovery_remote: string;
      discovery_auth: string;
      compliance: { type: string; section: string; description: string }[];
    };
  } | null;
  started_at: string | null;
  scanned_at: string | null;
};

export type QualysScanDetail = QualysScanSession & { rows: QualysRow[] };
