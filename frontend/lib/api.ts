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
