const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

export async function uploadExcel(file: File): Promise<{ job_id: string; filename: string }> {
  const fd = new FormData();
  fd.append("file", file);
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

export function createWebSocket(jobId: string): WebSocket {
  const WS = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8001";
  return new WebSocket(`${WS}/ws/${jobId}`);
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type ScanSession = {
  id: string;
  filename: string;
  total_assets: number;
  status: "processing" | "done" | "error";
  created_at: string;
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
  scanned_at: string | null;
};

export type ScanDetail = ScanSession & { assets: AssetRow[] };
