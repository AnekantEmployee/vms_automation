import { create } from "zustand";
import { listScans, deleteScan, uploadExcel, type ScanSession } from "@/lib/api";

type AssetStore = {
  scans: ScanSession[];
  loading: boolean;
  deleting: string | null;

  fetchScans: () => Promise<void>;
  upload: (file: File, scanName?: string) => Promise<void>;
  remove: (id: string) => Promise<void>;
};

export const useAssetStore = create<AssetStore>((set, get) => ({
  scans: [],
  loading: true,
  deleting: null,

  fetchScans: async () => {
    try { set({ scans: await listScans() }); }
    finally { set({ loading: false }); }
  },

  upload: async (file, scanName) => {
    await uploadExcel(file, scanName);
    await get().fetchScans();
  },

  remove: async (id) => {
    set({ deleting: id });
    try { await deleteScan(id); await get().fetchScans(); }
    finally { set({ deleting: null }); }
  },
}));
