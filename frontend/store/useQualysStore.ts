import { create } from "zustand";
import { listQualysScans, deleteQualysScan, uploadQualys, type QualysScanSession } from "@/lib/api";

type QualysStore = {
  scans: QualysScanSession[];
  loading: boolean;
  deleting: string | null;

  fetchScans: () => Promise<void>;
  upload: (file: File, scanName?: string) => Promise<void>;
  remove: (id: string) => Promise<void>;
};

export const useQualysStore = create<QualysStore>((set, get) => ({
  scans: [],
  loading: true,
  deleting: null,

  fetchScans: async () => {
    try { set({ scans: await listQualysScans() }); }
    finally { set({ loading: false }); }
  },

  upload: async (file, scanName) => {
    await uploadQualys(file, scanName);
    await get().fetchScans();
  },

  remove: async (id) => {
    set({ deleting: id });
    try { await deleteQualysScan(id); await get().fetchScans(); }
    finally { set({ deleting: null }); }
  },
}));
