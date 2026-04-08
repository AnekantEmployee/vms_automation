import { create } from "zustand";

export type RowResult = {
  job_id: string;
  row_index: number;
  total_rows: number;
  row_data: Record<string, unknown>;
  result: Record<string, unknown>;
  status: "processing" | "done";
};

type JobStore = {
  jobId: string | null;
  filename: string | null;
  results: RowResult[];
  isDone: boolean;
  isConnected: boolean;

  setJob: (jobId: string, filename: string) => void;
  addResult: (row: RowResult) => void;
  markDone: () => void;
  setConnected: (val: boolean) => void;
  reset: () => void;
};

export const useJobStore = create<JobStore>((set) => ({
  jobId: null,
  filename: null,
  results: [],
  isDone: false,
  isConnected: false,

  setJob: (jobId, filename) =>
    set({ jobId, filename, results: [], isDone: false }),

  addResult: (row) =>
    set((state) => ({ results: [...state.results, row] })),

  markDone: () => set({ isDone: true }),

  setConnected: (val) => set({ isConnected: val }),

  reset: () =>
    set({ jobId: null, filename: null, results: [], isDone: false, isConnected: false }),
}));
