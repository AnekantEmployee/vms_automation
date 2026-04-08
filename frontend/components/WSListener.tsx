"use client";

import { useEffect, useRef } from "react";
import { useJobStore } from "@/store/useJobStore";
import { createWebSocket } from "@/lib/api";

export default function WSListener() {
  const { jobId, addResult, markDone, setConnected } = useJobStore();
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    // Close old socket if jobId changes
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    if (!jobId) return;

    const ws = createWebSocket(jobId);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.status === "done") {
        markDone();
        ws.close();
      } else {
        addResult(data);
      }
    };

    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);

    return () => {
      ws.close();
    };
  }, [jobId]);

  return null; // invisible — just keeps the socket alive
}
