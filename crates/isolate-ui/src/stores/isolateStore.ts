/**
 * Global Zustand store for the isolate desktop GUI.
 *
 * Holds:
 *   - isoboxes list (polled from REST API)
 *   - live event ring buffer (latest 2000 events from WebSocket relay)
 *   - alert list (latest 500 alerts)
 *   - connection status
 */

import { create } from "zustand";
import { invoke } from "@tauri-apps/api/tauri";

export interface Isobox {
  id: string;
  name: string;
  state: "running" | "frozen" | "stopped" | "error";
  backends: string[];
  workload_class: string;
  created_at: string;
  anomaly_score: number;
  paladin_level: number;
  event_count: number;
  alert_count: number;
}

export interface IsolateEvent {
  seq: number;
  timestamp: number;
  isobox_id: string;
  backend: string;
  body: Record<string, unknown>;
}

export interface Alert {
  id: string;
  isobox_id: string;
  severity: number;   // 0=info 1=warn 2=critical 3=emergency
  title: string;
  detail: string;
  anomaly_score: number;
  action_taken: string;
  paladin_level: number;
  created_at: string;
}

const EVENT_RING_SIZE = 2000;
const ALERT_RING_SIZE = 500;

export type Theme = "cyber" | "soc";

interface IsolateStore {
  // Theme
  theme: Theme;
  setTheme: (t: Theme) => void;

  // Connection
  connected: boolean;
  setConnected: (v: boolean) => void;

  // Isoboxes
  isoboxes: Isobox[];
  fetchIsoboxes: () => Promise<void>;
  updateIsoboxList: (items: Isobox[]) => void;

  // Events
  events: IsolateEvent[];
  addEvent: (ev: IsolateEvent) => void;

  // Alerts
  alerts: Alert[];
  addAlert: (alert: Alert) => void;

  // Actions
  freezeIsobox: (id: string) => Promise<void>;
  thawIsobox: (id: string) => Promise<void>;
  stopIsobox: (id: string) => Promise<void>;
  snapshotIsobox: (id: string, path: string) => Promise<void>;
}

export const useIsolateStore = create<IsolateStore>((set, get) => ({
  theme: (localStorage.getItem("isolate-theme") as Theme) ?? "cyber",
  setTheme: (t) => {
    localStorage.setItem("isolate-theme", t);
    set({ theme: t });
  },

  connected: false,
  setConnected: (v) => set({ connected: v }),

  isoboxes: [],
  fetchIsoboxes: async () => {
    try {
      const data = await invoke<{ isoboxes: Isobox[] }>("list_isoboxes");
      set({ isoboxes: data.isoboxes ?? [] });
    } catch (e) {
      console.error("fetchIsoboxes:", e);
    }
  },
  updateIsoboxList: (items) => set({ isoboxes: items }),

  events: [],
  addEvent: (ev) =>
    set((s) => ({
      events: [ev, ...s.events].slice(0, EVENT_RING_SIZE),
    })),

  alerts: [],
  addAlert: (alert) =>
    set((s) => ({
      alerts: [alert, ...s.alerts].slice(0, ALERT_RING_SIZE),
    })),

  freezeIsobox: async (id) => {
    await invoke("freeze_isobox", { id });
    await get().fetchIsoboxes();
  },
  thawIsobox: async (id) => {
    await invoke("thaw_isobox", { id });
    await get().fetchIsoboxes();
  },
  stopIsobox: async (id) => {
    await invoke("stop_isobox", { id });
    await get().fetchIsoboxes();
  },
  snapshotIsobox: async (id, path) => {
    await invoke("snapshot_isobox", { id, outputPath: path });
  },
}));
