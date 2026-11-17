import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import Sidebar from "./components/Sidebar";
import Dashboard from "./views/Dashboard";
import IsoboxDetail from "./views/IsoboxDetail";
import PolicyEditor from "./views/PolicyEditor";
import AlertFeed from "./views/AlertFeed";
import FeedManager from "./views/FeedManager";
import Settings from "./views/Settings";
import { useIsolateStore } from "./stores/isolateStore";

const BG = { cyber: "#0a0a0a", soc: "#0b0f1a" };

export default function App() {
  const { addEvent, addAlert, setConnected, theme } = useIsolateStore();

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.body.style.background = BG[theme];
  }, [theme]);

  useEffect(() => {
    const unlisten = Promise.all([
      listen("isolate:event",        (ev) => addEvent(ev.payload as any)),
      listen("isolate:alert",        (ev) => addAlert(ev.payload as any)),
      listen("isolate:connected",    ()   => setConnected(true)),
      listen("isolate:disconnected", ()   => setConnected(false)),
    ]);
    return () => { unlisten.then((fns) => fns.forEach((fn) => fn())); };
  }, []);

  return (
    <div
      data-theme={theme}
      style={{ display: "flex", height: "100vh", background: BG[theme], overflow: "hidden" }}
    >
      <Sidebar />
      <main style={{ flex: 1, overflow: "auto" }}>
        <Routes>
          <Route path="/"                    element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"           element={<Dashboard />} />
          <Route path="/isoboxes/:id"        element={<IsoboxDetail />} />
          <Route path="/isoboxes/:id/policy" element={<PolicyEditor />} />
          <Route path="/alerts"              element={<AlertFeed />} />
          <Route path="/feeds"               element={<FeedManager />} />
          <Route path="/settings"            element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
