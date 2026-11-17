import { useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { Save } from "lucide-react";
import { useIsolateStore } from "../stores/isolateStore";
import type { Theme } from "../stores/isolateStore";
import { useTheme } from "../lib/theme";

const THEMES: { id: Theme; label: string; sub: string; accent: string }[] = [
  { id: "cyber", label: "Cyberpunk",  sub: "Neon green · glowing borders · scanlines", accent: "#00ff9f" },
  { id: "soc",   label: "SOC / SIEM", sub: "Midnight blue · amber alerts · ops-center",  accent: "#38bdf8" },
];

export default function Settings() {
  const { theme, setTheme } = useIsolateStore();
  const t = useTheme();
  const [restUrl, setRestUrl] = useState("http://127.0.0.1:7778");
  const [wsUrl,   setWsUrl]   = useState("ws://127.0.0.1:7779/ws/events");
  const [saved,   setSaved]   = useState(false);

  const save = async () => {
    await invoke("set_daemon_url", { restUrl, wsUrl });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const sectionLabel = (label: string) => (
    <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 12 }}>
      // {label}
    </div>
  );

  const inputStyle = {
    width: "100%" as const,
    background: t.bgInput,
    border: `1px solid ${t.border}`,
    color: t.text,
    fontFamily: "JetBrains Mono, monospace",
    fontSize: 12,
    padding: "8px 12px",
    outline: "none",
    caretColor: t.accent,
    boxSizing: "border-box" as const,
  };

  const cardTop = (
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${t.accent}30, transparent)` }} />
  );

  return (
    <div style={{ padding: 24, maxWidth: 540, display: "flex", flexDirection: "column", gap: 28 }}>

      {/* Header */}
      <div>
        <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 3 }}>
          // settings
        </div>
        <div style={{ color: t.textFaint, fontSize: 11 }}>Daemon endpoints · appearance</div>
      </div>

      {/* Theme picker */}
      <div>
        {sectionLabel("UI Theme")}
        <div style={{ display: "flex", gap: 12 }}>
          {THEMES.map((th) => {
            const isActive = theme === th.id;
            return (
              <button
                key={th.id}
                onClick={() => setTheme(th.id)}
                style={{
                  flex: 1,
                  textAlign: "left",
                  padding: "14px 16px",
                  background: t.bgCard,
                  border: `1px solid ${isActive ? th.accent : t.border}`,
                  boxShadow: isActive ? `0 0 12px ${th.accent}20` : "none",
                  cursor: "pointer",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                {isActive && <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: th.accent }} />}
                <div style={{ color: isActive ? th.accent : t.text, fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                  {th.label}
                </div>
                <div style={{ color: t.textFaint, fontSize: 10 }}>{th.sub}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Daemon URLs */}
      <div>
        {sectionLabel("Daemon Endpoints")}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <label style={{ display: "block", color: t.textFaint, fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>
              REST API URL
            </label>
            <input
              style={inputStyle}
              value={restUrl}
              onChange={(e) => setRestUrl(e.target.value)}
              onFocus={(e) => { e.target.style.borderColor = t.borderAccent; }}
              onBlur={(e) => { e.target.style.borderColor = t.border; }}
            />
            <div style={{ color: t.textFaint, fontSize: 10, marginTop: 4 }}>Default: http://127.0.0.1:7778</div>
          </div>

          <div>
            <label style={{ display: "block", color: t.textFaint, fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>
              WebSocket URL
            </label>
            <input
              style={inputStyle}
              value={wsUrl}
              onChange={(e) => setWsUrl(e.target.value)}
              onFocus={(e) => { e.target.style.borderColor = t.borderAccent; }}
              onBlur={(e) => { e.target.style.borderColor = t.border; }}
            />
            <div style={{ color: t.textFaint, fontSize: 10, marginTop: 4 }}>Default: ws://127.0.0.1:7779/ws/events</div>
          </div>

          <div>
            <button
              onClick={save}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "8px 16px", fontSize: 11, fontWeight: 600,
                letterSpacing: "0.08em", textTransform: "uppercase",
                color: saved ? t.green : t.accent,
                background: saved ? `${t.green}12` : t.bgAccentFaint,
                border: `1px solid ${saved ? t.green : t.borderAccent}`,
                cursor: "pointer",
              }}
            >
              <Save size={13} />
              {saved ? "Saved!" : "Save"}
            </button>
          </div>
        </div>
      </div>

      {/* About */}
      <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: 20 }}>
        {sectionLabel("About")}
        <div style={{
          background: t.bgCard, border: `1px solid ${t.border}`,
          padding: "14px 16px", position: "relative", overflow: "hidden",
        }}>
          {cardTop}
          <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 11, color: t.textFaint }}>
            <div><span style={{ color: t.textDim }}>isolate-ui</span> v0.1.0</div>
            <div>Backend: <span style={{ color: t.accent }}>Rust + Tauri v1</span></div>
            <div>Frontend: <span style={{ color: t.accent }}>React + TypeScript</span></div>
            <div>Daemon: <span style={{ color: t.accent }}>isolatd :7777 / :7778 / :7779</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
