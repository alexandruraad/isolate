import { useEffect, CSSProperties } from "react";
import { useNavigate } from "react-router-dom";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Snowflake, Trash2, Camera, AlertTriangle } from "lucide-react";
import { useIsolateStore } from "../stores/isolateStore";
import type { Isobox } from "../stores/isolateStore";
import { useTheme, type ThemeTokens } from "../lib/theme";

// ── Shared primitives ────────────────────────────────────────────────────────

function SectionLabel({ label, t }: { label: string; t: ThemeTokens }) {
  return (
    <div style={{
      color: t.accent,
      fontSize: 10,
      fontWeight: 700,
      letterSpacing: "0.12em",
      textTransform: "uppercase",
      marginBottom: 12,
    }}>
      // {label}
    </div>
  );
}

function Card({ children, style }: { children: React.ReactNode; style?: CSSProperties }) {
  const t = useTheme();
  return (
    <div style={{
      background: t.bgCard,
      border: `1px solid ${t.border}`,
      position: "relative",
      overflow: "hidden",
      ...style,
    }}>
      {/* top gradient line */}
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: 1,
        background: `linear-gradient(90deg, transparent, ${t.accent}35, transparent)`,
      }} />
      {children}
    </div>
  );
}

// ── Badges ───────────────────────────────────────────────────────────────────

function AnomalyBadge({ score, t }: { score: number; t: ThemeTokens }) {
  const pct = Math.round(score * 100);
  const color = pct >= 75 ? t.red : pct >= 50 ? t.yellow : t.green;
  return (
    <span style={{
      padding: "1px 6px",
      fontSize: 10,
      fontWeight: 700,
      color,
      background: `${color}18`,
      border: `1px solid ${color}40`,
      letterSpacing: "0.04em",
    }}>
      {pct}%
    </span>
  );
}

function PaladinBadge({ level, t }: { level: number; t: ThemeTokens }) {
  if (level === 0) return null;
  const names = ["", "ALERT", "CONTAIN", "FREEZE", "TERMINATE", "SCORCH", "RAMPART", "ABSOLUTION"];
  const color = level >= 6 ? t.red : level >= 4 ? t.orange : level >= 2 ? t.yellow : t.blue;
  return (
    <span style={{
      padding: "1px 6px",
      fontSize: 10,
      fontWeight: 700,
      color,
      background: `${color}18`,
      border: `1px solid ${color}40`,
      letterSpacing: "0.04em",
    }}>
      ⚔ {names[level] ?? `L${level}`}
    </span>
  );
}

// ── Isobox card ───────────────────────────────────────────────────────────────

function IsoboxCard({ box }: { box: Isobox }) {
  const navigate = useNavigate();
  const { freezeIsobox, thawIsobox, stopIsobox, snapshotIsobox } = useIsolateStore();
  const t = useTheme();

  const stateColor =
    box.state === "running" ? t.green :
    box.state === "frozen"  ? t.blue  :
    box.state === "error"   ? t.red   : t.textFaint;

  return (
    <Card style={{ cursor: "pointer" }}>
      <div
        style={{ padding: 16 }}
        onClick={() => navigate(`/isoboxes/${box.id}`)}
      >
        {/* Name + badges */}
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 10 }}>
          <div>
            <div style={{ color: t.text, fontWeight: 700, fontSize: 13, marginBottom: 2 }}>{box.name}</div>
            <div style={{ color: t.textFaint, fontSize: 10, letterSpacing: "0.06em" }}>{box.workload_class}</div>
          </div>
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <AnomalyBadge score={box.anomaly_score} t={t} />
            <PaladinBadge level={box.paladin_level} t={t} />
          </div>
        </div>

        {/* State + backends */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, fontSize: 11 }}>
          <span style={{
            width: 6, height: 6, borderRadius: "50%",
            background: stateColor,
            boxShadow: `0 0 5px ${stateColor}`,
          }} />
          <span style={{ color: stateColor, fontWeight: 600, letterSpacing: "0.06em", textTransform: "capitalize" }}>
            {box.state}
          </span>
          <span style={{ color: t.border, fontSize: 10 }}>·</span>
          <span style={{ color: t.textFaint, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {box.backends.join(" · ")}
          </span>
        </div>

        {/* Stats */}
        <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 11 }}>
          <span style={{ color: t.textFaint }}>{box.event_count.toLocaleString()} events</span>
          {box.alert_count > 0 && (
            <span style={{ color: t.yellow, display: "flex", alignItems: "center", gap: 4 }}>
              <AlertTriangle size={11} />
              {box.alert_count} alerts
            </span>
          )}
        </div>
      </div>

      {/* Actions */}
      <div
        style={{
          display: "flex",
          gap: 6,
          padding: "10px 16px",
          borderTop: `1px solid ${t.border}`,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {box.state === "running" ? (
          <button
            onClick={() => freezeIsobox(box.id)}
            style={{
              display: "flex", alignItems: "center", gap: 5,
              padding: "4px 10px", fontSize: 10, fontWeight: 600,
              color: t.blue, background: `${t.blue}15`, border: `1px solid ${t.blue}35`,
              cursor: "pointer", letterSpacing: "0.06em",
            }}
          >
            <Snowflake size={11} /> Freeze
          </button>
        ) : box.state === "frozen" ? (
          <button
            onClick={() => thawIsobox(box.id)}
            style={{
              display: "flex", alignItems: "center", gap: 5,
              padding: "4px 10px", fontSize: 10, fontWeight: 600,
              color: t.green, background: `${t.green}15`, border: `1px solid ${t.green}35`,
              cursor: "pointer", letterSpacing: "0.06em",
            }}
          >
            Thaw
          </button>
        ) : null}

        <button
          onClick={() => snapshotIsobox(box.id, `/tmp/snapshot-${box.id}.zip`)}
          style={{
            display: "flex", alignItems: "center", gap: 5,
            padding: "4px 10px", fontSize: 10, fontWeight: 600,
            color: t.textDim, background: `${t.textFaint}10`, border: `1px solid ${t.border}`,
            cursor: "pointer", letterSpacing: "0.06em",
          }}
        >
          <Camera size={11} /> Snapshot
        </button>

        <button
          onClick={() => { if (confirm(`Stop isobox "${box.name}"?`)) stopIsobox(box.id); }}
          style={{
            display: "flex", alignItems: "center", gap: 5,
            padding: "4px 10px", fontSize: 10, fontWeight: 600,
            color: t.red, background: `${t.red}12`, border: `1px solid ${t.red}35`,
            cursor: "pointer", letterSpacing: "0.06em",
          }}
        >
          <Trash2 size={11} /> Stop
        </button>
      </div>
    </Card>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

async function seedDemo() {
  try {
    const r = await fetch("http://127.0.0.1:7778/api/v1/demo/seed", { method: "POST" });
    const j = await r.json();
    console.log("demo seeded:", j);
  } catch (e) {
    console.error("seed failed:", e);
  }
}

export default function Dashboard() {
  const { isoboxes, alerts, events, fetchIsoboxes } = useIsolateStore();
  const t = useTheme();

  useEffect(() => {
    fetchIsoboxes();
    const id = setInterval(fetchIsoboxes, 5000);
    return () => clearInterval(id);
  }, []);

  // Event rate buckets (last 60s, 12×5s)
  const now = Date.now();
  const buckets = Array.from({ length: 12 }, (_, i) => ({
    t: `${(11 - i) * 5}s`,
    count: 0,
  }));
  for (const ev of events) {
    // ev.timestamp is epoch milliseconds (converted by the WS relay from RFC3339)
    const age = (now - ev.timestamp) / 1000;
    const bucket = Math.floor(age / 5);
    if (bucket >= 0 && bucket < 12) buckets[11 - bucket].count++;
  }

  const critAlerts = alerts.filter((a) => a.severity >= 2).slice(0, 5);

  const stats = [
    { label: "Active",   value: isoboxes.filter((b) => b.state === "running").length, color: t.green },
    { label: "Frozen",   value: isoboxes.filter((b) => b.state === "frozen").length,  color: t.blue },
    { label: "Alerts",   value: alerts.length,     color: t.yellow },
    { label: "Critical", value: critAlerts.length, color: t.red },
  ];

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 24, overflowY: "auto" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 2 }}>
            // dashboard
          </div>
          <div style={{ color: t.textFaint, fontSize: 11 }}>
            {isoboxes.length} isobox{isoboxes.length !== 1 ? "es" : ""} · live telemetry
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => seedDemo().then(fetchIsoboxes)}
            style={{
              padding: "6px 14px", fontSize: 11, fontWeight: 600,
              letterSpacing: "0.08em", textTransform: "uppercase",
              color: t.yellow, background: `${t.yellow}12`,
              border: `1px solid ${t.yellow}40`, cursor: "pointer",
            }}
          >
            Seed Demo
          </button>
          <button
            onClick={fetchIsoboxes}
            style={{
              padding: "6px 14px", fontSize: 11, fontWeight: 600,
              letterSpacing: "0.08em", textTransform: "uppercase",
              color: t.accent, background: t.bgAccentFaint,
              border: `1px solid ${t.borderAccent}`, cursor: "pointer",
            }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div>
        <SectionLabel label="System Status" t={t} />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {stats.map(({ label, value, color }) => (
            <Card key={label}>
              <div style={{ padding: "14px 16px" }}>
                <div style={{ color: t.textFaint, fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>
                  {label}
                </div>
                <div style={{ color, fontSize: 32, fontWeight: 700, lineHeight: 1 }}>
                  {value}
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* Event rate chart */}
      <div>
        <SectionLabel label="Event Rate · Last 60s" t={t} />
        <Card>
          <div style={{ padding: "14px 16px" }}>
            <ResponsiveContainer width="100%" height={80}>
              <BarChart data={buckets} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
                <XAxis dataKey="t" tick={{ fontSize: 10, fill: t.chartAxis }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: t.chartAxis }} width={28} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: t.tooltipBg,
                    border: `1px solid ${t.tooltipBorder}`,
                    fontSize: 11,
                    color: t.text,
                    fontFamily: "JetBrains Mono, monospace",
                  }}
                  cursor={{ fill: `${t.accent}08` }}
                />
                <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                  {buckets.map((_, i) => (
                    <Cell key={i} fill={t.chartBar} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Isoboxes */}
      <div>
        <SectionLabel label="Isoboxes" t={t} />
        {isoboxes.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px 0", color: t.textFaint }}>
            <div style={{ fontSize: 13, marginBottom: 6 }}>No active isoboxes</div>
            <div style={{ fontSize: 11 }}>
              Run <span style={{ color: t.accent }}>isobox run -- &lt;cmd&gt;</span> to start one
            </div>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12 }}>
            {isoboxes.map((box) => (
              <IsoboxCard key={box.id} box={box} />
            ))}
          </div>
        )}
      </div>

      {/* Critical alerts */}
      {critAlerts.length > 0 && (
        <div>
          <SectionLabel label="Critical Alerts" t={t} />
          <Card style={{ border: `1px solid ${t.red}35` }}>
            <div style={{ padding: "0 16px" }}>
              {critAlerts.map((a, i) => (
                <div key={a.id} style={{
                  padding: "12px 0",
                  borderBottom: i < critAlerts.length - 1 ? `1px solid ${t.border}` : "none",
                }}>
                  <div style={{ color: t.text, fontSize: 12, fontWeight: 600, marginBottom: 3 }}>{a.title}</div>
                  <div style={{ color: t.textFaint, fontSize: 11 }}>{a.isobox_id} · {a.detail}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
