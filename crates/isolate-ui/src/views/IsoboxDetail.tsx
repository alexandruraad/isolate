import { useParams, useNavigate } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import { Snowflake, Trash2, Camera, Shield, ArrowLeft } from "lucide-react";
import { useIsolateStore } from "../stores/isolateStore";
import { useTheme } from "../lib/theme";

export default function IsoboxDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { isoboxes, events, freezeIsobox, thawIsobox, stopIsobox, snapshotIsobox } = useIsolateStore();
  const t = useTheme();

  const box = isoboxes.find((b) => b.id === id);
  const myEvents = events.filter((e) => e.isobox_id === id).slice(0, 500);

  // Syscall frequency
  const syscallCounts: Record<string, number> = {};
  for (const ev of myEvents) {
    const sc = (ev.body as any)?.syscall?.syscall_name;
    if (sc) syscallCounts[sc] = (syscallCounts[sc] ?? 0) + 1;
  }
  const topSyscalls = Object.entries(syscallCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([name, count]) => ({ name, count }));

  // Network connections
  const netMap: Record<string, number> = {};
  for (const ev of myEvents) {
    const net = (ev.body as any)?.network;
    if (net) {
      const key = `${net.dst_addr}:${net.dst_port}`;
      netMap[key] = (netMap[key] ?? 0) + 1;
    }
  }
  const netConns = Object.entries(netMap)
    .map(([key, count]) => {
      const [dst, port] = key.split(":");
      return { dst, port: Number(port), count };
    })
    .sort((a, b) => b.count - a.count);

  const btnStyle = (color: string) => ({
    display: "flex" as const, alignItems: "center" as const, gap: 5,
    padding: "5px 12px", fontSize: 11, fontWeight: 600,
    letterSpacing: "0.06em",
    color, background: `${color}15`, border: `1px solid ${color}35`,
    cursor: "pointer",
  });

  if (!box) {
    return (
      <div style={{ padding: 24, color: t.textFaint }}>
        <button
          onClick={() => navigate(-1)}
          style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: t.textFaint, background: "none", border: "none", cursor: "pointer", marginBottom: 16 }}
        >
          <ArrowLeft size={14} /> Back
        </button>
        <p>Isobox not found: {id}</p>
      </div>
    );
  }

  const stateColor =
    box.state === "running" ? t.green :
    box.state === "frozen"  ? t.blue  :
    box.state === "error"   ? t.red   : t.textFaint;

  const cardTop = (
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${t.accent}30, transparent)` }} />
  );

  const sectionLabel = (label: string) => (
    <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 12 }}>
      // {label}
    </div>
  );

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20, overflowY: "auto" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
        <button
          onClick={() => navigate(-1)}
          style={{ background: "none", border: "none", color: t.textFaint, cursor: "pointer", marginTop: 2 }}
        >
          <ArrowLeft size={16} />
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 3 }}>
            // isobox
          </div>
          <div style={{ color: t.text, fontSize: 16, fontWeight: 700 }}>{box.name}</div>
          <div style={{ color: t.textFaint, fontSize: 11, marginTop: 2 }}>{box.id} · {box.workload_class}</div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
          {box.state === "running" ? (
            <button onClick={() => freezeIsobox(box.id)} style={btnStyle(t.blue)}>
              <Snowflake size={12} /> Freeze
            </button>
          ) : box.state === "frozen" ? (
            <button onClick={() => thawIsobox(box.id)} style={btnStyle(t.green)}>
              Thaw
            </button>
          ) : null}
          <button onClick={() => navigate(`/isoboxes/${box.id}/policy`)} style={btnStyle(t.textDim)}>
            <Shield size={12} /> Policy
          </button>
          <button onClick={() => snapshotIsobox(box.id, `/tmp/snapshot-${box.id}.zip`)} style={btnStyle(t.textDim)}>
            <Camera size={12} /> Snapshot
          </button>
          <button
            onClick={() => { if (confirm(`Stop "${box.name}"?`)) { stopIsobox(box.id); navigate("/dashboard"); } }}
            style={btnStyle(t.red)}
          >
            <Trash2 size={12} /> Stop
          </button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        {[
          { label: "State",   value: box.state,                              color: stateColor },
          { label: "Anomaly", value: `${Math.round(box.anomaly_score * 100)}%`, color: box.anomaly_score > 0.75 ? t.red : t.green },
          { label: "Events",  value: box.event_count.toLocaleString(),       color: t.text },
          { label: "Alerts",  value: String(box.alert_count),                color: box.alert_count > 0 ? t.yellow : t.text },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background: t.bgCard, border: `1px solid ${t.border}`, padding: "12px 14px", position: "relative", overflow: "hidden" }}>
            {cardTop}
            <div style={{ color: t.textFaint, fontSize: 10, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>{label}</div>
            <div style={{ color, fontSize: 24, fontWeight: 700, textTransform: "capitalize" }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Top syscalls */}
      <div>
        {sectionLabel("top syscalls")}
        <div style={{ background: t.bgCard, border: `1px solid ${t.border}`, padding: 16, position: "relative", overflow: "hidden" }}>
          {cardTop}
          {topSyscalls.length === 0 ? (
            <div style={{ color: t.textFaint, fontSize: 11 }}>No syscall events yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={topSyscalls} layout="vertical" margin={{ top: 0, right: 10, bottom: 0, left: 90 }}>
                <XAxis type="number" tick={{ fontSize: 10, fill: t.chartAxis }} axisLine={false} tickLine={false} />
                <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: t.textDim }} width={90} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: t.tooltipBg, border: `1px solid ${t.tooltipBorder}`, fontSize: 11, color: t.text, fontFamily: "JetBrains Mono, monospace" }} cursor={{ fill: `${t.accent}08` }} />
                <Bar dataKey="count" radius={[0, 2, 2, 0]}>
                  {topSyscalls.map((_, i) => <Cell key={i} fill={t.chartBar} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Network connections */}
      {netConns.length > 0 && (
        <div>
          {sectionLabel("network connections")}
          <div style={{ background: t.bgCard, border: `1px solid ${t.border}`, position: "relative", overflow: "hidden" }}>
            {cardTop}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 80px 80px", gap: 8, padding: "8px 16px", borderBottom: `1px solid ${t.border}`, fontSize: 9, fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", color: t.textFaint }}>
              <span>Destination</span><span>Port</span><span style={{ textAlign: "right" }}>Count</span>
            </div>
            {netConns.slice(0, 20).map((c, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 80px 80px", gap: 8, padding: "8px 16px", borderBottom: i < Math.min(netConns.length, 20) - 1 ? `1px solid ${t.border}` : "none", fontSize: 11 }}>
                <span style={{ color: t.text, fontFamily: "monospace" }}>{c.dst}</span>
                <span style={{ color: t.textFaint }}>{c.port}</span>
                <span style={{ color: t.textDim, textAlign: "right" }}>{c.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent events */}
      <div>
        {sectionLabel("recent events")}
        <div style={{ background: t.bgCard, border: `1px solid ${t.border}`, position: "relative", overflow: "hidden" }}>
          {cardTop}
          <div style={{ maxHeight: 260, overflowY: "auto", padding: "8px 0" }}>
            {myEvents.length === 0 ? (
              <div style={{ padding: "16px", color: t.textFaint, fontSize: 11 }}>No events yet</div>
            ) : myEvents.slice(0, 100).map((ev, i) => (
              <div key={i} style={{ display: "flex", gap: 12, padding: "4px 16px", borderBottom: `1px solid ${t.border}`, fontSize: 11 }}>
                <span style={{ color: t.accent, flexShrink: 0, width: 56, fontSize: 10 }}>{ev.backend}</span>
                <span style={{ color: t.textDim, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {JSON.stringify(ev.body).slice(0, 120)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
