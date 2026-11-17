import { useIsolateStore } from "../stores/isolateStore";
import { useTheme } from "../lib/theme";
import { AlertTriangle, AlertOctagon, Info, ShieldAlert } from "lucide-react";

const SEVERITY = [
  { label: "INFO",      icon: Info          },
  { label: "WARN",      icon: AlertTriangle },
  { label: "CRITICAL",  icon: ShieldAlert   },
  { label: "EMERGENCY", icon: AlertOctagon  },
];

export default function AlertFeed() {
  const { alerts } = useIsolateStore();
  const t = useTheme();

  const severityColor = (sev: number) => {
    if (sev >= 3) return t.red;
    if (sev >= 2) return t.orange;
    if (sev >= 1) return t.yellow;
    return t.blue;
  };

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20, overflowY: "auto" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
        <div>
          <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 2 }}>
            // alert feed
          </div>
          <div style={{ color: t.textFaint, fontSize: 11 }}>
            {alerts.length} alert{alerts.length !== 1 ? "s" : ""} total
          </div>
        </div>
      </div>

      {/* Table header */}
      {alerts.length > 0 && (
        <div style={{
          display: "grid",
          gridTemplateColumns: "80px 100px 1fr 80px",
          gap: 12,
          padding: "6px 16px",
          borderBottom: `1px solid ${t.border}`,
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: "0.15em",
          textTransform: "uppercase",
          color: t.textFaint,
        }}>
          <span>Severity</span>
          <span>Isobox</span>
          <span>Event</span>
          <span style={{ textAlign: "right" }}>Time</span>
        </div>
      )}

      {/* Alert rows */}
      {alerts.length === 0 ? (
        <div style={{ textAlign: "center", padding: "64px 0", color: t.textFaint }}>
          <ShieldAlert size={36} style={{ margin: "0 auto 12px", opacity: 0.3, display: "block" }} />
          <div style={{ fontSize: 13 }}>No alerts</div>
          <div style={{ fontSize: 11, marginTop: 4 }}>System nominal</div>
        </div>
      ) : (
        <div>
          {alerts.map((alert) => {
            const sev = Math.min(alert.severity, 3);
            const meta = SEVERITY[sev];
            const Icon = meta.icon;
            const color = severityColor(sev);

            return (
              <div key={alert.id} style={{
                display: "grid",
                gridTemplateColumns: "80px 100px 1fr 80px",
                gap: 12,
                padding: "10px 16px",
                borderBottom: `1px solid ${t.border}`,
                borderLeft: `2px solid ${color}60`,
                background: sev >= 2 ? `${color}06` : "transparent",
                alignItems: "center",
              }}>

                {/* Severity */}
                <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <Icon size={11} style={{ color }} />
                  <span style={{ color, fontSize: 10, fontWeight: 700, letterSpacing: "0.06em" }}>
                    {meta.label}
                  </span>
                </div>

                {/* Isobox */}
                <div style={{ fontSize: 11, color: t.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {alert.isobox_id}
                </div>

                {/* Title + detail */}
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: t.text, marginBottom: 2 }}>
                    {alert.title}
                    {alert.paladin_level > 0 && (
                      <span style={{ marginLeft: 8, fontSize: 10, color: t.red, fontWeight: 700 }}>
                        ⚔ PALADIN L{alert.paladin_level}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 11, color: t.textFaint }}>
                    {alert.detail}
                    {alert.action_taken && (
                      <span style={{ marginLeft: 8, color: t.accent }}>→ {alert.action_taken}</span>
                    )}
                  </div>
                </div>

                {/* Time */}
                <div style={{ fontSize: 10, color: t.textFaint, textAlign: "right" }}>
                  {new Date(alert.created_at).toLocaleTimeString()}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
