import { NavLink } from "react-router-dom";
import { LayoutDashboard, ShieldAlert, Rss, Settings } from "lucide-react";
import { useIsolateStore } from "../stores/isolateStore";
import { useTheme } from "../lib/theme";

const NAV = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/alerts",    icon: ShieldAlert,      label: "Alerts" },
  { to: "/feeds",     icon: Rss,              label: "Feeds" },
  { to: "/settings",  icon: Settings,         label: "Settings" },
];

export default function Sidebar() {
  const { connected, isoboxes } = useIsolateStore();
  const t = useTheme();

  const runningCount = isoboxes.filter((b) => b.state === "running").length;

  return (
    <aside style={{
      width: 220,
      flexShrink: 0,
      background: t.bgCard,
      borderRight: `1px solid ${t.border}`,
      display: "flex",
      flexDirection: "column",
    }}>

      {/* Logo */}
      <div style={{ borderBottom: `1px solid ${t.border}`, padding: "14px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            border: `1px solid ${t.accent}`,
            color: t.accent,
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.08em",
            padding: "2px 6px",
          }}>
            ISO
          </div>
          <span style={{
            color: t.text,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.18em",
            textTransform: "uppercase",
          }}>
            Isolate
          </span>
          <span style={{ marginLeft: "auto", color: t.textFaint, fontSize: 10 }}>v0.1</span>
        </div>
      </div>

      {/* Connection status */}
      <div style={{ borderBottom: `1px solid ${t.border}`, padding: "10px 16px" }}>
        <div style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          color: connected ? t.green : t.red,
          background: connected ? `${t.green}18` : `${t.red}18`,
          border: `1px solid ${connected ? t.green : t.red}40`,
          padding: "3px 8px",
        }}>
          <span style={{
            width: 5, height: 5, borderRadius: "50%",
            background: connected ? t.green : t.red,
            boxShadow: `0 0 5px ${connected ? t.green : t.red}`,
            flexShrink: 0,
          }} />
          {connected ? "Isolatd Online" : "Not Connected"}
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, paddingTop: 8 }}>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} style={{ display: "block", textDecoration: "none" }}>
            {({ isActive }) => (
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "9px 16px",
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                color: isActive ? t.accent : t.textFaint,
                background: isActive ? t.bgAccentFaint : "transparent",
                borderLeft: `2px solid ${isActive ? t.accent : "transparent"}`,
                cursor: "pointer",
                transition: "color 0.15s, background 0.15s",
              }}>
                <Icon size={13} />
                {label}
              </div>
            )}
          </NavLink>
        ))}

        {/* Isobox list */}
        {isoboxes.length > 0 && (
          <div style={{ paddingTop: 16 }}>
            <div style={{
              padding: "0 16px 6px",
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              color: t.textFaint,
            }}>
              // isoboxes
            </div>
            {isoboxes.map((box) => (
              <NavLink key={box.id} to={`/isoboxes/${box.id}`} style={{ display: "block", textDecoration: "none" }}>
                {({ isActive }) => (
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "6px 16px",
                    fontSize: 11,
                    color: isActive ? t.text : t.textDim,
                    background: isActive ? t.bgAccentFaint : "transparent",
                    borderLeft: `2px solid ${isActive ? t.accent : "transparent"}`,
                    cursor: "pointer",
                  }}>
                    <span style={{
                      width: 5, height: 5, borderRadius: "50%", flexShrink: 0,
                      background:
                        box.state === "running" ? t.green :
                        box.state === "frozen"  ? t.blue  :
                        box.state === "error"   ? t.red   : t.textFaint,
                    }} />
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {box.name}
                    </span>
                  </div>
                )}
              </NavLink>
            ))}
          </div>
        )}
      </nav>

      {/* Footer */}
      <div style={{
        borderTop: `1px solid ${t.border}`,
        padding: "10px 16px",
        fontSize: 10,
        color: t.textFaint,
        letterSpacing: "0.04em",
      }}>
        {runningCount} running · {isoboxes.length} total
      </div>
    </aside>
  );
}
