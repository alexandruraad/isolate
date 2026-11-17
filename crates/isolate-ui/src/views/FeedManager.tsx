import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { RefreshCw, Check, AlertTriangle } from "lucide-react";
import { useTheme } from "../lib/theme";

interface FeedEntry {
  name: string;
  url: string;
  enabled: boolean;
  ioc_count: number;
  last_updated: string | null;
  status: string;
}

export default function FeedManager() {
  const [feeds, setFeeds] = useState<FeedEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const t = useTheme();

  const load = async () => {
    try {
      const data = await invoke<{ feeds: FeedEntry[] }>("list_feeds");
      setFeeds(data.feeds ?? []);
    } catch {
      setFeeds([]);
    } finally {
      setLoading(false);
    }
  };

  const update = async () => {
    setUpdating(true);
    try {
      await invoke("update_feeds");
      await load();
    } finally {
      setUpdating(false);
    }
  };

  useEffect(() => { load(); }, []);

  const totalIocs = feeds.reduce((a, f) => a + f.ioc_count, 0);

  const cardTop = (
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${t.accent}30, transparent)` }} />
  );

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20, overflowY: "auto" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <div>
          <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 3 }}>
            // threat feeds
          </div>
          <div style={{ color: t.textFaint, fontSize: 11 }}>
            {totalIocs.toLocaleString()} IOCs loaded · {feeds.length} feeds
          </div>
        </div>
        <button
          onClick={update}
          disabled={updating}
          style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "6px 14px", fontSize: 11, fontWeight: 600,
            letterSpacing: "0.08em", textTransform: "uppercase",
            color: t.accent, background: t.bgAccentFaint,
            border: `1px solid ${t.borderAccent}`,
            cursor: updating ? "not-allowed" : "pointer",
            opacity: updating ? 0.6 : 1,
          }}
        >
          <RefreshCw size={13} style={{ animation: updating ? "spin 1s linear infinite" : "none" }} />
          {updating ? "Updating…" : "Refresh All"}
        </button>
      </div>

      {/* Feed list */}
      {loading ? (
        <div style={{ color: t.textFaint, fontSize: 12 }}>Loading feeds…</div>
      ) : feeds.length === 0 ? (
        <div style={{ textAlign: "center", padding: "48px 0", color: t.textFaint }}>
          <div style={{ fontSize: 13, marginBottom: 4 }}>No feeds configured</div>
          <div style={{ fontSize: 11 }}>Add feeds in <span style={{ color: t.accent }}>isobox.toml</span></div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>

          {/* Table header */}
          <div style={{
            display: "grid", gridTemplateColumns: "1fr 80px 140px",
            gap: 12, padding: "6px 16px",
            borderBottom: `1px solid ${t.border}`,
            fontSize: 9, fontWeight: 700, letterSpacing: "0.15em",
            textTransform: "uppercase", color: t.textFaint,
          }}>
            <span>Feed</span>
            <span style={{ textAlign: "right" }}>IOCs</span>
            <span style={{ textAlign: "right" }}>Last Updated</span>
          </div>

          {feeds.map((feed) => (
            <div key={feed.name} style={{
              background: t.bgCard, border: `1px solid ${t.border}`,
              position: "relative", overflow: "hidden",
            }}>
              {cardTop}
              <div style={{
                display: "grid", gridTemplateColumns: "1fr 80px 140px",
                gap: 12, padding: "12px 16px", alignItems: "center",
              }}>
                {/* Feed name + url */}
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                    {feed.status === "ok"
                      ? <Check size={11} style={{ color: t.green }} />
                      : <AlertTriangle size={11} style={{ color: t.yellow }} />}
                    <span style={{ color: t.text, fontSize: 13, fontWeight: 700 }}>{feed.name}</span>
                  </div>
                  <div style={{ color: t.textFaint, fontSize: 10, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 340 }}>
                    {feed.url}
                  </div>
                </div>

                {/* IOC count */}
                <div style={{ textAlign: "right" }}>
                  <span style={{ color: t.accent, fontSize: 14, fontWeight: 700 }}>
                    {feed.ioc_count.toLocaleString()}
                  </span>
                </div>

                {/* Last updated */}
                <div style={{ textAlign: "right", fontSize: 11, color: t.textFaint }}>
                  {feed.last_updated
                    ? new Date(feed.last_updated).toLocaleString()
                    : <span style={{ color: t.textFaint, fontStyle: "italic" }}>never</span>}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
