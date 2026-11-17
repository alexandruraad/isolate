import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/tauri";
import { ArrowLeft, Save, RotateCcw } from "lucide-react";
import { useTheme } from "../lib/theme";

export default function PolicyEditor() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const t = useTheme();
  const [policy, setPolicy] = useState<string>("");
  const [reason, setReason] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    invoke<{ toml: string }>("get_policy", { id })
      .then((p) => { setPolicy(p.toml); setLoading(false); })
      .catch((e) => { setPolicy(`# Error loading policy: ${e}`); setLoading(false); });
  }, [id]);

  const save = async () => {
    if (!reason.trim()) { setMsg({ ok: false, text: "Please enter a reason for the change" }); return; }
    setSaving(true);
    try {
      await invoke("apply_policy", { id, patchToml: policy, reason });
      setMsg({ ok: true, text: "Policy applied successfully" });
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 16, height: "100%", boxSizing: "border-box" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button
          onClick={() => navigate(-1)}
          style={{ background: "none", border: "none", color: t.textFaint, cursor: "pointer" }}
        >
          <ArrowLeft size={16} />
        </button>
        <div>
          <div style={{ color: t.accent, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 2 }}>
            // policy editor
          </div>
          <div style={{ color: t.textFaint, fontSize: 11 }}>{id}</div>
        </div>
      </div>

      {/* Status message */}
      {msg && (
        <div style={{
          padding: "8px 12px", fontSize: 12,
          color: msg.ok ? t.green : t.red,
          background: msg.ok ? `${t.green}12` : `${t.red}12`,
          border: `1px solid ${msg.ok ? t.green : t.red}35`,
        }}>
          {msg.text}
        </div>
      )}

      {/* Editor */}
      <textarea
        style={{
          flex: 1,
          background: t.bgInput,
          border: `1px solid ${t.border}`,
          color: t.text,
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 12,
          padding: 16,
          resize: "none",
          outline: "none",
          lineHeight: 1.6,
          caretColor: t.accent,
          minHeight: 300,
        }}
        onFocus={(e) => { e.target.style.borderColor = t.borderAccent; }}
        onBlur={(e) => { e.target.style.borderColor = t.border; }}
        value={loading ? "// Loading policy…" : policy}
        onChange={(e) => setPolicy(e.target.value)}
        disabled={loading}
        spellCheck={false}
      />

      {/* Footer actions */}
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <input
          style={{
            flex: 1,
            background: t.bgInput,
            border: `1px solid ${t.border}`,
            color: t.text,
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
            padding: "8px 12px",
            outline: "none",
            caretColor: t.accent,
          }}
          onFocus={(e) => { e.target.style.borderColor = t.borderAccent; }}
          onBlur={(e) => { e.target.style.borderColor = t.border; }}
          placeholder="Reason for this change (required for audit log)…"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <button
          onClick={save}
          disabled={saving || loading}
          style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "8px 16px", fontSize: 11, fontWeight: 600,
            letterSpacing: "0.08em", textTransform: "uppercase",
            color: t.accent, background: t.bgAccentFaint,
            border: `1px solid ${t.borderAccent}`,
            cursor: saving || loading ? "not-allowed" : "pointer",
            opacity: saving || loading ? 0.6 : 1,
          }}
        >
          <Save size={13} />
          {saving ? "Saving…" : "Apply Policy"}
        </button>
        <button
          onClick={() => { setPolicy(""); setReason(""); setMsg(null); }}
          style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "8px 12px", fontSize: 11,
            color: t.textFaint, background: `${t.textFaint}10`,
            border: `1px solid ${t.border}`,
            cursor: "pointer",
          }}
        >
          <RotateCcw size={13} />
        </button>
      </div>
    </div>
  );
}
