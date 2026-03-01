import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";

const FEATURES = [
  { icon: "🔍", title: "Reconnaissance", desc: "Crawls pages, maps forms, detects technology stack" },
  { icon: "⚡", title: "Active Exploitation", desc: "Tests SQLi, XSS, file exposure with real payloads" },
  { icon: "🛡️", title: "Human Oversight", desc: "Every attack requires explicit human approval" },
  { icon: "📊", title: "Detailed Report", desc: "PoC evidence, CVSS scoring, remediation steps" },
];

export function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) {
        const body = await res.json() as { error?: string };
        throw new Error(body.error ?? "Failed to start scan");
      }
      const { scanId } = await res.json() as { scanId: string };
      navigate(`/scan/${scanId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", display: "flex", flexDirection: "column" }}>
      {/* Nav */}
      <nav style={{
        padding: "1rem 2rem",
        borderBottom: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "rgba(13,24,41,0.8)",
        backdropFilter: "blur(12px)",
        position: "sticky",
        top: 0,
        zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: "#3b82f6",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "1rem",
          }}>🔐</div>
          <span style={{ fontWeight: 700, fontSize: "1rem", color: "var(--text-primary)" }}>AgenticVAPT</span>
          <span style={{
            background: "rgba(59,130,246,0.15)", color: "var(--primary)",
            padding: "2px 8px", borderRadius: 20, fontSize: "0.7rem", fontWeight: 600,
            border: "1px solid rgba(59,130,246,0.3)",
          }}>BETA</span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{
            width: 8, height: 8, borderRadius: "50%", background: "var(--success)",
            boxShadow: "0 0 6px var(--success)",
          }} />
          <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Codex Connected</span>
        </div>
      </nav>

      {/* Hero */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "4rem 1.5rem" }}>
        {/* Badge */}
        <div style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.25)",
          borderRadius: 20, padding: "4px 14px", fontSize: "0.78rem", color: "var(--primary)",
          fontWeight: 500, marginBottom: "1.5rem",
          animation: "fade-in 0.4s ease both",
        }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--primary)", display: "inline-block" }} />
          Powered by OpenAI Codex SDK · MCP Tools · Human-in-the-Loop
        </div>

        {/* Title */}
        <h1 style={{
          fontSize: "clamp(2.2rem, 5vw, 3.5rem)",
          fontWeight: 800,
          textAlign: "center",
          lineHeight: 1.15,
          marginBottom: "1rem",
          animation: "fade-in 0.5s ease 0.1s both",
          color: "#f1f5f9",
        }}>
          Agentic Vulnerability<br />Assessment & Pen Testing
        </h1>

        <p style={{
          color: "var(--text-secondary)", fontSize: "1.05rem", textAlign: "center",
          maxWidth: 520, lineHeight: 1.7, marginBottom: "3rem",
          animation: "fade-in 0.5s ease 0.2s both",
        }}>
          An AI security agent that crawls, scans, and exploits vulnerabilities — with human approval at every critical step.
        </p>

        {/* Form card */}
        <div style={{
          width: "100%", maxWidth: 520,
          background: "var(--card)",
          border: "1px solid var(--border)",
          borderRadius: 16,
          padding: "2rem",
          animation: "slide-up 0.5s ease 0.3s both",
          boxShadow: "0 0 60px rgba(59,130,246,0.07), 0 20px 40px rgba(0,0,0,0.4)",
        }}>
          <form onSubmit={handleSubmit}>
            <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>
              Target URL
            </label>
            <div style={{ position: "relative", marginBottom: "0.75rem" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)",
                color: "var(--text-dim)", fontSize: "1rem",
              }}>🌐</span>
              <input
                type="url"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://your-website.com"
                style={{
                  width: "100%",
                  padding: "0.8rem 1rem 0.8rem 2.8rem",
                  background: "var(--surface)",
                  border: `1px solid ${error ? "var(--danger)" : "var(--border-light)"}`,
                  borderRadius: 10,
                  color: "var(--text-primary)",
                  fontSize: "0.95rem",
                  outline: "none",
                  fontFamily: "var(--mono)",
                  transition: "border-color 0.2s",
                }}
                onFocus={(e) => (e.target.style.borderColor = "var(--primary)")}
                onBlur={(e) => (e.target.style.borderColor = error ? "var(--danger)" : "var(--border-light)")}
              />
            </div>

            <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginBottom: "1.5rem", display: "flex", alignItems: "center", gap: 5 }}>
              <span>⚠️</span> Only scan websites you own or have explicit written permission to test.
            </p>

            {error && (
              <div style={{
                background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
                color: "#fca5a5", padding: "0.7rem 1rem", borderRadius: 8,
                fontSize: "0.85rem", marginBottom: "1rem", display: "flex", gap: 8,
              }}>
                <span>✕</span> {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: "100%",
                padding: "0.85rem",
                background: loading ? "var(--border)" : "#2563eb",
                color: loading ? "var(--text-dim)" : "white",
                border: "none",
                borderRadius: 10,
                fontSize: "0.95rem",
                fontWeight: 700,
                cursor: loading ? "not-allowed" : "pointer",
                transition: "all 0.2s",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 8,
                fontFamily: "var(--font)",
                letterSpacing: "0.02em",
              }}
            >
              {loading ? (
                <>
                  <span style={{ width: 16, height: 16, border: "2px solid #64748b", borderTopColor: "white", borderRadius: "50%", animation: "spin 0.8s linear infinite", display: "inline-block" }} />
                  Initializing scan...
                </>
              ) : (
                <>Launch Security Scan →</>
              )}
            </button>
          </form>
        </div>

        {/* Feature grid */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "1rem",
          width: "100%",
          maxWidth: 900,
          marginTop: "3rem",
          animation: "fade-in 0.5s ease 0.5s both",
        }}>
          {FEATURES.map((f) => (
            <div key={f.title} style={{
              background: "var(--card)",
              border: "1px solid var(--border)",
              borderRadius: 12,
              padding: "1.2rem",
              transition: "border-color 0.2s",
            }}>
              <div style={{ fontSize: "1.4rem", marginBottom: 8 }}>{f.icon}</div>
              <div style={{ fontWeight: 600, fontSize: "0.9rem", marginBottom: 4, color: "var(--text-primary)" }}>{f.title}</div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "1.5rem", borderTop: "1px solid var(--border)", color: "var(--text-dim)", fontSize: "0.75rem" }}>
        Built on OpenAI Codex SDK · MCP Security Tools · Human-in-the-Loop VAPT
      </div>
    </div>
  );
}
