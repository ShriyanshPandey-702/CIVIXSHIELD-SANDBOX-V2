"use client";

import { useState, useEffect } from "react";

const SCAN_STEPS = [
  "Initializing sandbox...",
  "Rendering environment...",
  "Analyzing threats...",
  "Finalizing report...",
];

type Analysis = {
  riskScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH";
  reasons: string[];
  explanation: string;
  isBlocked?: boolean;
  isTrustedBrand?: boolean;
};

export default function SandboxPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [screenshot, setScreenshot] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [reported, setReported] = useState(false);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (loading) {
      setLoadingStep(0);
      interval = setInterval(() => {
        setLoadingStep((s) => (s + 1) % SCAN_STEPS.length);
      }, 2500);
    }
    return () => clearInterval(interval);
  }, [loading]);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setScreenshot(null);
    setError(null);
    setWarning(null);
    setAnalysis(null);
    setReported(false);

    let submitUrl = url.trim();
    if (!submitUrl.startsWith("http://") && !submitUrl.startsWith("https://")) {
      submitUrl = "https://" + submitUrl;
    }

    try {
      const res = await fetch("/api/sandbox", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: submitUrl }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "An error occurred while scanning.");
      } else {
        if (data.screenshot) setScreenshot(data.screenshot);
        if (data.analysis) setAnalysis(data.analysis);
        if (data.analysis?.isBlocked || data.warning) {
          setWarning("Site blocked sandbox or prevented secure analysis");
        }
      }
    } catch {
      setError("Network error — could not reach the API.");
    } finally {
      setLoading(false);
    }
  }

  const riskColor = (level: string) => {
    if (level === "HIGH") return "#ff2d55";
    if (level === "MEDIUM") return "#ffc300";
    return "#00e5ff";
  };

  const riskGlow = (level: string) => {
    if (level === "HIGH") return "0 0 20px #ff2d5588, 0 0 40px #ff2d5544";
    if (level === "MEDIUM") return "0 0 20px #ffc30088, 0 0 40px #ffc30044";
    return "0 0 20px #00e5ff44";
  };

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
          background: #0a0a0a;
          color: #e0e0e0;
          font-family: 'Rajdhani', sans-serif;
        }

        .scan-btn {
          padding: 14px 32px;
          border-radius: 6px;
          border: 1px solid #ff2d55;
          background: linear-gradient(135deg, #ff2d55cc, #c0003a);
          color: #fff;
          font-size: 16px;
          font-weight: 700;
          letter-spacing: 1px;
          cursor: pointer;
          transition: box-shadow 0.3s;
          white-space: nowrap;
        }
        .scan-btn:hover:not(:disabled) {
          box-shadow: 0 0 18px #ff2d55aa;
        }
        .scan-btn:disabled { opacity: 0.45; cursor: not-allowed; }

        .report-btn {
          padding: 11px 24px;
          border-radius: 6px;
          border: 1px solid #ff2d55;
          background: transparent;
          color: #ff2d55;
          font-size: 15px;
          font-weight: 700;
          letter-spacing: 1px;
          cursor: pointer;
          transition: all 0.25s;
        }
        .report-btn:hover {
          background: #ff2d5522;
          box-shadow: 0 0 12px #ff2d5566;
        }

        @keyframes pulse-glow {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
        .pulse { animation: pulse-glow 1.8s ease-in-out infinite; }

        @keyframes meter-fill {
          from { width: 0%; }
        }
        .meter-bar { animation: meter-fill 0.8s cubic-bezier(0.22,1,0.36,1) forwards; }
      `}</style>

      <div style={{
        minHeight: "100vh",
        background: "#0a0a0a",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        padding: "60px 20px 100px",
      }}>
        {/* ── HEADER ─────────────────────────────────────────────── */}
        <div style={{ textAlign: "center", marginBottom: "48px" }}>
          <div style={{
            fontFamily: "'Share Tech Mono', monospace",
            color: "#00e5ff",
            fontSize: "12px",
            letterSpacing: "4px",
            marginBottom: "10px",
            textTransform: "uppercase",
          }}>
            INTELLIGENT SECURITY SANDBOX
          </div>
          <h1 style={{
            fontFamily: "'Rajdhani', sans-serif",
            fontSize: "clamp(2rem, 6vw, 3.6rem)",
            fontWeight: 700,
            letterSpacing: "3px",
            color: "#fff",
            textShadow: "0 0 30px #00e5ff44",
            lineHeight: 1.1,
          }}>
            CIVIXSHIELD<span style={{ color: "#ff2d55" }}>-SANDBOX</span>
          </h1>
          <p style={{ color: "#666", marginTop: "12px", fontSize: "15px", letterSpacing: "1px" }}>
            Paste any URL. We analyse it safely in an isolated browser.
          </p>
        </div>

        {/* ── MAIN CARD ────────────────────────────────────────────── */}
        <div style={{
          width: "100%",
          maxWidth: "860px",
          display: "flex",
          flexDirection: "column",
          gap: "24px",
        }}>
          {/* URL Form */}
          <form onSubmit={handleScan} style={{ display: "flex", gap: "12px", width: "100%" }}>
            <input
              type="text"
              placeholder="https://suspicious-site.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              autoComplete="off"
              required
              style={{
                flex: 1,
                padding: "14px 18px",
                borderRadius: "6px",
                border: "1px solid #1e1e2a",
                background: "#111118",
                color: "#e0e0e0",
                fontSize: "16px",
                fontFamily: "'Share Tech Mono', monospace",
                outline: "none",
                transition: "border-color 0.2s",
              }}
              onFocus={(e) => (e.target.style.borderColor = "#00e5ff66")}
              onBlur={(e) => (e.target.style.borderColor = "#1e1e2a")}
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="scan-btn"
            >
              {loading ? "SCANNING..." : "SCAN LINK"}
            </button>
          </form>

          {/* Scanning Steps */}
          {loading && (
            <div style={{
              background: "#111118",
              border: "1px solid #1e1e2a",
              borderRadius: "8px",
              padding: "20px 24px",
              display: "flex",
              flexDirection: "column",
              gap: "10px",
            }}>
              {SCAN_STEPS.map((step, i) => (
                <div key={i} style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  opacity: i <= loadingStep ? 1 : 0.25,
                  transition: "opacity 0.4s",
                }}>
                  <div style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: i < loadingStep ? "#00e5ff" : i === loadingStep ? "#ffc300" : "#333",
                    boxShadow: i === loadingStep ? "0 0 8px #ffc300" : "none",
                    flexShrink: 0,
                  }} className={i === loadingStep ? "pulse" : ""} />
                  <span style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: "13px",
                    color: i < loadingStep ? "#00e5ff" : i === loadingStep ? "#ffc300" : "#555",
                  }}>
                    {step}
                  </span>
                  {i < loadingStep && (
                    <span style={{ marginLeft: "auto", color: "#00e5ff", fontSize: "12px" }}>✓</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Error */}
          {error && (
            <div style={{
              padding: "16px 20px",
              background: "#1a0810",
              border: "1px solid #ff2d5566",
              borderRadius: "8px",
              color: "#ff6b87",
              fontSize: "14px",
              fontFamily: "'Share Tech Mono', monospace",
            }}>
              ✗ {error}
            </div>
          )}

          {/* Warning Banner */}
          {warning && (
            <div style={{
              padding: "16px 20px",
              background: "#1a1500",
              border: "1px solid #ffc30066",
              borderRadius: "8px",
              color: "#ffc300",
              fontSize: "14px",
              fontWeight: 600,
              letterSpacing: "0.5px",
            }}>
              ⚠ {warning}
            </div>
          )}

          {/* HIGH RISK auto-alert */}
          {analysis?.riskLevel === "HIGH" && (
            <div style={{
              padding: "18px 20px",
              background: "#1a0810",
              border: "1px solid #ff2d55",
              borderRadius: "8px",
              color: "#ff2d55",
              fontSize: "15px",
              fontWeight: 700,
              letterSpacing: "0.5px",
              boxShadow: "0 0 20px #ff2d5533",
            }}>
              🚨 This site should be reported immediately
            </div>
          )}

          {/* Analysis Card */}
          {analysis && (
            <div style={{
              background: "#0e0e16",
              border: `1px solid ${riskColor(analysis.riskLevel)}44`,
              borderLeft: `4px solid ${riskColor(analysis.riskLevel)}`,
              borderRadius: "10px",
              padding: "24px",
              display: "flex",
              flexDirection: "column",
              gap: "16px",
              boxShadow: riskGlow(analysis.riskLevel),
            }}>
              {/* Risk Level Header */}
              <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
                <div style={{
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: "11px",
                  color: "#555",
                  letterSpacing: "3px",
                  textTransform: "uppercase",
                }}>RISK LEVEL</div>
                <div style={{
                  padding: "4px 16px",
                  borderRadius: "4px",
                  background: `${riskColor(analysis.riskLevel)}22`,
                  border: `1px solid ${riskColor(analysis.riskLevel)}66`,
                  color: riskColor(analysis.riskLevel),
                  fontWeight: 700,
                  fontSize: "18px",
                  letterSpacing: "3px",
                  fontFamily: "'Rajdhani', sans-serif",
                }}>
                  {analysis.riskLevel}
                </div>
                {analysis.isTrustedBrand && (
                  <div style={{
                    padding: "4px 14px",
                    borderRadius: "4px",
                    background: "#00e5ff11",
                    border: "1px solid #00e5ff44",
                    color: "#00e5ff",
                    fontSize: "12px",
                    fontFamily: "'Share Tech Mono', monospace",
                  }}>✓ TRUSTED BRAND</div>
                )}
              </div>

              {/* Risk Meter */}
              <div>
                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "8px",
                }}>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#555" }}>THREAT SCORE</span>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "13px", color: riskColor(analysis.riskLevel) }}>
                    {analysis.riskScore}/100
                  </span>
                </div>
                <div style={{
                  width: "100%",
                  height: "8px",
                  background: "#1e1e2a",
                  borderRadius: "4px",
                  overflow: "hidden",
                }}>
                  <div
                    className="meter-bar"
                    style={{
                      height: "100%",
                      width: `${Math.min(100, analysis.riskScore)}%`,
                      background: `linear-gradient(90deg, ${riskColor(analysis.riskLevel)}88, ${riskColor(analysis.riskLevel)})`,
                      borderRadius: "4px",
                      boxShadow: `0 0 8px ${riskColor(analysis.riskLevel)}`,
                    }}
                  />
                </div>
              </div>

              {/* Explanation */}
              {analysis.explanation && (
                <p style={{
                  color: "#b0b0b0",
                  fontSize: "15px",
                  lineHeight: "1.6",
                  borderTop: "1px solid #1e1e2a",
                  paddingTop: "14px",
                }}>
                  {analysis.explanation}
                </p>
              )}

              {/* Reasons */}
              {analysis.reasons.length > 0 && (
                <div>
                  <div style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: "11px",
                    color: "#555",
                    letterSpacing: "3px",
                    textTransform: "uppercase",
                    marginBottom: "10px",
                  }}>DETECTION FLAGS</div>
                  <ul style={{ paddingLeft: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: "8px" }}>
                    {analysis.reasons.map((reason, i) => (
                      <li key={i} style={{
                        display: "flex",
                        gap: "10px",
                        alignItems: "flex-start",
                        color: "#c0c0c0",
                        fontSize: "14px",
                        lineHeight: "1.4",
                      }}>
                        <span style={{ color: riskColor(analysis.riskLevel), flexShrink: 0, marginTop: "1px" }}>›</span>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Screenshot */}
          {screenshot && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: "11px",
                color: "#555",
                letterSpacing: "3px",
              }}>SANDBOX CAPTURE</div>
              {analysis?.isBlocked && (
                <div style={{
                  fontStyle: "italic",
                  color: "#ffc300",
                  fontSize: "13px",
                  fontFamily: "'Share Tech Mono', monospace",
                }}>
                  ⚠ Content could not be fully loaded due to security restrictions
                </div>
              )}
              <img
                src={`data:image/png;base64,${screenshot}`}
                alt="Scanned website screenshot"
                style={{
                  width: "100%",
                  borderRadius: "8px",
                  border: `2px solid ${analysis ? riskColor(analysis.riskLevel) + "66" : "#1e1e2a"}`,
                  boxShadow: analysis ? riskGlow(analysis.riskLevel) : "none",
                  display: "block",
                }}
              />
            </div>
          )}

          {/* Report Button */}
          {(screenshot || warning) && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "12px", marginTop: "8px" }}>
              {!reported ? (
                <button
                  className="report-btn"
                  onClick={() => setReported(true)}
                >
                  🚨 Report Phishing Site
                </button>
              ) : (
                <div style={{
                  padding: "12px 24px",
                  borderRadius: "6px",
                  background: "#0e200e",
                  border: "1px solid #00e5ff55",
                  color: "#00e5ff",
                  fontSize: "14px",
                  fontFamily: "'Share Tech Mono', monospace",
                }}>
                  ✓ This site has been flagged for further investigation.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
