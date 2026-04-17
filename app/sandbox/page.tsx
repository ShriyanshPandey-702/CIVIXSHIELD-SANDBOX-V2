"use client";

import { useState, useEffect, useRef } from "react";

const SCAN_STEPS = [
  "Checking DNS...",
  "Inspecting forms...",
  "OCR scanning...",
  "Threat intelligence match...",
];

type LogItem = {
  time: string;
  type: "info" | "success" | "warning" | "danger";
  msg: string;
};

type Analysis = {
  riskScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH";
  reasons: string[];
  explanation: string;
  isBlocked?: boolean;
  isTrustedBrand?: boolean;
  isLegitInstitution?: boolean;
  fakeLoginDetected?: boolean;
  loginSignals?: string[];
  credentialRiskScore?: number;
  ocrDetectedText?: string;
  ocrSignals?: string[];
  ocrRiskScore?: number;
  threatCategory?: string;
};

function getConfidence(level: string, score: number): number {
  if (level === "HIGH") return Math.min(95, 80 + Math.floor((score - 60) / 4));
  if (level === "MEDIUM") return Math.min(75, 50 + Math.floor(score / 6));
  return Math.min(95, 80 + Math.floor((30 - score) / 3));
}

function reasonToTag(reason: string): string {
  if (reason.includes("password input")) return "Login Form Detected";
  if (reason.includes("Urgency") || reason.includes("urgency")) return "Urgency Language";
  if (reason.includes("HTTPS")) return "No HTTPS";
  if (reason.includes("Typosquatting") || reason.includes("typosquat")) return "Typosquatting";
  if (reason.includes("impersonat") || reason.includes("Brand")) return "Brand Impersonation";
  if (reason.includes("blocked") || reason.includes("prevented")) return "Sandbox Blocked";
  if (reason.includes("Phishing content")) return "Phishing Phrases Found";
  if (reason.includes("URL path")) return "Suspicious URL";
  if (reason.includes("hyphens")) return "Suspicious Domain";
  if (reason.includes("numbers") || reason.includes("long domain")) return "Odd Domain Pattern";
  if (reason.includes("Email input")) return "Credential Harvesting Form";
  if (reason.includes("external domain")) return "External Form Action";
  if (reason.includes("script")) return "Suspicious Scripts";
  if (reason.includes("trusted brand")) return "Trusted Brand";
  if (reason.includes("hidden fields")) return "Hidden Fields";
  if (reason.includes("Sensitive data")) return "Sensitive Data Keywords";
  if (reason.includes("Suspicious form")) return "Suspicious Form Language";
  return reason.slice(0, 30);
}

function tagColor(tag: string, level: string): { bg: string; border: string; color: string } {
  const safe = ["Trusted Brand"];
  const warn = ["No HTTPS", "Suspicious URL", "Suspicious Domain", "Odd Domain Pattern", "Suspicious Form Language", "Sandbox Blocked"];
  if (safe.includes(tag)) return { bg: "#00e5ff11", border: "#00e5ff55", color: "#00e5ff" };
  if (warn.includes(tag)) return { bg: "#ffc30011", border: "#ffc30055", color: "#ffc300" };
  return { bg: "#ff2d5511", border: "#ff2d5555", color: "#ff2d55" };
}

function CircularScoreMeter({ score, riskLevel }: { score: number, riskLevel: "LOW" | "MEDIUM" | "HIGH" }) {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    const duration = 1500;
    const start = Date.now();
    const animate = () => {
      const now = Date.now();
      const progress = Math.min((now - start) / duration, 1);
      // EaseOutCubic
      const ease = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(Math.floor(ease * score));
      if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }, [score]);

  const getHeatColor = (s: number) => {
    if (s <= 25) return "#00ff66"; // Neon Green
    if (s <= 50) return "#ffc300"; // Yellow
    if (s <= 75) return "#ff9500"; // Orange
    return "#ff2d55"; // Red
  };

  const color = getHeatColor(score);
  const radius = 55;
  const strokeWidth = 8;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (displayScore / 100) * circumference;
  
  const label = riskLevel === "LOW" ? "Trust Score" : "Threat Score";

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "12px", margin: "10px 0 20px" }}>
      <div style={{ position: "relative", width: "130px", height: "130px", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <svg width="130" height="130" viewBox="0 0 130 130" style={{ transform: "rotate(-90deg)", position: "absolute", top: 0, left: 0 }}>
          <circle cx="65" cy="65" r={radius} fill="none" stroke="#1e1e2a" strokeWidth={strokeWidth} />
          <circle 
            cx="65" cy="65" r={radius} 
            fill="none" 
            stroke={color} 
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ 
              transition: "stroke-dashoffset 0.1s linear", 
              filter: `drop-shadow(0 0 10px ${color}aa)` 
            }}
          />
        </svg>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", zIndex: 1 }}>
          <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "42px", fontWeight: 700, color: "#fff", lineHeight: 1, textShadow: `0 0 15px ${color}88` }}>{displayScore}</span>
        </div>
      </div>
      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "13px", color: color, letterSpacing: "3px", textTransform: "uppercase", textShadow: `0 0 8px ${color}66` }}>{label}</span>
    </div>
  );
}

export default function SandboxPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [screenshot, setScreenshot] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [reported, setReported] = useState(false);
  const [scanTime, setScanTime] = useState<number | null>(null);
  const [scannedUrl, setScannedUrl] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const scanStartRef = useRef<number>(0);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

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
    const rawUrl = url;
    if (!rawUrl.trim()) return;

    let submitUrl = rawUrl.trim();
    if (!submitUrl.startsWith("http://") && !submitUrl.startsWith("https://")) {
      submitUrl = "https://" + submitUrl;
    }

    setLoading(true);
    setScreenshot(null);
    setError(null);
    setWarning(null);
    setAnalysis(null);
    setReported(false);
    setScanTime(null);
    setScannedUrl(submitUrl);
    setLogs([]);
    scanStartRef.current = Date.now();

    try {
      const res = await fetch("/api/sandbox", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: submitUrl }),
      });

      const data = await res.json();
      const elapsed = (Date.now() - scanStartRef.current) / 1000;
      setScanTime(parseFloat(elapsed.toFixed(1)));

      if (data.logs) {
        setLogs(data.logs);
      }

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

  // Parse domain and protocol from scanned URL
  let displayDomain = "";
  let displayProtocol = "";
  try {
    if (scannedUrl) {
      const parsed = new URL(scannedUrl);
      displayDomain = parsed.hostname.replace(/^www\./, "");
      displayProtocol = parsed.protocol === "https:" ? "HTTPS" : "HTTP";
    }
  } catch {}

  const confidence = analysis ? getConfidence(analysis.riskLevel, analysis.riskScore) : null;

  // Noisy tags that should never appear on a trusted LOW-risk domain
  const SUPPRESSED_FOR_TRUSTED = new Set([
    "Suspicious URL", "Odd Domain Pattern", "No HTTPS", "Credential Harvesting Form",
    "External Form Action", "Suspicious Scripts", "Hidden Fields", "Sensitive Data Keywords",
    "Suspicious Form Language", "Phishing Phrases Found", "Urgency Language",
    "Login Form Detected", "Brand Impersonation", "Typosquatting", "Sandbox Blocked",
  ]);
  const isTrustedLow = !!(analysis?.isTrustedBrand && analysis?.riskLevel === "LOW");

  const rawTags = analysis ? [...new Set(analysis.reasons.map(reasonToTag))] : [];
  const tags = isTrustedLow
    ? rawTags.filter(tag => !SUPPRESSED_FOR_TRUSTED.has(tag))
    : rawTags;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0a0a0a; color: #e0e0e0; font-family: 'Rajdhani', sans-serif; }

        .scan-btn {
          padding: 14px 32px; border-radius: 6px;
          border: 1px solid #ff2d55;
          background: linear-gradient(135deg, #ff2d55cc, #c0003a);
          color: #fff; font-size: 16px; font-weight: 700; letter-spacing: 1px;
          cursor: pointer; transition: box-shadow 0.3s, transform 0.15s; white-space: nowrap;
        }
        .scan-btn:hover:not(:disabled) { box-shadow: 0 0 22px #ff2d55aa; transform: translateY(-1px); }
        .scan-btn:disabled { opacity: 0.45; cursor: not-allowed; }

        .report-btn {
          padding: 11px 24px; border-radius: 6px;
          border: 1px solid #ff2d55; background: transparent;
          color: #ff2d55; font-size: 15px; font-weight: 700; letter-spacing: 1px;
          cursor: pointer; transition: all 0.25s;
        }
        .report-btn:hover { background: #ff2d5522; box-shadow: 0 0 12px #ff2d5566; }

        @keyframes pulse-glow { 0%, 100% { opacity: 1; } 50% { opacity: 0.55; } }
        .pulse { animation: pulse-glow 1.8s ease-in-out infinite; }
        @keyframes fade-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .fade-in { animation: fade-in 0.4s ease forwards; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .blink { animation: blink 1s ease-in-out infinite; }

        @keyframes neon-pulse-high { 
          from { box-shadow: 0 0 10px #ff2d5522, inset 0 0 5px #ff2d5511; border-color: #ff2d5544; } 
          to { box-shadow: 0 0 35px #ff2d55aa, inset 0 0 15px #ff2d5544; border-color: #ff2d55; } 
        }
        @keyframes neon-pulse-medium { 
          from { box-shadow: 0 0 10px #ffc30022, inset 0 0 5px #ffc30011; border-color: #ffc30044; } 
          to { box-shadow: 0 0 35px #ffc300aa, inset 0 0 15px #ffc30044; border-color: #ffc300; } 
        }
        @keyframes neon-pulse-low { 
          from { box-shadow: 0 0 10px #00ff6622, inset 0 0 5px #00ff6611; border-color: #00ff6644; } 
          to { box-shadow: 0 0 35px #00ff66aa, inset 0 0 15px #00ff6644; border-color: #00ff66; } 
        }
      `}</style>

      <div style={{ minHeight: "100vh", background: "#0a0a0a", display: "flex", flexDirection: "column", alignItems: "center", padding: "60px 20px 100px" }}>

        {/* ── HEADER ─────────────────────────────────────────────────────────── */}
        <div style={{ textAlign: "center", marginBottom: "48px" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", color: "#00e5ff", fontSize: "11px", letterSpacing: "5px", marginBottom: "10px", textTransform: "uppercase" }}>
            INTELLIGENT SECURITY SANDBOX
          </div>
          <h1 style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "clamp(2rem, 6vw, 3.6rem)", fontWeight: 700, letterSpacing: "3px", color: "#fff", textShadow: "0 0 30px #00e5ff44", lineHeight: 1.1 }}>
            CIVIXSHIELD<span style={{ color: "#ffc300" }}>-SANDBOX</span>
          </h1>
          <p style={{ color: "#555", marginTop: "12px", fontSize: "14px", letterSpacing: "1px" }}>
            Paste any URL. We analyse it safely in an isolated browser.
          </p>
        </div>

        <div style={{ width: "100%", maxWidth: "860px", display: "flex", flexDirection: "column", gap: "20px" }}>

          {/* ── URL FORM ───────────────────────────────────────────────────────── */}
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
                flex: 1, padding: "14px 18px", borderRadius: "6px",
                border: "1px solid #1e1e2a", background: "#111118",
                color: "#e0e0e0", fontSize: "15px", fontFamily: "'Share Tech Mono', monospace",
                outline: "none", transition: "border-color 0.2s",
              }}
              onFocus={(e) => (e.target.style.borderColor = "#00e5ff55")}
              onBlur={(e) => (e.target.style.borderColor = "#1e1e2a")}
            />
            <button type="submit" disabled={loading || !url.trim()} className="scan-btn">
              {loading ? "SCANNING..." : "SCAN LINK"}
            </button>
          </form>

          {/* ── SCANNING STEPS ─────────────────────────────────────────────────── */}
          {loading && (
            <div style={{ background: "#111118", border: "1px solid #1e1e2a", borderRadius: "8px", padding: "20px 24px", display: "flex", flexDirection: "column", gap: "10px" }}>
              {SCAN_STEPS.map((step, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: "12px", opacity: i <= loadingStep ? 1 : 0.2, transition: "opacity 0.4s" }}>
                  <div style={{
                    width: "8px", height: "8px", borderRadius: "50%", flexShrink: 0,
                    background: i < loadingStep ? "#00e5ff" : i === loadingStep ? "#ffc300" : "#333",
                    boxShadow: i === loadingStep ? "0 0 8px #ffc300" : "none",
                  }} className={i === loadingStep ? "pulse" : ""} />
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "13px", color: i < loadingStep ? "#00e5ff" : i === loadingStep ? "#ffc300" : "#444" }}>
                    {step}
                  </span>
                  {i < loadingStep && <span style={{ marginLeft: "auto", color: "#00e5ff", fontSize: "11px" }}>✓ DONE</span>}
                </div>
              ))}
            </div>
          )}

          {/* ── ERROR ──────────────────────────────────────────────────────────── */}
          {error && (
            <div className="fade-in" style={{ padding: "16px 20px", background: "#1a0810", border: "1px solid #ff2d5566", borderRadius: "8px", color: "#ff6b87", fontSize: "14px", fontFamily: "'Share Tech Mono', monospace" }}>
              ✗ {error}
            </div>
          )}

          {/* ── WARNING BANNER ─────────────────────────────────────────────────── */}
          {warning && (
            <div className="fade-in" style={{ padding: "16px 20px", background: "#1a1500", border: "1px solid #ffc30066", borderRadius: "8px", color: "#ffc300", fontSize: "14px", fontWeight: 600, letterSpacing: "0.5px" }}>
              ⚠ {warning}
            </div>
          )}

          {/* ── HIGH RISK ALERT BANNER ─────────────────────────────────────────── */}
          {analysis?.riskLevel === "HIGH" && analysis.riskScore > 50 && !analysis.isTrustedBrand && (
            <div className="fade-in blink" style={{
              padding: "20px 24px", background: "#1a0810",
              border: "2px solid #ff2d55", borderRadius: "8px",
              color: "#ff2d55", fontSize: "18px", fontWeight: 700,
              letterSpacing: "0.5px", textAlign: "center",
              boxShadow: "0 0 30px #ff2d5544, inset 0 0 20px #ff2d5511",
            }}>
              🚨 WARNING: This is likely a phishing website. Do NOT enter credentials.
            </div>
          )}

          {/* ── SCAN TIME ──────────────────────────────────────────────────────── */}
          {scanTime !== null && !loading && (
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "12px", color: "#444", textAlign: "right", letterSpacing: "1px" }}>
              ⏱ Scan completed in {scanTime}s
            </div>
          )}

          {/* ── DOMAIN INFO PANEL ──────────────────────────────────────────────── */}
          {analysis && displayDomain && (
            <div className="fade-in" style={{
              display: "flex", gap: "24px", flexWrap: "wrap",
              padding: "14px 20px", background: "#0e0e16",
              border: "1px solid #1e1e2a", borderRadius: "8px",
            }}>
              {[
                ["DOMAIN", displayDomain],
                ["PROTOCOL", displayProtocol],
                ["RISK LEVEL", analysis.riskLevel],
              ].map(([label, val]) => (
                <div key={label} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#444", letterSpacing: "2px" }}>{label}</span>
                  <span style={{
                    fontFamily: "'Rajdhani', sans-serif", fontSize: "16px", fontWeight: 700,
                    color: label === "RISK LEVEL" ? riskColor(val) : "#e0e0e0",
                  }}>{val}</span>
                </div>
              ))}
            </div>
          )}

          {/* ── ANALYSIS CARD ──────────────────────────────────────────────────── */}
          {analysis && (
            <div className="fade-in" style={{
              background: "#0e0e16", border: `1px solid ${riskColor(analysis.riskLevel)}44`,
              borderRadius: "10px", padding: "30px 24px",
              display: "flex", flexDirection: "column", gap: "18px",
              animation: `neon-pulse-${analysis.riskLevel.toLowerCase()} 2s infinite alternate ease-in-out`,
            }}>
              {/* Risk Header */}
              <div style={{ display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#444", letterSpacing: "3px" }}>RISK LEVEL</div>
                <div style={{ padding: "4px 16px", borderRadius: "4px", background: `${riskColor(analysis.riskLevel)}22`, border: `1px solid ${riskColor(analysis.riskLevel)}66`, color: riskColor(analysis.riskLevel), fontWeight: 700, fontSize: "18px", letterSpacing: "3px" }}>
                  {analysis.riskLevel}
                </div>
                {analysis.isTrustedBrand && (
                  <div style={{ padding: "4px 14px", borderRadius: "4px", background: "#00e5ff11", border: "1px solid #00e5ff44", color: "#00e5ff", fontSize: "11px", fontFamily: "'Share Tech Mono', monospace" }}>
                    ✓ {analysis.loginSignals && analysis.loginSignals.length > 0 ? "Trusted Official Login Page" : "Trusted Brand"}
                  </div>
                )}
                {analysis.isLegitInstitution && !analysis.isTrustedBrand && (
                  <div style={{ padding: "4px 14px", borderRadius: "4px", background: "#00ff9911", border: "1px solid #00ff9944", color: "#00ff99", fontSize: "11px", fontFamily: "'Share Tech Mono', monospace" }}>
                    🏛 Institutional Site
                  </div>
                )}
                {analysis.fakeLoginDetected && (
                  <div style={{
                    padding: "4px 14px", borderRadius: "4px",
                    background: "#ff2d5522", border: "1px solid #ff2d5588",
                    color: "#ff2d55", fontSize: "11px",
                    fontFamily: "'Share Tech Mono', monospace",
                    fontWeight: 700,
                  }}>⚠ Credential Harvesting Page Suspected</div>
                )}
                {confidence !== null && (
                  <div style={{ marginLeft: "auto", fontFamily: "'Share Tech Mono', monospace", fontSize: "12px", color: "#555" }}>
                    Confidence: <span style={{ color: riskColor(analysis.riskLevel) }}>{confidence}%</span>
                  </div>
                )}
              </div>

              {/* Animated Circular Score Meter */}
              <div style={{ width: "100%", display: "flex", justifyContent: "center", margin: "10px 0" }}>
                <CircularScoreMeter score={analysis.riskScore} riskLevel={analysis.riskLevel} />
              </div>

              {/* Explanation — rendered as structured lines */}
              {analysis.explanation && (
                <div style={{ borderTop: "1px solid #1e1e2a", paddingTop: "14px" }}>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#444", letterSpacing: "2px", marginBottom: "10px" }}>ANALYSIS SUMMARY</div>
                  
                  {analysis.threatCategory && (
                    <div style={{ 
                      display: "inline-block", 
                      padding: "6px 12px", 
                      background: riskColor(analysis.riskLevel) + "15",
                      border: `1px solid ${riskColor(analysis.riskLevel)}88`,
                      color: riskColor(analysis.riskLevel),
                      borderRadius: "6px",
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: "13px",
                      marginBottom: "14px",
                      textTransform: "uppercase",
                      letterSpacing: "1px"
                    }}>
                      {analysis.riskLevel === "LOW" 
                        ? `🛡️ ${analysis.threatCategory}`
                        : `🚨 THREAT: ${analysis.threatCategory}`
                      }
                    </div>
                  )}

                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {analysis.explanation.split("\n").map((line, i) => {
                      const isBullet = line.startsWith("\u2022");
                      const isEmpty = line.trim() === "";
                      if (isEmpty) return <div key={i} style={{ height: "4px" }} />;
                      return (
                        <p key={i} style={{
                          color: isBullet ? "#b0b0b0" : "#888",
                          fontSize: isBullet ? "14px" : "13px",
                          lineHeight: "1.6",
                          paddingLeft: isBullet ? "4px" : "0",
                          fontStyle: isBullet ? "normal" : "italic",
                        }}>
                          {line}
                        </p>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Risk Tags */}
              {tags.length > 0 && (
                <div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#444", letterSpacing: "2px", marginBottom: "10px" }}>DETECTION FLAGS</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                    {tags.map((tag, i) => {
                      const tc = tagColor(tag, analysis.riskLevel);
                      return (
                        <span key={i} style={{
                          padding: "4px 12px", borderRadius: "4px",
                          background: tc.bg, border: `1px solid ${tc.border}`,
                          color: tc.color, fontSize: "12px",
                          fontFamily: "'Share Tech Mono', monospace",
                          letterSpacing: "0.5px",
                        }}>
                          {tag}
                        </span>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Credential Harvesting Signals */}
              {analysis.fakeLoginDetected && analysis.loginSignals && analysis.loginSignals.length > 0 && (
                <div style={{ borderTop: "1px solid #ff2d5533", paddingTop: "14px" }}>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#ff2d5588", letterSpacing: "2px", marginBottom: "10px" }}>CREDENTIAL HARVESTING SIGNALS</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {analysis.loginSignals.map((signal, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
                        <span style={{ color: "#ff2d55", flexShrink: 0, marginTop: "2px" }}>⚠</span>
                        <span style={{ color: "#b0b0b0", fontSize: "13px", lineHeight: "1.5" }}>{signal}</span>
                      </div>
                    ))}
                  </div>
                  {analysis.credentialRiskScore !== undefined && (
                    <div style={{ marginTop: "10px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#ff2d5566" }}>
                      Credential Risk Sub-Score: <span style={{ color: "#ff2d55" }}>{analysis.credentialRiskScore}/170</span>
                    </div>
                  )}
                </div>
              )}

              {/* OCR Screen Text Alerts */}
              {analysis.ocrSignals && analysis.ocrSignals.length > 0 && (
                <div style={{ borderTop: "1px solid #ffc30033", paddingTop: "14px" }}>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#ffc30088", letterSpacing: "2px", marginBottom: "10px" }}>OCR SCREEN TEXT ALERTS</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "12px" }}>
                    {analysis.ocrSignals.map((phrase, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
                        <span style={{ color: "#ffc300", flexShrink: 0, marginTop: "2px" }}>🔍</span>
                        <span style={{ color: "#b0b0b0", fontSize: "13px", lineHeight: "1.5", textTransform: "capitalize" }}>{phrase}</span>
                      </div>
                    ))}
                  </div>
                  {analysis.ocrDetectedText && (
                    <div style={{
                      background: "#0a0a12", border: "1px solid #ffc30033",
                      borderRadius: "6px", padding: "10px 14px",
                    }}>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#ffc30066", letterSpacing: "2px", marginBottom: "6px" }}>EXTRACTED TEXT PREVIEW</div>
                      <p style={{
                        color: "#666", fontSize: "12px",
                        fontFamily: "'Share Tech Mono', monospace",
                        lineHeight: "1.6", wordBreak: "break-word",
                      }}>{analysis.ocrDetectedText}</p>
                    </div>
                  )}
                  {analysis.ocrRiskScore !== undefined && analysis.ocrRiskScore > 0 && (
                    <div style={{ marginTop: "10px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#ffc30066" }}>
                      OCR Risk Score Added: <span style={{ color: "#ffc300" }}>+{analysis.ocrRiskScore}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── SCREENSHOT ─────────────────────────────────────────────────────── */}
          {screenshot && (
            <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#444", letterSpacing: "3px" }}>SANDBOX CAPTURE</div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#00e5ff88" }}>🛡️ Loaded inside secure sandbox environment</div>
              </div>
              {analysis?.isBlocked && (
                <div style={{ fontStyle: "italic", color: "#ffc300", fontSize: "13px", fontFamily: "'Share Tech Mono', monospace" }}>
                  ⚠ This page could not be fully loaded. Displaying partial or error state.
                </div>
              )}
              <img
                src={`data:image/png;base64,${screenshot}`}
                alt="Scanned website screenshot"
                style={{
                  width: "100%", borderRadius: "8px",
                  border: `2px solid ${analysis ? riskColor(analysis.riskLevel) + "66" : "#1e1e2a"}`,
                  boxShadow: analysis ? riskGlow(analysis.riskLevel) : "none",
                  display: "block",
                }}
              />
            </div>
          )}

          {/* ── REPORT BUTTON — only for MEDIUM / HIGH risk ────────────────────── */}
          {(screenshot || warning) && analysis && (analysis.riskLevel === "HIGH" || analysis.riskLevel === "MEDIUM") && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "12px", marginTop: "8px" }}>
              {!reported ? (
                <button className="report-btn" onClick={() => setReported(true)}>
                  🚨 Report Phishing Site
                </button>
              ) : (
                <div className="fade-in" style={{
                  padding: "14px 24px", borderRadius: "6px",
                  background: "#0e1a0e", border: "1px solid #00e5ff55",
                  color: "#00e5ff", fontSize: "14px",
                  fontFamily: "'Share Tech Mono', monospace",
                }}>
                  ✔️ Site reported successfully. Authorities will review it.
                </div>
              )}
            </div>
          )}

          {/* ── LIVE FORENSIC CONSOLE ────────────────────────────────────────────── */}
          {logs.length > 0 && (
            <div className="fade-in" style={{ marginTop: "30px", background: "#0a0a0f", borderRadius: "10px", border: "1px solid #1e1e2a", overflow: "hidden", boxShadow: "0 10px 40px rgba(0,0,0,0.5)" }}>
              <div style={{ background: "#151520", padding: "12px 16px", borderBottom: "1px solid #1e1e2a", display: "flex", alignItems: "center", gap: "12px" }}>
                <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#ff2d55", boxShadow: "0 0 10px #ff2d55" }}></div>
                <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#ffc300", boxShadow: "0 0 10px #ffc300" }}></div>
                <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#00ff66", boxShadow: "0 0 10px #00ff66" }}></div>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "14px", color: "#00e5ff", letterSpacing: "2px", marginLeft: "10px" }}>LIVE FORENSIC CONSOLE</span>
              </div>
              <div style={{ maxHeight: "350px", overflowY: "auto", padding: "20px", display: "flex", flexDirection: "column", gap: "6px" }}>
                {logs.map((log, i) => (
                  <div key={i} className="fade-in" style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: "13px",
                    lineHeight: "1.5",
                    animationDelay: `${i * 0.15}s`,
                    animationFillMode: "both",
                    display: "flex",
                    gap: "12px",
                  }}>
                    <span style={{ color: "#666", minWidth: "110px", whiteSpace: "nowrap" }}>[{log.time}]</span>
                    <span style={{ 
                      color: log.type === 'success' ? '#00ff66' : log.type === 'warning' ? '#ffc300' : log.type === 'danger' ? '#ff2d55' : '#00e5ff', 
                      minWidth: "75px", textTransform: "uppercase", fontWeight: "bold" 
                    }}>
                      {log.type}
                    </span>
                    <span style={{ color: "#dcdcaa", wordBreak: "break-word" }}>{log.msg}</span>
                  </div>
                ))}
                <div ref={logsEndRef} style={{ height: "10px" }} />
              </div>
            </div>
          )}

        </div>
      </div>
    </>
  );
}
