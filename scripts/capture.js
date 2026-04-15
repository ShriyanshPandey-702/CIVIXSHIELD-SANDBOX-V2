const { chromium } = require('playwright');
const url = process.argv[2];
const isDev = process.env.NODE_ENV !== 'production';

// ─── SAFE ENV KEY EXTRACTION ──────────────────────────────────────────────
// Keys are ONLY read server-side here. Never exposed to frontend.
function extractApiKey(raw) {
  if (!raw || raw.trim() === "") return null;
  const trimmed = raw.trim();
  // If a full URL was accidentally pasted, extract the key from the query string
  if (trimmed.startsWith("http")) {
    try {
      const keyParam = new URL(trimmed).searchParams.get("key");
      return keyParam || null;
    } catch { return null; }
  }
  return trimmed;
}
const GEMINI_KEY = extractApiKey(process.env.GOOGLE_GENERATIVE_AI_API_KEY);
const SAFE_BROWSING_KEY = extractApiKey(process.env.SAFE_BROWSING_API_KEY);

// Startup diagnostic — printed to stderr (visible in server logs, not in JSON stdout)
console.error(`[CIVIX] STARTUP — Gemini key: ${GEMINI_KEY ? `SET (${GEMINI_KEY.length} chars)` : "NOT SET"} | Safe Browsing key: ${SAFE_BROWSING_KEY ? `SET (${SAFE_BROWSING_KEY.length} chars)` : "NOT SET"}`);

// ─── TRUSTED BRAND WHITELIST ───────────────────────────────────────────────
const TRUSTED_BRANDS = [
  "google", "youtube", "gmail", "facebook", "instagram", "twitter", "x.com",
  "whatsapp", "microsoft", "apple", "amazon", "netflix", "linkedin", "github",
  "stackoverflow", "wikipedia", "reddit", "dropbox", "spotify", "airbnb",
  "uber", "paypal", "stripe", "shopify", "zoom", "slack", "notion", "figma",
  "canva", "adobe", "salesforce", "wordpress", "cloudflare", "vercel",
  "sbi", "hdfc", "icici", "axisbank", "kotak", "npci", "uidai", "gov.in",
  "india.gov", "irctc", "incometax", "mca", "sebi", "rbi"
];

// ─── TYPOSQUATTING PATTERNS ────────────────────────────────────────────────
const TYPOSQUAT_PATTERNS = [
  { real: "google",    fakes: ["g00gle","gooogle","googel","googie"] },
  { real: "amazon",    fakes: ["amaz0n","amazom","arnazon","amozon"] },
  { real: "paypal",    fakes: ["paypa1","paypai","pay-pal","paypeI"] },
  { real: "facebook",  fakes: ["faceb00k","faceboook","facebok"] },
  { real: "microsoft", fakes: ["micros0ft","mircosoft","microsofft"] },
  { real: "apple",     fakes: ["app1e","apple-id","appl3"] },
  { real: "netflix",   fakes: ["netf1ix","netflx","net-flix"] },
  { real: "instagram", fakes: ["instageam","1nstagram","instagramm"] },
  { real: "sbi",       fakes: ["sb1","sbi-bank","sbionline"] },
  { real: "hdfc",      fakes: ["hdfcc","hd-fc","hdfcbank-in"] },
];

// ─── ROOT DOMAIN EXTRACTION ───────────────────────────────────────────────
// Collapses any subdomain to just the registrable root: e.g. login.amazon.in → amazon.in
function getRootDomain(host) {
  const h = host.toLowerCase().replace(/^www\./, "");
  const parts = h.split(".");
  // Handle known two-part TLDs (co.in, co.uk, com.au, etc.)
  const twoPartTLDs = ["co.in", "co.uk", "com.au", "co.nz", "gov.in", "net.in", "org.in"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTLDs.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// Explicit list — root domain must be an EXACT match
const TRUSTED_ROOTS = new Set([
  "google.com", "youtube.com", "gmail.com",
  "facebook.com", "instagram.com", "twitter.com", "x.com",
  "whatsapp.com", "microsoft.com", "apple.com",
  "amazon.com", "amazon.in",
  "flipkart.com",
  "netflix.com", "linkedin.com", "github.com",
  "stackoverflow.com", "wikipedia.org", "reddit.com",
  "dropbox.com", "spotify.com", "zoom.us", "slack.com",
  "notion.so", "figma.com", "canva.com", "adobe.com",
  "cloudflare.com", "vercel.com", "paypal.com", "stripe.com",
  "sbi.co.in", "onlinesbi.sbi",
  "hdfcbank.com", "icicibank.com",
  "indianrailways.gov.in", "irctc.co.in",
  "incometax.gov.in", "uidai.gov.in", "npci.org.in",
]);

(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    });

    const page = await context.newPage();

    // Block heavy resources for speed — images/fonts/media skipped entirely
    await page.route("**/*", (route) => {
      const type = route.request().resourceType();
      if (["image", "font", "media", "websocket", "eventsource"].includes(type)) {
        route.abort();
      } else {
        route.continue();
      }
    });

    let timedOut = false;
    try {
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 6000,  // Fast-fail: heavy sites must respond within 6s
      });
      // Brief settle time for DOM to stabilise after load event
      await page.waitForTimeout(1000);
    } catch (navErr) {
      timedOut = true;
    }

    // Always try to get HTML even after timeout (partial content is better than nothing)
    let htmlContent = "";
    try { htmlContent = await page.content(); } catch (e) {}

    // Inject standardised Chrome-style error page on failure
    if (timedOut || !(await page.content().catch(() => "")).includes("<")) {
      try {
        await page.setContent(`<html style="background:#202124;color:#e8eaed;font-family:Arial,sans-serif"><body style="display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;text-align:center;padding:40px"><div style="font-size:64px;opacity:.5;margin-bottom:24px">⚠</div><h2 style="font-size:28px;font-weight:400;margin-bottom:12px">This site can't be reached</h2><p style="color:#9aa0a6;font-size:16px;margin-bottom:8px">${url.replace(/</g,'&lt;').replace(/>/g,'&gt;')} took too long to respond.</p><p style="color:#5f6368;font-size:14px;margin-top:24px;font-family:monospace">ERR_CONNECTION_TIMED_OUT</p></body></html>`, { waitUntil: "domcontentloaded" });
      } catch(e) {}
    }

    // Capture screenshot — with retry fallback to guarantee output
    let screenshotBuffer;
    try {
      screenshotBuffer = await page.screenshot({
        fullPage: false,
        type: "png",
        timeout: 3000,
        animations: "disabled",
      });
    } catch (ssErr) {
      // Retry once with extra wait
      try {
        await page.waitForTimeout(1000);
        screenshotBuffer = await page.screenshot({ fullPage: false, type: "png" });
      } catch (ssErr2) {
        // Last resort: blank fallback page
        await page.setContent("<html style='background:#202124'><body></body></html>");
        screenshotBuffer = await page.screenshot({ fullPage: false, type: "png" });
      }
    }

    // Stop any remaining JS execution before closing
    try { await page.evaluate(() => window.stop()); } catch(e) {}
    await browser.close();

    // ─── ANALYSIS ENGINE ─────────────────────────────────────────────────────
    let riskScore = 0;
    const reasons = [];
    let hostname = "";
    let isTrustedBrand = false;
    let isTyposquat = false;
    let isBrandMisuse = false;
    let isScamPage = false;

    // ── ROOT-DOMAIN TRUSTED CHECK (runs before ALL heuristics) ────────────────
    // This is the primary false-positive guard for legitimate heavy sites
    // (Amazon, Flipkart, Google, SBI) that would otherwise trip generic signals.
    try {
      const _parsedForRoot = new URL(url);
      const _rawHost = _parsedForRoot.hostname.toLowerCase();
      const rootDomain = getRootDomain(_rawHost);
      if (TRUSTED_ROOTS.has(rootDomain)) {
        isTrustedBrand = true;
        riskScore = 5;
        hostname = _rawHost.replace(/^www\./, "");
        reasons.push("Trusted domain (official source)");
        if (isDev) console.error(`[CIVIX] Trusted root matched: ${rootDomain} → forcing LOW`);
      }
    } catch(e) {}

    try {
      const parsedUrl = new URL(url);
      hostname = parsedUrl.hostname.toLowerCase().replace(/^www\./, "");
      const parts = hostname.split(".");
      // Domain label = everything except the TLD (last part)
      const domainLabel = parts.slice(0, -1).join(".");

      // 1. HTTPS check
      if (parsedUrl.protocol !== "https:") {
        riskScore += 20;
        reasons.push("Not using HTTPS");
      }

      // 2. Too many hyphens
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount > 2) {
        riskScore += 15;
        reasons.push("Domain has excessive hyphens (common in phishing)");
      }

      // 3. Long domain (obfuscation technique)
      if (hostname.length > 25) {
        riskScore += 10;
        reasons.push(`Unusually long domain name (${hostname.length} chars)`);
      }

      // 4. Random numbers in domain
      if (/\d/.test(hostname)) {
        riskScore += 10;
        reasons.push("Domain contains numbers (suspicious pattern)");
      }

      // 5. Suspicious URL path keywords (work on the full URL)
      const urlLower = url.toLowerCase();
      const urlPhishingWords = ["login", "verify", "update", "secure", "account", "password", "signin", "confirm", "recover", "validate"];
      const foundUrlWords = urlPhishingWords.filter(w => urlLower.includes(w));
      if (foundUrlWords.length > 0) {
        riskScore += 20;
        reasons.push(`Suspicious URL path keywords: "${foundUrlWords.slice(0, 3).join('", "')}"`);
      }

      // ── PRIORITY 1: TRUSTED DOMAIN CHECK ────────────────────────────────────
      const knownTLDs = [".com", ".in", ".co.in", ".org", ".net", ".gov.in", ".bank.in", ".co", ".io", ".edu"];
      const matchedTrustedBrand = TRUSTED_BRANDS.find(brand => {
        return knownTLDs.some(tld => {
          const canonical = `${brand}${tld}`;
          return hostname === canonical || hostname.endsWith(`.${canonical}`);
        }) || hostname === brand;
      });

      if (matchedTrustedBrand) {
        isTrustedBrand = true;
        // HARD RESET: wipe all generic domain signal scores accrued before this point
        // (long domain, numbers, URL keywords, hyphens) — they are noise for trusted sites
        riskScore = 0;
        reasons.length = 0;
        reasons.push(`Recognized trusted brand domain: ${matchedTrustedBrand}`);
      } else {
        // ── PRIORITY 2: TYPOSQUATTING — char substitution ────────────────────
        // Normalize chars (0→o, 1→i/l, 3→e, @→a) and compare to brand names
        const normalized = domainLabel
          .replace(/0/g, "o")
          .replace(/1/g, "i")
          .replace(/3/g, "e")
          .replace(/@/g, "a")
          .replace(/\$/g, "s")
          .replace(/5/g, "s")
          .replace(/4/g, "a")
          .split("-")[0]; // Take only the first chunk before hyphens

        const typosquatBrand = TRUSTED_BRANDS.find(brand =>
          normalized.includes(brand) || brand.includes(normalized)
        );

        // Also keep the old fake-list matching as a secondary signal
        const oldFakeMatch = TYPOSQUAT_PATTERNS.find(p =>
          p.fakes.some(fake => hostname.includes(fake))
        );

        if (typosquatBrand || oldFakeMatch) {
          isTyposquat = true;
          riskScore += 60;
          const brandName = typosquatBrand || (oldFakeMatch && oldFakeMatch.real);
          reasons.push(`Typosquatting detected: domain impersonates "${brandName}"`);
        }

        // ── PRIORITY 3: BRAND MISUSE — real name in unofficial domain ────────
        // e.g. amazon-login-secure.net, paypal-verification.xyz
        if (!isTyposquat) {
          const brandInDomain = TRUSTED_BRANDS.find(brand => domainLabel.includes(brand));
          if (brandInDomain) {
            isBrandMisuse = true;
            riskScore += 50;
            reasons.push(`Brand "${brandInDomain}" used in unofficial domain (impersonation)`);
          }
        }
      }
    } catch(e) {}

    // ─── HTML CONTENT ANALYSIS ────────────────────────────────────────────────
    if (htmlContent) {
      const lowerHtml = htmlContent.toLowerCase();

      // Password field — checked for ALL sites (including trusted, it's the exception trigger)
      const hasPasswordInHtml = lowerHtml.includes('type="password"') || lowerHtml.includes("type='password'");
      if (hasPasswordInHtml) {
        riskScore += 50;
        reasons.push("Login form detected (password input field)");
      }

      // ── The following checks are SKIPPED for trusted domains ──────────────────
      if (!isTrustedBrand) {
        // Email input combined with a form (generic credential harvesting)
        const hasEmailInput = lowerHtml.includes('type="email"') || lowerHtml.includes("type='email'");
        const hasFormTag = lowerHtml.includes('<form');
        if (hasEmailInput && hasFormTag) {
          riskScore += 20;
          reasons.push("Email input inside a form detected (possible credential harvesting)");
        }

        // Form action pointing to external domain
        const formActionMatch = lowerHtml.match(/action=["']([^"']+)["']/g) || [];
        const externalFormAction = formActionMatch.some(a => {
          try {
            const actionUrl = a.match(/action=["']([^"']+)["']/)[1];
            if (actionUrl.startsWith("http")) {
              const actionHost = new URL(actionUrl).hostname;
              return actionHost !== hostname;
            }
            return false;
          } catch { return false; }
        });
        if (externalFormAction) {
          riskScore += 30;
          reasons.push("Form submits data to an external domain (data exfiltration risk)");
        }

        // High-signal phishing content phrases
        const phishingPhrases = [
          "enter your password", "verify your account", "urgent action required",
          "your account will be blocked", "confirm your identity", "account suspended",
          "click here to verify", "update your information"
        ];
        const foundPhrases = phishingPhrases.filter(p => lowerHtml.includes(p));
        if (foundPhrases.length > 0) {
          riskScore += 30;
          reasons.push(`Phishing content detected: "${foundPhrases[0]}"`);
        }

        // Suspicious form actions
        const suspiciousFormWords = ["verify", "update", "secure", "confirm", "validate", "account"];
        const foundFormWords = suspiciousFormWords.filter(w => lowerHtml.includes(w));
        if (foundFormWords.length >= 2) {
          riskScore += 20;
          reasons.push(`Suspicious form language: "${foundFormWords.slice(0, 3).join('", "')}"`);
        }

        // Urgency keywords
        const urgencyWords = ["urgent", "immediately", "suspended", "blocked", "expires", "action required", "limited time", "click now"];
        const foundUrgency = urgencyWords.filter(w => lowerHtml.includes(w));
        if (foundUrgency.length > 0) {
          riskScore += 20;
          reasons.push(`Urgency manipulation detected: "${foundUrgency.slice(0, 2).join('", "')}"`);
        }

        // Hidden inputs (common in phishing)
        const hiddenInputCount = (lowerHtml.match(/type="hidden"/g) || []).length;
        if (hiddenInputCount > 5) {
          riskScore += 10;
          reasons.push(`Excessive hidden fields detected (${hiddenInputCount})`);
        }

        // Excessive script tags
        const scriptTagCount = (lowerHtml.match(/<script/g) || []).length;
        if (scriptTagCount > 15) {
          riskScore += 10;
          reasons.push(`High number of script tags (${scriptTagCount}) detected`);
        }

        // External scripts from unknown domains
        const scriptSrcMatches = lowerHtml.match(/src=["']https?:\/\/([^/"']+)/g) || [];
        const externalScriptDomains = new Set(
          scriptSrcMatches
            .map(s => { try { return new URL(s.replace(/src=["']/, '')).hostname; } catch { return ''; } })
            .filter(h => h && h !== hostname)
        );
        if (externalScriptDomains.size > 5) {
          riskScore += 15;
          reasons.push(`Scripts loaded from ${externalScriptDomains.size} external domains`);
        }

        // General sensitive keywords
        const keywords = ["ssn", "credit card", "bank account", "social security", "national id"];
        const foundKeywords = keywords.filter(w => lowerHtml.includes(w));
        if (foundKeywords.length > 0) {
          riskScore += 15;
          reasons.push(`Sensitive data keywords: "${foundKeywords.slice(0, 3).join('", "')}"`);
        }

        // ── INTENT ANALYSIS: SCAM / MANIPULATION PHRASES ─────────────────────
        const scamPhrases = [
          "claim your reward", "you have won", "you've won", "limited time offer",
          "act now", "verify now", "click below", "congratulations",
          "free gift", "lottery", "exclusive deal", "you are selected",
          "winner", "prize", "claim your prize", "redeem now", "special offer"
        ];
        const foundScamPhrases = scamPhrases.filter(p => lowerHtml.includes(p));
        if (foundScamPhrases.length > 0) {
          isScamPage = true;
          riskScore += 40;
          reasons.push(`Scam/manipulation phrases detected: "${foundScamPhrases.slice(0, 2).join('", "')}"`);
        }

        // ── INTENT ANALYSIS: FAKE CTA BUTTONS ────────────────────────────────
        const fakeCTAs = ["claim now", "verify account", "get reward", "click to claim",
          "collect reward", "get your prize", "redeem gift", "access now", "proceed now"];
        const foundCTAs = fakeCTAs.filter(c => lowerHtml.includes(c));
        if (foundCTAs.length > 0) {
          isScamPage = true;
          riskScore += 30;
          reasons.push(`Fake call-to-action detected: "${foundCTAs[0]}"`);
        }

        // ── INTENT ANALYSIS: THIN LANDING PAGE PATTERN ───────────────────────
        const pageTextLength = lowerHtml.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().length;
        const buttonCount = (lowerHtml.match(/<button|type="submit"|type='submit'/g) || []).length;
        const linkCount = (lowerHtml.match(/<a\s/g) || []).length;
        if (pageTextLength < 2000 && (buttonCount + linkCount) > 4) {
          riskScore += 20;
          reasons.push("Thin landing page: minimal content with multiple interactive elements");
        }

        // ── INTENT ANALYSIS: NO REAL CONTENT SIGNAL ──────────────────────────
        if (pageTextLength < 800 && htmlContent.length > 500) {
          riskScore += 20;
          reasons.push("Page has very little readable text content");
        }

        // ── INTENT ANALYSIS: EXCESSIVE EXTERNAL LINKS ────────────────────────
        const externalLinkMatches = lowerHtml.match(/href=["']https?:\/\/([^/"']+)/g) || [];
        const externalLinkDomains = externalLinkMatches
          .map(h => { try { return new URL(h.replace(/href=["']/, '')).hostname; } catch { return ''; } })
          .filter(h => h && h !== hostname);
        if (externalLinkDomains.length > 10) {
          riskScore += 15;
          reasons.push(`High number of external links: ${externalLinkDomains.length} outbound links`);
        }
      } // end: !isTrustedBrand generic checks
    }

    // ─── BLOCKED / TIMEOUT OVERRIDE ──────────────────────────────────────────
    let isBlocked = false;
    if (timedOut) {
      isBlocked = true;
      riskScore = Math.max(riskScore, 50);
      if (!reasons.find(r => r.includes("blocked"))) {
        reasons.push("Site blocked sandbox or prevented analysis");
      }
    }

    // ─── FINAL RISK CLASSIFICATION — STRICT PRIORITY ─────────────────────────
    const hasPasswordField = reasons.some(r => r.includes("password input field"));
    const hasPhishingContent = reasons.some(r =>
      r.includes("Phishing content") || r.includes("Urgency") ||
      r.includes("form language") || r.includes("keywords") || r.includes("exfiltration")
    );

    // For trusted brands: hard cap score to 20 unless password+phishing both fire
    if (isTrustedBrand && !(hasPasswordField && hasPhishingContent)) {
      riskScore = Math.min(riskScore, 20);
    }

    let riskLevel = "LOW";
    let explanation = "";

    // Build a contextual bullet list from actual detected signals
    const signalBullets = [];
    if (isTyposquat)     signalBullets.push("The domain structure is manipulated using character substitutions to impersonate a real brand");
    if (isBrandMisuse)   signalBullets.push("A legitimate brand name is embedded in an unofficial domain to deceive users");
    if (isScamPage)      signalBullets.push("The page contains psychological triggers such as fake prizes, urgency language, or deceptive rewards");
    if (hasPasswordField) signalBullets.push("The page contains a login form which could be used to harvest credentials");
    if (hasPhishingContent) signalBullets.push("Suspicious form language, urgency keywords, or data-exfiltration signals were detected");
    if (isBlocked)       signalBullets.push("The site blocked sandbox access, which is common with obfuscated or bot-protected phishing pages");
    if (riskScore >= 30 && !isTyposquat && !isBrandMisuse && !isScamPage && !hasPasswordField)
      signalBullets.push("Multiple low-confidence signals collectively indicate suspicious behavior");

    if (isBlocked) {
      riskLevel = "MEDIUM";
      explanation = `This website could not be fully analyzed:\n• ${signalBullets.join("\n• ")}\n\nProceed with caution and avoid entering any personal information.`;
    } else if (isTyposquat) {
      riskLevel = "HIGH";
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.join("\n• ")}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (isBrandMisuse) {
      riskLevel = "HIGH";
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.join("\n• ")}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (isScamPage) {
      riskLevel = "HIGH";
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.join("\n• ")}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (isTrustedBrand) {
      riskLevel = "LOW";
      explanation = `This website appears legitimate:\n• Domain and content are consistent with a recognized trusted brand\n• No strong phishing indicators were detected\n\nHowever, always verify URLs before sharing sensitive information.`;
    } else if (hasPasswordField && hasPhishingContent) {
      riskLevel = "HIGH";
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.join("\n• ")}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (riskScore >= 60) {
      riskLevel = "HIGH";
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Multiple domain and content risk signals accumulated above the high-risk threshold"}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (riskScore >= 30) {
      riskLevel = "MEDIUM";
      explanation = `This website shows several suspicious characteristics:\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Some elements resemble phishing behavior"}\n• Certain patterns indicate potential risk\n\nProceed with caution and avoid sharing sensitive information.`;
    } else {
      riskLevel = "LOW";
      explanation = `This website appears legitimate:\n• No strong phishing indicators detected\n• Domain and content are consistent with expected behavior\n\nHowever, always verify before sharing sensitive information.`;
    }

    // ─── OPTIONAL: GOOGLE SAFE BROWSING CHECK ─────────────────────────────────
    // Only runs if key exists and site is not already trusted
    if (SAFE_BROWSING_KEY && !isTrustedBrand && riskLevel !== "HIGH") {
      try {
        const sbEndpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`;
        const sbRes = await fetch(sbEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "civixshield", clientVersion: "1.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }]
            }
          })
        });
        const sbData = await sbRes.json();
        if (sbData.matches && sbData.matches.length > 0) {
          riskScore = Math.max(riskScore, 70);
          reasons.push("Google Safe Browsing: URL flagged as dangerous");
          if (riskLevel !== "HIGH") {
            riskLevel = "HIGH";
            explanation = `This website is highly suspicious based on multiple phishing indicators:\n• Flagged by Google Safe Browsing threat database\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Additional heuristic signals detected"}\n\nUsers should avoid interacting with this site entirely.`;
          }
          if (isDev) console.error("[CIVIX] Safe Browsing: URL is FLAGGED");
        } else {
          if (isDev) console.error("[CIVIX] Safe Browsing: URL is clean");
        }
      } catch (sbErr) {
        // Fail open — safe browsing failure is NOT unsafe
        if (isDev) console.error("[CIVIX] Safe Browsing check failed (fallback to heuristic):", sbErr.message);
      }
    }

    // ─── OPTIONAL: GEMINI AI ENRICHMENT LAYER ─────────────────────────────────
    // STRICT RULES:
    // 1. Trusted domains ALWAYS stay LOW — AI cannot escalate them
    // 2. If AI confidence < 60% → fall back to heuristic result
    // 3. If Gemini fails for any reason → silently continue with heuristic
    let aiRiskLevel = null;
    let aiConfidence = 0;

    if (GEMINI_KEY && !isTrustedBrand && !isBlocked) {
      try {
        const truncatedHtml = htmlContent ? htmlContent.slice(0, 3000) : "(no content available)";
        const geminiPrompt = [
          "You are a cybersecurity expert specializing in phishing detection.",
          "Analyze the following website:",
          `URL: ${url}`,
          `HTML snippet (first 3000 chars): ${truncatedHtml}`,
          "",
          "STRICT RULE: Trusted domains (google.com, amazon.com, sbi.co.in, etc.) MUST NEVER be marked as phishing unless there is clear impersonation or active credential harvesting.",
          "",
          "Respond ONLY with valid JSON in this exact format:",
          `{ "riskLevel": "LOW" | "MEDIUM" | "HIGH", "confidence": 0-100, "reason": "one sentence" }`,
          "No other text."
        ].join("\n");

        const geminiRes = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_KEY}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              contents: [{ parts: [{ text: geminiPrompt }] }],
              generationConfig: { temperature: 0.1, maxOutputTokens: 120 }
            })
          }
        );

        const geminiData = await geminiRes.json();
        const rawText = geminiData?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "";
        // Strip markdown fences if present
        const cleaned = rawText.replace(/^```[a-z]*\n?/i, "").replace(/\n?```$/i, "").trim();
        const aiResult = JSON.parse(cleaned);

        aiRiskLevel = aiResult.riskLevel;
        aiConfidence = Number(aiResult.confidence) || 0;

        if (isDev) console.error(`[CIVIX] Gemini AI: ${aiRiskLevel} (confidence ${aiConfidence}%) — ${aiResult.reason}`);

        // Apply AI result ONLY if confidence >= 60 and NOT trusted domain
        if (aiConfidence >= 60 && !isTrustedBrand) {
          if (aiRiskLevel === "HIGH" && riskLevel !== "HIGH" && !isTrustedBrand) {
            riskLevel = "HIGH";
            riskScore = Math.max(riskScore, 65);
            reasons.push(`AI analysis (${aiConfidence}% confidence): ${aiResult.reason}`);
            explanation = `This website is highly suspicious based on multiple phishing indicators:\n• AI-detected: ${aiResult.reason}\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Multiple heuristic signals"}\n\nUsers should avoid interacting with this site entirely.`;
          } else if (aiRiskLevel === "MEDIUM" && riskLevel === "LOW") {
            riskLevel = "MEDIUM";
            riskScore = Math.max(riskScore, 35);
            reasons.push(`AI analysis (${aiConfidence}% confidence): ${aiResult.reason}`);
            explanation = `This website shows several suspicious characteristics:\n• AI-detected: ${aiResult.reason}\n\nProceed with caution and avoid sharing sensitive information.`;
          }
        } else {
          if (isDev) console.error(`[CIVIX] Gemini confidence too low (${aiConfidence}%) — using heuristic result`);
        }

      } catch (aiErr) {
        // Fail silently — heuristic result is used
        if (isDev) console.error("[CIVIX] Gemini fallback (error):", aiErr.message);
      }
    } else if (!GEMINI_KEY) {
      if (isDev) console.error("[CIVIX] Gemini key not set — using heuristic only");
    }

    // ─── FINAL TRUSTED DOMAIN SAFETY NET ─────────────────────────────────────
    // Hard guarantee: trusted domain NEVER leaves as HIGH or MEDIUM
    // unless both credential signals fire (the only legitimate exception)
    if (isTrustedBrand && !(hasPasswordField && hasPhishingContent)) {
      riskScore = Math.min(riskScore, 15);
      riskLevel = "LOW";
      explanation = `This website appears legitimate:\n• Domain and content are consistent with a recognized trusted brand\n• No strong phishing indicators were detected\n\nHowever, always verify URLs before sharing sensitive information.`;
    }

    const result = {
      screenshot: screenshotBuffer.toString("base64"),
      warning: isBlocked ? "Site blocked sandbox or prevented secure analysis" : null,
      analysis: {
        riskScore: Math.min(100, riskScore),
        riskLevel,
        reasons,
        explanation,
        isBlocked,
        isTrustedBrand
      }
    };

    console.log(JSON.stringify(result));

  } catch (err) {
    if (browser) {
      try { await browser.close(); } catch {}
    }
    console.error(err.message || "Unknown error inside Playwright script");
    process.exit(1);
  }
})();
