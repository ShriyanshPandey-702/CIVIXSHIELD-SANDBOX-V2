const { chromium } = require('playwright');
const url = process.argv[2];

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

(async () => {
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    });

    const page = await context.newPage();

    // Block heavy media resources for speed + security
    await page.route("**/*", (route) => {
      const type = route.request().resourceType();
      if (["media", "websocket", "eventsource"].includes(type)) {
        route.abort();
      } else {
        route.continue();
      }
    });

    let timedOut = false;
    try {
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 20000,
      });
    } catch (navErr) {
      timedOut = true;
      try { await page.evaluate(() => window.stop()); } catch (e) {}
    }

    let htmlContent = "";
    if (!timedOut) {
      try { htmlContent = await page.content(); } catch (e) {}
    }

    // Capture screenshot
    const screenshotBuffer = await page.screenshot({
      fullPage: false,
      type: "png",
      timeout: 5000,
      animations: "disabled",
    });

    await browser.close();

    // ─── ANALYSIS ENGINE ─────────────────────────────────────────────────────
    let riskScore = 0;
    const reasons = [];
    let hostname = "";
    let isTrustedBrand = false;
    let isKnownBrand = false;

    try {
      const parsedUrl = new URL(url);
      hostname = parsedUrl.hostname.toLowerCase().replace(/^www\./, "");

      // 1. HTTPS check
      if (parsedUrl.protocol !== "https:") {
        riskScore += 20;
        reasons.push("Not using HTTPS");
      }

      // 2. Numbers in domain
      if (/\d/.test(hostname)) {
        riskScore += 10;
        reasons.push("Domain contains numbers (suspicious pattern)");
      }

      // 3. Too many hyphens
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount > 2) {
        riskScore += 15;
        reasons.push("Domain has excessive hyphens (common in phishing)");
      }

      // 4. Typosquatting detection
      const typosquatMatch = TYPOSQUAT_PATTERNS.find(p =>
        p.fakes.some(fake => hostname.includes(fake))
      );
      if (typosquatMatch) {
        riskScore += 40;
        reasons.push(`Typosquatting detected: resembles "${typosquatMatch.real}"`);
      }

      // 5. Trusted brand check
      const matchedBrand = TRUSTED_BRANDS.find(brand => hostname.includes(brand));
      if (matchedBrand) {
        isKnownBrand = true;
        // Check if the domain is EXACTLY the brand or a subdomain of it
        // (e.g., sbi.co.in passes, sbi-alert.xyz fails)
        const isExactOrSubdomain = hostname === matchedBrand ||
          hostname.endsWith(`.${matchedBrand}.com`) ||
          hostname.endsWith(`.${matchedBrand}.in`) ||
          hostname.endsWith(`.${matchedBrand}.co.in`) ||
          hostname.endsWith(`.${matchedBrand}.org`) ||
          hostname.endsWith(`.${matchedBrand}.net`) ||
          hostname === `${matchedBrand}.com` ||
          hostname === `${matchedBrand}.in` ||
          hostname === `${matchedBrand}.co.in` ||
          hostname === `${matchedBrand}.org` ||
          hostname === `${matchedBrand}.net` ||
          hostname === `${matchedBrand}.gov.in`;

        if (isExactOrSubdomain) {
          isTrustedBrand = true;
          riskScore = Math.max(0, riskScore - 40);
          reasons.push(`Recognized trusted brand domain: ${matchedBrand}`);
        } else {
          // Brand keyword in a suspicious domain — phishing signal!
          riskScore += 35;
          reasons.push(`Brand name "${matchedBrand}" used in suspicious domain (possible impersonation)`);
        }
      }
    } catch(e) {}

    // ─── HTML CONTENT ANALYSIS ────────────────────────────────────────────────
    if (htmlContent) {
      const lowerHtml = htmlContent.toLowerCase();

      // Password field
      if (lowerHtml.includes('type="password"') || lowerHtml.includes("type='password'")) {
        riskScore += 50;
        reasons.push("Login form detected (password input field)");
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

      // Hidden inputs (common in phishing to send extra data)
      const hiddenInputCount = (lowerHtml.match(/type="hidden"/g) || []).length;
      if (hiddenInputCount > 5) {
        riskScore += 10;
        reasons.push(`Excessive hidden fields detected (${hiddenInputCount})`);
      }

      // General suspicious keywords
      const keywords = ["password", "ssn", "credit card", "bank account", "social security"];
      const foundKeywords = keywords.filter(w => lowerHtml.includes(w));
      if (foundKeywords.length > 0) {
        riskScore += 15;
        reasons.push(`Sensitive data keywords: "${foundKeywords.slice(0, 3).join('", "')}"`);
      }
    }

    // ─── BLOCKED / TIMEOUT OVERRIDE ──────────────────────────────────────────
    let isBlocked = false;
    if (timedOut || (!htmlContent && !timedOut)) {
      isBlocked = true;
      riskScore = Math.max(riskScore, 50);
      if (!reasons.find(r => r.includes("blocked"))) {
        reasons.push("Site blocked sandbox or prevented analysis");
      }
    }

    // ─── FINAL RISK CLASSIFICATION ────────────────────────────────────────────
    // If trusted brand but has phishing signals, don't downgrade
    if (isTrustedBrand && riskScore <= 20 && reasons.length <= 1) {
      riskScore = 0;
    }

    let riskLevel = "LOW";
    let explanation = "";

    if (isBlocked) {
      riskLevel = "MEDIUM";
      explanation = "This site prevented sandbox analysis. This does NOT mean it is safe. Treat all unverifiable sites with caution.";
    } else if (riskScore >= 70) {
      riskLevel = "HIGH";
      explanation = "This site appears to be a phishing attempt because it requests sensitive credentials and uses manipulative language. Do NOT enter any personal information.";
    } else if (riskScore >= 40) {
      riskLevel = "MEDIUM";
      explanation = "This site shows suspicious patterns and should be treated cautiously. Verify the URL before entering any information.";
    } else {
      riskLevel = "LOW";
      explanation = isTrustedBrand
        ? "This site belongs to a recognized trusted brand and appears safe based on automated analysis."
        : "This site appears safe based on current analysis. Always verify URLs before sharing sensitive data.";
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
