const { chromium } = require('playwright');
const { createWorker } = require('tesseract.js');
const url = process.argv[2];
const isDev = process.env.NODE_ENV !== 'production';

// ─── FORENSIC LOGGING ─────────────────────────────────────────────────────
const logs = [];
function addLog(type, msg) {
  const now = new Date();
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const msStr = now.getMilliseconds().toString().padStart(3, '0');
  logs.push({ time: `${timeStr}.${msStr}`, type, msg });
  if (isDev) console.error(`[FORENSIC] ${type.toUpperCase()}: ${msg}`);
}

addLog('info', 'Initializing CIVIXSHIELD sandbox environment');

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
  // Global Tech & Social
  "google", "youtube", "gmail", "facebook", "instagram", "twitter", "x.com",
  "whatsapp", "microsoft", "apple", "amazon", "netflix", "linkedin", "github",
  "stackoverflow", "wikipedia", "reddit", "dropbox", "spotify", "airbnb",
  "uber", "paypal", "stripe", "shopify", "zoom", "slack", "notion", "figma",
  "canva", "adobe", "salesforce", "wordpress", "cloudflare", "vercel",
  "tiktok", "twitch", "yahoo", "pinterest", "discord", "telegram", "snapchat",
  "samsung", "sony", "tencent", "alibaba", "oracle", "ibm", "cisco", "intel",
  // US & Global Finance
  "chase", "bankofamerica", "wellsfargo", "binance", "coinbase",
  "americanexpress", "mastercard", "visa", "capitalone", "citibank",
  // Indian Banking & Govt
  "sbi", "hdfc", "icici", "axisbank", "kotak", "npci", "uidai", "gov.in",
  "india.gov", "irctc", "incometax", "mca", "sebi", "rbi", "pnb", "bob",
  "canara", "unionbank", "indianbank", "bseindia", "nseindia",
  // Indian Tech & Commerce
  "paytm", "phonepe", "zerodha", "groww", "upstox", "myntra", "nykaa",
  "zomato", "swiggy", "makemytrip", "yatra", "cleartrip", "bookmyshow",
  "flipkart", "tata", "reliance", "jio", "airtel"
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
  { real: "paytm",     fakes: ["payteem","paytime","pay-tm"] },
  { real: "whatsapp",  fakes: ["whatsap","whatapp","watsapp"] }
];

// ─── ROOT DOMAIN EXTRACTION ───────────────────────────────────────────────
// Collapses any subdomain to just the registrable root: e.g. login.amazon.in → amazon.in
function getRootDomain(host) {
  const h = host.toLowerCase().replace(/^www\./, "");
  const parts = h.split(".");
  // Handle known two-part TLDs (co.in, co.uk, com.au, etc.)
  const twoPartTLDs = ["co.in", "co.uk", "com.au", "co.nz", "gov.in", "net.in", "org.in", "ac.in", "edu.in", "bank.in", "res.in"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTLDs.includes(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// Explicit list — root domain must be an EXACT match
// Includes all official subdomains that resolve to these roots via getRootDomain()
const TRUSTED_ROOTS = new Set([
  // Google ecosystem
  "google.com", "google.co.in", "google.co.uk", "youtube.com", "gmail.com",
  // Microsoft ecosystem
  "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
  "office.com", "azure.com", "bing.com", "xbox.com", "linkedin.com",
  // Apple
  "apple.com", "icloud.com",
  // Meta
  "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
  // Amazon
  "amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com",
  // Global Finance & Payments
  "paypal.com", "stripe.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
  "binance.com", "coinbase.com", "americanexpress.com", "mastercard.us", "visa.com", "capitalone.com", "citi.com",
  // Indian Banking & Payments
  "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
  "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
  "indianbank.in", "npci.org.in", "paytm.com", "phonepe.com", "zerodha.com", "groww.in", "upstox.com",
  // Dev & Cloud
  "github.com", "gitlab.com", "cloudflare.com", "vercel.com",
  "stackoverflow.com", "heroku.com", "oracle.com", "ibm.com", "cisco.com", "intel.com",
  // Social, Media & Content
  "twitter.com", "x.com", "reddit.com", "wikipedia.org",
  "netflix.com", "spotify.com", "dropbox.com", "tiktok.com", "twitch.tv", "yahoo.com",
  "pinterest.com", "discord.com", "t.me", "snapchat.com",
  // Productivity
  "slack.com", "zoom.us", "notion.so", "figma.com",
  "canva.com", "adobe.com", "salesforce.com",
  // Global Commerce
  "shopify.com", "airbnb.com", "uber.com", "samsung.com", "sony.com", "alibaba.com",
  // Indian Commerce & Services
  "flipkart.com", "myntra.com", "nykaa.com", "zomato.com", "swiggy.com",
  "makemytrip.com", "yatra.com", "cleartrip.com", "bookmyshow.com", "tata.com",
  "jiomart.com", "jio.com", "airtel.in",
  // Indian government & regulatory
  "irctc.co.in", "indianrailways.gov.in",
  "incometax.gov.in", "uidai.gov.in", "mca.gov.in", "sebi.gov.in", "rbi.org.in",
  "bseindia.com", "nseindia.com", "india.gov.in"
]);

(async () => {
  let browser;
  try {
    addLog('info', 'Booting Chromium isolation chamber');
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
      addLog('info', `Resolving DNS and opening URL: ${url}`);
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 6000,  // Fast-fail: heavy sites must respond within 6s
      });
      // Brief settle time for DOM to stabilise after load event
      await page.waitForTimeout(1000);
      addLog('success', 'Page DOM successfully loaded');
    } catch (navErr) {
      timedOut = true;
      addLog('warning', `Page load timed out (6s limit reached)`);
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
      addLog('info', 'Capturing forensic screenshot');
      screenshotBuffer = await page.screenshot({
        fullPage: false,
        type: "png",
        timeout: 3000,
        animations: "disabled",
      });
    } catch (ssErr) {
      // Retry once with extra wait
      try {
        addLog('warning', 'Screenshot failed, retrying fallback method');
        await page.waitForTimeout(1000);
        screenshotBuffer = await page.screenshot({ fullPage: false, type: "png" });
      } catch (ssErr2) {
        // Last resort: blank fallback page
        addLog('danger', 'Screenshot failed completely, injecting blank fallback');
        await page.setContent("<html style='background:#202124'><body></body></html>");
        screenshotBuffer = await page.screenshot({ fullPage: false, type: "png" });
      }
    }

    // Stop any remaining JS execution before closing
    try { await page.evaluate(() => window.stop()); } catch(e) {}

    // ── LIVE DOM: FAKE LOGIN FORM SIGNALS ─────────────────────────────────────
    // Runs while page is still live so we can inspect computed styles.
    // Lightweight — uses no external calls, finishes in <50ms.
    let domLoginSignals = {};
    try {
      addLog('info', 'Injecting script to inspect live DOM objects (forms, inputs)');
      domLoginSignals = await page.evaluate(() => {
        const inputs = Array.from(document.querySelectorAll('input'));
        const forms  = Array.from(document.querySelectorAll('form'));

        // 1. Password field count
        const passwordFields = inputs.filter(i => i.type === 'password');

        // 2. Email / username fields
        const credFields = inputs.filter(i =>
          i.type === 'email' ||
          /user(name)?|email|login|account/i.test(i.name + i.id + i.placeholder)
        );

        // 3. Suspicious submit buttons/links
        const SUSPICIOUS_BTNS = ['login','sign in','verify','continue','unlock','confirm account','secure login'];
        const allClickables = [
          ...Array.from(document.querySelectorAll('button')),
          ...Array.from(document.querySelectorAll('input[type="submit"]')),
          ...Array.from(document.querySelectorAll('a')),
        ];
        const suspiciousButtons = allClickables.filter(el => {
          const t = (el.textContent || el.value || '').toLowerCase().trim();
          return SUSPICIOUS_BTNS.some(k => t.includes(k));
        });

        // 4. Hidden / offscreen forms
        const hiddenForms = forms.filter(f => {
          const s = window.getComputedStyle(f);
          const r = f.getBoundingClientRect();
          return s.display === 'none' || s.visibility === 'hidden' ||
                 s.opacity === '0' || r.top > 9000 || r.left < -500;
        });

        // 5. Forms posting to external domain
        const currentHost = location.hostname.replace(/^www\./, '');
        const externalActions = forms.filter(f => {
          try {
            const action = f.action;
            if (!action || action === '' || action.startsWith('javascript')) return false;
            const actionHost = new URL(action, location.href).hostname.replace(/^www\./, '');
            return actionHost !== currentHost && actionHost !== '';
          } catch { return false; }
        });

        // 6. Brand words in visible page text
        const bodyText = (document.body?.innerText || '').toLowerCase();
        const BRANDS = ['google','microsoft','paypal','amazon','facebook','instagram','bank','apple','netflix','sbi','hdfc','icici'];
        const brandsFound = BRANDS.filter(b => bodyText.includes(b));

        return {
          passwordFieldCount: passwordFields.length,
          credFieldCount: credFields.length,
          suspiciousButtonCount: suspiciousButtons.length,
          hiddenFormCount: hiddenForms.length,
          externalActionCount: externalActions.length,
          brandsInPageText: brandsFound,
          pageTextLength: bodyText.length,
          hasLoginForm: passwordFields.length > 0,
        };
      });
    } catch(domErr) {
      addLog('warning', 'Live DOM inspection failed');
      if (isDev) console.error('[CIVIX] DOM login scan failed:', domErr.message);
    }

    addLog('info', 'Terminating browser context');
    await browser.close();

    // ─── ANALYSIS ENGINE ─────────────────────────────────────────────────────
    let riskScore = 0;
    const reasons = [];
    let hostname = "";
    let isTrustedBrand = false;
    let isTyposquat = false;
    let isBrandMisuse = false;
    let isScamPage = false;
    let isLegitInstitution = false; // Set after HTML analysis

    // ── ROOT-DOMAIN TRUSTED CHECK (runs before ALL heuristics) ────────────────
    // This is the primary false-positive guard for legitimate heavy sites
    // (Amazon, Flipkart, Google, SBI) that would otherwise trip generic signals.
    try {
      const _parsedForRoot = new URL(url);
      const _rawHost = _parsedForRoot.hostname.toLowerCase().replace(/^www\./, "");
      const rootDomain = getRootDomain(_rawHost);
      
      if (TRUSTED_ROOTS.has(rootDomain)) {
        isTrustedBrand = true;
        riskScore = 5;
        hostname = _rawHost;
        reasons.push("Trusted domain (official source)");
        addLog('success', `Official trusted domain matched whitelist: ${rootDomain}`);
        if (isDev) console.error(`[CIVIX] Trusted root matched: ${rootDomain} → forcing LOW`);
      } else {
        // ── DELEGATED NAMESPACE VERIFICATION ──────────────────────────
        const TRUSTED_NAMESPACES = [".bank.in", ".co.in", ".gov.in", ".nic.in", ".edu.in", ".ac.in", ".org.in", ".ernet.in", ".res.in"];
        const tldMatch = TRUSTED_NAMESPACES.find(ns => rootDomain.endsWith(ns));
        
        if (tldMatch) {
          const brandLabel = rootDomain.slice(0, -(tldMatch.length)); // remove the .bank.in part
          if (TRUSTED_BRANDS.includes(brandLabel)) {
            isTrustedBrand = true;
            riskScore = 5;
            hostname = _rawHost;
            reasons.push(`Trusted domain (verified delegated namespace: ${tldMatch})`);
            addLog('success', `Trusted brand "${brandLabel}" matched verified namespace ${tldMatch}`);
            if (isDev) console.error(`[CIVIX] Delegated namespace matched: ${brandLabel}${tldMatch} → forcing LOW`);
          }
        }
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

      // ── BRAND IMPERSONATION & TYPOSQUATTING (Only for non-official domains) ──
      if (!isTrustedBrand) {
        addLog('info', 'Checking domain for typosquatting and brand impersonation');

        let foundTyposquat = false;
        let foundBrandMisuse = false;
        let targetBrand = null;

        // 1. Check direct Fake Patterns
        const oldFakeMatch = TYPOSQUAT_PATTERNS.find(p => p.fakes.some(fake => hostname.includes(fake)));
        if (oldFakeMatch) {
          foundTyposquat = true;
          targetBrand = oldFakeMatch.real;
        }

        // 2. Check affixes (Brand Impersonation)
        const AFFIX_LIST = ["login", "secure", "verify", "update", "account", "support", "online", "portal", "auth", "service", "banking"];
        // Split by dash or dot to find exact words
        const domainWords = domainLabel.split(/[-.]/);
        
        for (const brand of TRUSTED_BRANDS) {
          if (domainWords.includes(brand)) {
             const hasAffix = domainWords.some(p => AFFIX_LIST.includes(p));
             if (hasAffix) {
               foundBrandMisuse = true;
               targetBrand = brand;
               break;
             }
          }
        }

        // 3. Char Substitution Typosquatting (e.g. paypa1) OR Edit Distance
        if (!foundTyposquat && !foundBrandMisuse) {
          const normalized = domainLabel
            .replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e")
            .replace(/@/g, "a").replace(/\$/g, "s").replace(/5/g, "s")
            .replace(/4/g, "a");
            
          for (const brand of TRUSTED_BRANDS) {
             // Substitution spoof
             if (domainLabel !== brand && normalized === brand) {
                foundTyposquat = true;
                targetBrand = brand;
                break;
             }
             // Edit Distance (e.g., hdfccbank padding spoof)
             if (normalized !== brand) {
               // Must be close in length so 'u' doesn't flag 'uber'
               if ((normalized.includes(brand) && Math.abs(normalized.length - brand.length) <= 4) ||
                   (brand.includes(normalized) && Math.abs(brand.length - normalized.length) <= 2 && normalized.length >= 4)) {
                 foundTyposquat = true;
                 targetBrand = brand;
                 break;
               }
             }
          }
        }
        
        // 4. Exact match in an unverified TLD (General Brand Misuse)
        if (!foundTyposquat && !foundBrandMisuse && TRUSTED_BRANDS.includes(domainLabel)) {
           foundBrandMisuse = true;
           targetBrand = domainLabel;
        }

        // Apply Scores
        if (foundTyposquat) {
          isTyposquat = true;
          riskScore += 60;
          reasons.push(`Typosquatting detected: domain impersonates "${targetBrand}"`);
          addLog('danger', `Typosquatting pattern detected: domain impersonates "${targetBrand}"`);
        } else if (foundBrandMisuse) {
          isBrandMisuse = true;
          riskScore += 50;
          reasons.push(`Brand Impersonation: "${targetBrand}" used in unofficial/unverified domain`);
          addLog('danger', `Brand Impersonation detected: "${targetBrand}" in unverified namespace`);
        }
      }
    } catch(e) {}

    // ─── HTML CONTENT ANALYSIS ────────────────────────────────────────────────
    if (htmlContent) {
      const lowerHtml = htmlContent.toLowerCase();

      // Password field — checked with institution awareness
      // Institutions (college portals, hospital systems, gov portals) legitimately have login forms.
      // We defer the password penalty until AFTER institution detection further below.
      const hasPasswordInHtml = lowerHtml.includes('type="password"') || lowerHtml.includes("type='password'");
      if (hasPasswordInHtml && !isTrustedBrand) {
        // Soft-add: will be cancelled if institution detection fires later
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
        // Threshold: 25 (not 10) — real content-rich sites legitimately link to many places
        // Extra allowance if the page has many sections (linkCount > 20 = likely a real nav site)
        const linkThreshold = linkCount > 20 ? 40 : 25;
        if (externalLinkDomains.length > linkThreshold) {
          riskScore += 15;
          reasons.push(`High number of external links: ${externalLinkDomains.length} outbound links`);
        }
      } // end: !isTrustedBrand generic checks
    }

    // ─── LEGITIMATE INSTITUTION DETECTION ENGINE ───────────────────────────────
    // Runs AFTER all heuristics so we can evaluate accumulated score against context.
    // Does NOT zero out scores — dampens them proportionally so genuine threats survive.
    if (!isTrustedBrand && htmlContent) {
      const lowerHtml2 = htmlContent.toLowerCase();
      const bodyText2 = lowerHtml2.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

      // 1. Domain TLD signals — strong structural indicator
      let tldInstitutionScore = 0;
      try {
        const _h = new URL(url).hostname.toLowerCase();
        if (_h.endsWith('.edu') || _h.endsWith('.edu.in') || _h.endsWith('.ac.in') ||
            _h.endsWith('.ac.uk') || _h.endsWith('.sch.in')) tldInstitutionScore += 40;
        if (_h.endsWith('.gov') || _h.endsWith('.gov.in') || _h.endsWith('.nic.in')) tldInstitutionScore += 40;
        if (_h.endsWith('.org') || _h.endsWith('.org.in') || _h.endsWith('.ngo')) tldInstitutionScore += 15;
        if (_h.endsWith('.mil') || _h.endsWith('.int')) tldInstitutionScore += 40;
      } catch(e) {}

      // 2. Content signals — institutional language in body text
      let contentInstitutionScore = 0;
      const INSTITUTION_PHRASES = [
        ['college', 10], ['university', 10], ['institute', 10], ['school of', 10],
        ['department of', 8], ['faculty', 8], ['students', 6], ['alumni', 8],
        ['campus', 8], ['hostel', 6], ['semester', 8], ['examination', 8],
        ['admissions', 6], ['curriculum', 8], ['accredited', 10], ['affiliated', 10],
        ['hospital', 10], ['clinic', 8], ['patients', 6], ['healthcare', 8],
        ['government', 8], ['ministry', 10], ['municipality', 10], ['department', 6],
        ['ngo', 8], ['nonprofit', 8], ['foundation', 8], ['trust', 6], ['charity', 8],
        ['corporate', 6], ['headquarters', 8], ['annual report', 10], ['investor', 8],
        ['about us', 4], ['contact us', 4], ['our team', 4], ['our mission', 4],
      ];
      for (const [phrase, pts] of INSTITUTION_PHRASES) {
        if (bodyText2.includes(phrase)) contentInstitutionScore += pts;
      }

      // 3. Structural richness signals — real sites have nav, footer, many sections
      let structureScore = 0;
      if ((lowerHtml2.match(/<nav[\s>]/g) || []).length >= 1) structureScore += 10;
      if ((lowerHtml2.match(/<footer[\s>]/g) || []).length >= 1) structureScore += 10;
      if ((lowerHtml2.match(/<header[\s>]/g) || []).length >= 1) structureScore += 5;
      if ((lowerHtml2.match(/<section[\s>]|<article[\s>]/g) || []).length >= 3) structureScore += 10;
      if ((lowerHtml2.match(/href=["'].*?(about|contact|team|career|gallery|news|event)/gi) || []).length >= 2) structureScore += 15;

      // 4. Registration/admission words ≠ phishing — whitelist them for institutions
      const LEGIT_REGISTRATION_WORDS = [
        'admission', 'register', 'registration', 'apply', 'application form',
        'enrollment', 'enroll', 'sign up', 'new user', 'create account',
      ];
      const hasLegitRegistration = LEGIT_REGISTRATION_WORDS.some(w => bodyText2.includes(w));

      // 5. Social media links — these are normal trust indicators, not phishing signals
      const SOCIAL_DOMAINS = ['facebook.com','twitter.com','instagram.com','youtube.com',
        'linkedin.com','x.com','t.me','wa.me','whatsapp.com','pinterest.com'];
      const hasSocialLinks = SOCIAL_DOMAINS.some(d => lowerHtml2.includes(d));

      // Base identity must be strong (TLD or institutional keywords).
      // Structural richness alone cannot make a site 'Institutional'.
      const baseIdentityScore = tldInstitutionScore + contentInstitutionScore;
      const institutionConfidence = baseIdentityScore + structureScore;

      if (baseIdentityScore >= 20 && institutionConfidence >= 30) {
        isLegitInstitution = true;
        const DAMPENING = institutionConfidence >= 60 ? 0.35 : 0.55;
        addLog('info', `Institutional signals detected (Score: ${institutionConfidence}pts). Applying risk dampening.`);

        // Apply dampening to suppress noise-inflated score
        const rawScore = riskScore;
        riskScore = Math.floor(riskScore * DAMPENING);

        // Remove password-form reason if institution has a portal — expected behaviour
        const pwIdx = reasons.findIndex(r => r.includes('password input field'));
        if (pwIdx !== -1) reasons.splice(pwIdx, 1);

        // Remove urgency/form-language noise if institution has legit registration
        if (hasLegitRegistration) {
          const cleanOut = ['Urgency manipulation', 'Suspicious form language', 'Thin landing page', 'little readable text'];
          for (let i = reasons.length - 1; i >= 0; i--) {
            if (cleanOut.some(c => reasons[i].includes(c))) reasons.splice(i, 1);
          }
        }

        // Add the institution signal as a positive badge
        reasons.push(`Legitimate institution signals detected (confidence score: ${institutionConfidence})`);
        if (hasSocialLinks) reasons.push('Official social media presence detected (trust signal)');

        if (isDev) console.error(`[CIVIX] Institution detected: tld=${tldInstitutionScore} content=${contentInstitutionScore} struct=${structureScore} → score ${rawScore} → ${riskScore} (dampening ${DAMPENING})`);
      }
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
    // For legitimate institutions: hard cap at 48 (MEDIUM ceiling) unless typosquat/scam/brand-misuse
    if (isLegitInstitution && !isTyposquat && !isBrandMisuse && !isScamPage) {
      riskScore = Math.min(riskScore, 48);
    }

    // ─── SINGLE SOURCE OF TRUTH: score → level ────────────────────────────────────
    // Every riskLevel in this file must flow through this function.
    // NO code below may assign riskLevel directly without going through scoreToLevel().
    function scoreToLevel(s) {
      if (s <= 25) return "LOW";
      if (s <= 50) return "MEDIUM";
      return "HIGH";  // 51-100
    }

    let riskLevel = scoreToLevel(riskScore);
    let explanation = "";

    // Build explanation from flags and current score-derived level
    const signalBullets = [];
    if (isTyposquat)      signalBullets.push("The domain structure is manipulated using character substitutions to impersonate a real brand");
    if (isBrandMisuse)    signalBullets.push("A legitimate brand name is embedded in an unofficial domain to deceive users");
    if (isScamPage)       signalBullets.push("The page contains psychological triggers such as fake prizes, urgency language, or deceptive rewards");
    if (hasPasswordField) signalBullets.push("The page contains a login form which could be used to harvest credentials");
    if (hasPhishingContent) signalBullets.push("Suspicious form language, urgency keywords, or data-exfiltration signals were detected");
    if (isBlocked)        signalBullets.push("The site blocked sandbox access, which is common with obfuscated or bot-protected phishing pages");
    if (riskScore >= 26 && !isTyposquat && !isBrandMisuse && !isScamPage && !hasPasswordField)
      signalBullets.push("Multiple low-confidence signals collectively indicate suspicious behavior");

    // Derive riskLevel from score — flags only influence explanation text
    riskLevel = scoreToLevel(riskScore);

    if (isBlocked) {
      explanation = `This website could not be fully analyzed:\n• ${signalBullets.join("\n• ")}\n\nProceed with caution and avoid entering any personal information.`;
    } else if (isTyposquat || isBrandMisuse || isScamPage || (hasPasswordField && hasPhishingContent)) {
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.join("\n• ")}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (isTrustedBrand) {
      explanation = `This website appears legitimate:\n• Domain and content are consistent with a recognized trusted brand\n• No strong phishing indicators were detected\n\nHowever, always verify URLs before sharing sensitive information.`;
    } else if (isLegitInstitution) {
      explanation = `This website shows characteristics of a legitimate institutional site:\n• Institutional content and structure detected\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "No strong phishing patterns detected"}\n\nVerify the domain matches the official institution URL before sharing credentials.`;
    } else if (riskLevel === "HIGH") {
      explanation = `This website is highly suspicious based on multiple phishing indicators:\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Multiple domain and content risk signals accumulated above the high-risk threshold"}\n\nUsers should avoid interacting with this site entirely.`;
    } else if (riskLevel === "MEDIUM") {
      explanation = `This website shows several suspicious characteristics:\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Some elements resemble phishing behavior"}\n• Certain patterns indicate potential risk\n\nProceed with caution and avoid sharing sensitive information.`;
    } else {
      explanation = `This website appears legitimate:\n• No strong phishing indicators detected\n• Domain and content are consistent with expected behavior\n\nHowever, always verify before sharing sensitive information.`;
    }

    // ─── OPTIONAL: GOOGLE SAFE BROWSING CHECK ─────────────────────────────────
    // Only runs if key exists and site is not already trusted
    if (SAFE_BROWSING_KEY && !isTrustedBrand && riskLevel !== "HIGH") {
      try {
        addLog('info', 'Querying Google Safe Browsing threat databases');
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
          addLog('danger', 'Safe Browsing hit: Google threat database match found');
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
        addLog('info', 'Executing deep payload analysis via Gemini AI');
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

        // Apply AI result ONLY if confidence >= 60 and NOT trusted domain or institution
        if (aiConfidence >= 60 && !isTrustedBrand) {
          addLog(aiRiskLevel === "HIGH" ? 'danger' : 'warning', `AI analysis returned ${aiRiskLevel} risk (conf: ${aiConfidence}%)`);
          if (aiRiskLevel === "HIGH" && !isTrustedBrand) {
            // Escalate score to HIGH band — label re-derives from score at end
            riskScore = Math.max(riskScore, 65);
            reasons.push(`AI analysis (${aiConfidence}% confidence): ${aiResult.reason}`);
            explanation = `This website is highly suspicious based on multiple phishing indicators:\n• AI-detected: ${aiResult.reason}\n• ${signalBullets.length > 0 ? signalBullets.join("\n• ") : "Multiple heuristic signals"}\n\nUsers should avoid interacting with this site entirely.`;
          } else if (aiRiskLevel === "MEDIUM" && scoreToLevel(riskScore) === "LOW") {
            // Escalate score to MEDIUM band — label re-derives from score at end
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

    // NOTE: Trusted domain final override is applied AFTER fake login + OCR
    // (see ABSOLUTE FINAL TRUST OVERRIDE block below) so no layer can re-escalate.

    // ─── FAKE LOGIN FORM DETECTION ENGINE ────────────────────────────────────
    // Applied AFTER trusted safety net so trusted sites are fully immune.
    const loginSignals = [];
    let credentialRiskScore = 0;
    let fakeLoginDetected = false;

    if (!isTrustedBrand && domLoginSignals && domLoginSignals.hasLoginForm !== undefined) {
      const d = domLoginSignals;

      // Rule 1: Password field exists
      if (d.passwordFieldCount >= 1) {
        credentialRiskScore += 35;
        loginSignals.push("Password input field detected on page");
      }

      // Rule 2: Email/username + password combo
      if (d.credFieldCount >= 1 && d.passwordFieldCount >= 1) {
        credentialRiskScore += 25;
        loginSignals.push("Email/username and password fields present together (credential combo)");
      }

      // Rule 3: Suspicious submit buttons
      if (d.suspiciousButtonCount >= 1) {
        credentialRiskScore += 15;
        loginSignals.push(`Suspicious authentication button detected (e.g. 'Login', 'Verify', 'Unlock')`);
      }

      // Rule 4: Brand word in page but domain not official — brand/login mismatch
      if (d.brandsInPageText && d.brandsInPageText.length > 0 && !isTrustedBrand) {
        const brandList = d.brandsInPageText.slice(0, 3).join(', ');
        credentialRiskScore += 40;
        loginSignals.push(`Brand names detected in page content (${brandList}) but domain is not an official source`);
      }

      // Rule 5: Hidden / obfuscated forms
      if (d.hiddenFormCount >= 1) {
        credentialRiskScore += 20;
        loginSignals.push(`${d.hiddenFormCount} hidden or offscreen form(s) detected`);
      }

      // Rule 6: Multiple password fields
      if (d.passwordFieldCount >= 2) {
        credentialRiskScore += 15;
        loginSignals.push(`Multiple password fields (${d.passwordFieldCount}) — possible credential cloning`);
      }

      // Rule 7: External form action
      if (d.externalActionCount >= 1) {
        credentialRiskScore += 35;
        loginSignals.push("Form posts credentials to an external domain (data exfiltration)");
      }

      // Rule 8: Thin credential trap
      if (d.hasLoginForm && d.pageTextLength < 1500) {
        credentialRiskScore += 20;
        loginSignals.push("Login form on a page with very little content (credential trap pattern)");
      }

      // Threshold: flag if credential sub-score is high enough
      fakeLoginDetected = credentialRiskScore >= 50;

      // Merge into main risk score only — riskLevel re-derives from score at end
      if (fakeLoginDetected) {
        const contribution = Math.min(60, credentialRiskScore);
        riskScore = Math.min(100, riskScore + contribution);
        addLog('danger', `Credential harvesting form detected (Risk +${contribution})`);
      }
    }

    // ─── OCR SCREENSHOT TEXT DETECTION ────────────────────────────────────────
    // Reads visible text from the screenshot image (catches dynamically rendered
    // or canvas-based phishing pages that hide content from DOM/HTML inspection).
    let ocrDetectedText = "";
    let ocrSignals = [];
    let ocrRiskScore = 0;

    const OCR_PHRASES = [
      "verify your account", "account suspended", "urgent action required",
      "claim reward", "payment failed", "kyc update", "security alert",
      "login expired", "confirm identity", "bank verification",
      "gift card", "lottery winner", "limited time", "click below",
      "reset password", "act now", "account blocked", "verify now",
      "congratulations you won", "free gift", "claim your prize",
    ];

    try {
      addLog('info', 'Initializing Tesseract.js OCR to scan screenshot text');
      // Race against a 20s timeout — OCR must not block the full response
      const ocrTimeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('OCR timeout after 20s')), 20000)
      );

      const ocrRun = (async () => {
        const worker = await createWorker('eng', 1, {
          logger: () => {}, // Silence progress logs
          errorHandler: () => {},
        });
        try {
          const { data: { text } } = await worker.recognize(screenshotBuffer);
          return text || "";
        } finally {
          await worker.terminate();
        }
      })();

      const rawOcrText = await Promise.race([ocrRun, ocrTimeout]);
      ocrDetectedText = rawOcrText.toLowerCase().replace(/\s+/g, ' ').trim().slice(0, 500);
      addLog('success', 'OCR extraction completed');

      // Match against phishing phrase list
      const foundOcrPhrases = OCR_PHRASES.filter(p => ocrDetectedText.includes(p));
      ocrSignals = foundOcrPhrases;

      // Trusted domains need 4+ OCR hits to register any score (very high bar)
      const phraseCount = foundOcrPhrases.length;
      const ocrThreshold = isTrustedBrand ? 4 : 1;

      // Trusted domains: OCR signals are purely informational — zero score contribution
      if (isTrustedBrand) {
        ocrRiskScore = 0;
        if (isDev) console.error(`[CIVIX] OCR: trusted domain — ${phraseCount} phrase(s) noted as informational only`);
      } else {
        if (phraseCount >= ocrThreshold) {
          if (phraseCount >= 4)      ocrRiskScore = 40;
          else if (phraseCount >= 2) ocrRiskScore = 25;
          else                       ocrRiskScore = 10;
          // Only update score — riskLevel re-derives from score at the very end
          riskScore = Math.min(100, riskScore + ocrRiskScore);
          addLog('warning', `OCR found ${phraseCount} suspicious phishing phrase(s) in screenshot`);
        }
      }

      if (isDev) console.error(`[CIVIX] OCR: ${phraseCount} phrase(s) found, ocrRiskScore=${ocrRiskScore}`);
    } catch (ocrErr) {
      // OCR failure is non-fatal — scan continues normally
      if (isDev) console.error('[CIVIX] OCR failed (non-fatal):', ocrErr.message);
    }

    // ─── ABSOLUTE FINAL TRUST OVERRIDE ───────────────────────────────────────
    // This runs LAST — after Gemini, Safe Browsing, fake login, and OCR.
    // Nothing above can make a trusted domain return HIGH or MEDIUM
    // except the two explicitly allowed exceptions:
    //   1. Google Safe Browsing produced a confirmed malicious hit
    //   2. A form on the trusted page posts credentials to a completely different external domain
    if (isTrustedBrand) {
      const hasSafeBrowsingHit = reasons.some(r => r.includes("Safe Browsing"));
      const hasExternalExfiltration = loginSignals.some(s => s.includes("external domain"));
      const isGenuineThreat = hasSafeBrowsingHit || hasExternalExfiltration;

      if (!isGenuineThreat) {
        // Lock to LOW: cap score, clear warning-level flags, reset riskLevel
        riskScore = Math.min(riskScore, 25);
        riskLevel = "LOW";
        fakeLoginDetected = false;

        // ── BADGE SANITIZATION ──────────────────────────────────────────────
        // Replace all noisy heuristic signals with clean, user-friendly trust signals.
        // Badges like "Suspicious URL", "Odd Domain Pattern", "Credential Harvesting"
        // are technically correct for any login page but actively mislead users on
        // official domains (accounts.google.com legitimately has a login form).
        const NOISY_PATTERNS = [
          "Suspicious URL", "URL path", "hyphens", "numbers", "long domain",
          "password input", "credential", "Credential", "Email input",
          "form language", "Urgency", "urgency", "Phishing content",
          "hidden fields", "script", "external domain", "external link",
          "Sensitive data", "Scam", "scam", "landing page", "readable text",
          "Not using HTTPS",
        ];

        // Filter reasons to keep only non-noisy entries
        const cleanReasons = reasons.filter(r =>
          !NOISY_PATTERNS.some(p => r.includes(p))
        );

        // Ensure the canonical trust signal is always present
        if (!cleanReasons.some(r => r.includes("Trusted") || r.includes("trusted"))) {
          cleanReasons.push("Recognized trusted official domain");
        }
        // Add HTTPS signal only if the connection actually is HTTPS
        if (url.startsWith("https://")) {
          cleanReasons.push("Verified secure HTTPS connection");
        }

        // Replace the reasons array in-place
        reasons.length = 0;
        reasons.push(...cleanReasons);

        // Clear credential harvesting and OCR signals — they are informational only
        loginSignals.length = 0;
        ocrSignals.length = 0;
        ocrRiskScore = 0;
        credentialRiskScore = 0;

        explanation = `This is a trusted official domain:\n• Login forms and authentication pages on verified domains are expected and safe\n• No malicious signals were detected outside of normal login page behavior\n\nAlways ensure you are on the correct domain before entering credentials.`;
        addLog('info', 'ABSOLUTE TRUST OVERRIDE applied — forced LOW + badge sanitization');
        if (isDev) console.error(`[CIVIX] ABSOLUTE TRUST OVERRIDE applied — forced LOW + badge sanitization for trusted root`);
      } else {
        addLog('warning', 'TRUST OVERRIDE skipped — genuine threat detected');
        if (isDev) console.error(`[CIVIX] TRUST OVERRIDE skipped — genuine threat detected: SB=${hasSafeBrowsingHit}, ExternalExfil=${hasExternalExfiltration}`);
      }
    }

    addLog('info', 'Finalizing risk classifications and packing report');

    // ─── DEFINITIVE FINAL CLASSIFICATION ────────────────────────────────────
    // After every score mutation (heuristics, dampening, OCR, fake login, trust caps,
    // trust override), recompute riskLevel from the actual final number.
    // This is the one and only place where riskLevel is written to the output.
    const finalScore = Math.min(100, Math.max(0, Math.round(riskScore)));
    const finalLevel = scoreToLevel(finalScore);

    // ─── RISK CATEGORY INTELLIGENCE ─────────────────────────────────────────
    let threatCategory = "Unknown";
    
    if (finalLevel === "LOW") {
      if (isTrustedBrand) threatCategory = "Verified Official Brand";
      else if (isLegitInstitution) threatCategory = "Legitimate Institution";
      else threatCategory = "Safe / Low Risk";
    } else {
      if (isBlocked) {
        threatCategory = "Evasion / Blocked Analysis";
      } else if (reasons.some(r => r.includes("Safe Browsing"))) {
        threatCategory = "Known Malicious / Blocklisted";
      } else if (isTyposquat || isBrandMisuse) {
        threatCategory = "Brand Impersonation / Typosquatting";
      } else if (fakeLoginDetected || reasons.some(r => r.includes("exfiltration") || r.includes("Credential"))) {
        threatCategory = "Credential Harvester";
      } else if (isScamPage || reasons.some(r => r.includes("Scam/manipulation") || r.includes("Urgency"))) {
        threatCategory = "Scam / Deceptive Warning";
      } else {
        threatCategory = "Suspicious Metadata / Generic Risk";
      }
    }

    // Sync explanation if label changed from intermediate value
    if (finalLevel !== riskLevel && !isTrustedBrand) {
      if (finalLevel === "HIGH") {
        explanation = `This website is highly suspicious based on multiple phishing indicators:\\n• Multiple domain and content risk signals accumulated above the high-risk threshold\\n\\nUsers should avoid interacting with this site entirely.`;
      } else if (finalLevel === "MEDIUM") {
        explanation = `This website shows several suspicious characteristics that warrant caution:\\n• Some elements resemble phishing behavior\\n\\nProceed with caution and avoid sharing sensitive information.`;
      } else {
        explanation = `This website appears legitimate:\\n• No strong phishing indicators detected\\n• Domain and content are consistent with expected behavior\\n\\nHowever, always verify before sharing sensitive information.`;
      }
    }

    if (isDev) console.error(`[CIVIX] FINAL: score=${finalScore} level=${finalLevel} (was riskLevel=${riskLevel})`);

    const result = {
      screenshot: screenshotBuffer.toString("base64"),
      warning: isBlocked ? "Site blocked sandbox or prevented secure analysis" : null,
      analysis: {
        riskScore: finalScore,
        riskLevel: finalLevel,
        reasons,
        explanation,
        isBlocked,
        isTrustedBrand,
        isLegitInstitution,
        fakeLoginDetected,
        loginSignals,
        credentialRiskScore,
        ocrDetectedText,
        ocrSignals,
        ocrRiskScore,
        threatCategory,
      }
    };

    result.logs = logs;
    addLog('success', 'Analysis complete. Constructing final security report.');

    console.log(JSON.stringify(result));

  } catch (err) {
    if (browser) {
      try { await browser.close(); } catch {}
    }
    
    addLog('danger', `Critical sandbox error: ${err.message}`);
    // Output valid JSON even on strict failure
    console.log(JSON.stringify({ 
      error: err.message || "Unknown error inside Playwright script",
      logs 
    }));
    process.exit(1);
  }
})();
