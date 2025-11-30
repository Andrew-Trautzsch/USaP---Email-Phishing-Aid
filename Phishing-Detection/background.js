// background.js
console.log("Background started (scraper ready)");

// Register our message display script so Thunderbird injects it
// into every displayed email.
try {
  messenger.messageDisplayScripts.register({
    js: [{ file: "content/banner.js" }],
    css: [{ file: "content/banner.css" }],
  });
  console.log("Phishing banner script registered.");
} catch (e) {
  console.error("Failed to register message display script:", e);
}


// Utility: recursively find first text/plain part
function extractPlainFromParts(parts) {
  if (!parts) return null;
  for (const p of parts) {
    if (p.contentType && p.contentType.startsWith("text/plain")) {
      if (typeof p.body === "string" && p.body.length) return p.body;
      // sometimes body is in p.body or needs decoding; try p.body
    }
    if (p.parts) {
      const r = extractPlainFromParts(p.parts);
      if (r) return r;
    }
  }
  return null;
}

// Utility: extract HTML part (first text/html)
function extractHtmlFromParts(parts) {
  if (!parts) return null;
  for (const p of parts) {
    if (p.contentType && p.contentType.startsWith("text/html")) {
      if (typeof p.body === "string" && p.body.length) return p.body;
    }
    if (p.parts) {
      const r = extractHtmlFromParts(p.parts);
      if (r) return r;
    }
  }
  return null;
}

// Utility: collect attachments metadata from parts
function collectAttachments(parts, out = []) {
  if (!parts) return out;
  for (const p of parts) {
    // heuristics: attachments often have filename or disposition
    if (p.name || p.filename || (p.contentType && !p.contentType.startsWith("text/"))) {
      out.push({
        partName: p.partName || null,
        name: p.name || p.filename || null,
        contentType: p.contentType || null,
        size: p.size || null
      });
    }
    if (p.parts) collectAttachments(p.parts, out);
  }
  return out;
}

// ---- Phishing risk scoring (JS port of score_email.py) ----

// Sets from your Python model
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co"]);
const BAD_TLDS   = new Set([".ru", ".xyz", ".top", ".click", ".shop"]);

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "click", "shop", "link", "ru", "cn", "work"
]);

const BRAND_KEYWORDS = [
  "google", "paypal", "microsoft", "apple", "amazon",
  "office", "outlook", "bank", "secure", "login"
];

function sigmoid(z) {
  return 1.0 / (1.0 + Math.exp(-z));
}

function domainFeatures(domain) {
  const d = (domain || "").toLowerCase();
  const feats = {};

  feats.len = d.length;
  feats.dot_count = (d.match(/\./g) || []).length;
  feats.hyphen_count = (d.match(/-/g) || []).length;
  feats.digit_count = (d.match(/\d/g) || []).length;
  feats.digit_ratio =
    feats.len ? feats.digit_count / feats.len : 0.0;

  const labels = d ? d.split(".") : [];
  feats.label_count = labels.length;
  const tld = labels.length ? labels[labels.length - 1] : "";
  feats.suspicious_tld = SUSPICIOUS_TLDS.has(tld) ? 1.0 : 0.0;

  feats.contains_brand_keyword = BRAND_KEYWORDS.some(k => d.includes(k)) ? 1.0 : 0.0;

  const vowels = "aeiou";
  const vowel_count = [...d].filter(c => vowels.includes(c)).length;
  feats.vowel_ratio = feats.len ? vowel_count / feats.len : 0.0;

  return feats;
}

function domainLegitimacyScore(domain) {
  const f = domainFeatures(domain);
  let z = 0.0;

  z += 0.5; // baseline "probably OK"
  if (f.suspicious_tld) {
    z += -2.0;
  }

  z += -1.0 * f.digit_ratio;
  z += -0.3 * f.hyphen_count;

  const short_len = Math.min(f.len, 20);
  z += 0.05 * short_len;
  if (f.len > 30) {
    z += -0.05 * (f.len - 30);
  }

  if (f.label_count > 4) {
    z += -0.4 * (f.label_count - 4);
  }

  z += 0.4 * f.contains_brand_keyword;

  return sigmoid(z);
}

function parseDomain(addr) {
  if (!addr || !addr.includes("@")) return "";
  return addr.split("@").slice(-1)[0].trim().toLowerCase();
}

function extractSenderDomains(email) {
  const headers = email.headers || {};

  let from_field = headers["from"] || email.author || [""];
  let reply_field = headers["reply-to"] || [""];
  let return_field = headers["return-path"] || [""];

  from_field = Array.isArray(from_field) ? from_field[0] : from_field;
  reply_field = Array.isArray(reply_field) ? reply_field[0] : reply_field;
  return_field = Array.isArray(return_field) ? return_field[0] : return_field;

  function safeExtract(addr) {
    if (typeof addr !== "string") return "";
    const parts = addr.split(/\s+/);
    if (!parts.length) return "";
    const last = parts[parts.length - 1].replace(/[<>]/g, "");
    return parseDomain(last);
  }

  return {
    fromDomain: safeExtract(from_field),
    replyDomain: safeExtract(reply_field),
    returnDomain: safeExtract(return_field),
  };
}

function evaluateLinksForScoring(email) {
  const suspicious_links = [];
  const links = email.links || [];

  for (const link of links) {
    const href = link.href || "";
    let domain = "";

    try {
      const url = new URL(href.startsWith("http") ? href : "http://" + href);
      domain = url.hostname.toLowerCase();
    } catch (e) {
      domain = "";
    }

    const reasons = [];

    if (href.startsWith("http://")) {
      reasons.push("uses HTTP instead of HTTPS");
    }

    if ([...SHORTENERS].some(s => domain.endsWith(s))) {
      reasons.push("URL shortener");
    }

    if ([...BAD_TLDS].some(tld => domain.endsWith(tld))) {
      reasons.push("suspicious TLD");
    }

    if (domain) {
      const score = domainLegitimacyScore(domain);
      if (score < 0.4) {
        reasons.push(`domain looks suspicious (score=${score.toFixed(2)})`);
      }
    }

    if (reasons.length) {
      suspicious_links.push({
        href,
        domain,
        reasons
      });
    }
  }

  return suspicious_links;
}

function scoreEmail(email) {
  const reasons = [];
  const headers = email.headers || {};

  // Auth headers (SPF / DKIM / DMARC)
  const auth = (headers["authentication-results"] || [])
    .join(" ")
    .toLowerCase();

  if (auth.includes("spf=fail")) {
    reasons.push("SPF failed");
  }
  if (auth.includes("dkim=fail") || auth.includes("dkim=none")) {
    reasons.push("DKIM missing or failed");
  }
  if (auth.includes("dmarc=fail")) {
    reasons.push("DMARC failed");
  }

  // Sender domains
  const { fromDomain, replyDomain } = extractSenderDomains(email);

  if (fromDomain) {
    const senderScore = domainLegitimacyScore(fromDomain);
    if (senderScore < 0.4) {
      reasons.push(
        `sender domain looks suspicious (score=${senderScore.toFixed(2)}): ${fromDomain}`
      );
    }
  }

  if (replyDomain && replyDomain !== fromDomain) {
    reasons.push("reply-to domain differs from sender");
  }

  // Body flags
  const body =
    (email.plainText || "") +
    (email.textFromHtml || "") +
    (email.rawSnippet || "");

  const bodyLower = body.toLowerCase();

  if (bodyLower.includes("external sender")) {
    reasons.push("external sender banner detected");
  }

  // Links
  const suspiciousLinks = evaluateLinksForScoring(email);
  if (suspiciousLinks.length) {
    reasons.push("one or more links appear suspicious");
  }

  // Trust score & risk level
  const MAX_RISK = 10;
  let trustScore = 1.0 - reasons.length / MAX_RISK;
  if (trustScore < 0.0) trustScore = 0.0;
  if (trustScore > 1.0) trustScore = 1.0;

  let risk = "low";
  if (trustScore < 0.3) risk = "high";
  else if (trustScore < 0.7) risk = "medium";

  return {
    trustScore: Number(trustScore.toFixed(2)),
    riskLevel: risk,
    reasons,
    suspiciousLinks
  };
}

// Extract text from small HTML by stripping tags. This is lightweight text extraction.
// It does not run scripts or load remote content.
function textFromHtml(html) {
  if (!html) return "";
  // Create a DOM in an offscreen manner using DOMParser (available in extension)
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");
    // remove script/style
    const scripts = doc.querySelectorAll("script, style, noscript");
    scripts.forEach(s => s.remove());
    const text = doc.body ? doc.body.innerText || doc.body.textContent : doc.documentElement.textContent;
    return text ? text.trim() : "";
  } catch (e) {
    // fallback: naive tag removal
    return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  }
}

// Extract links from HTML and plain text (regex for text)
function extractLinks(html, plain) {
  const links = [];
  // From HTML using DOMParser
  if (html) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");
      const anchors = doc.querySelectorAll("a[href]");
      anchors.forEach(a => {
        const href = a.getAttribute("href");
        const text = a.textContent ? a.textContent.trim() : null;
        // capture some surrounding context - here just the anchor text
        links.push({ href, text, contextSnippet: text ? text.slice(0, 200) : null });
      });
    } catch (e) {
      // ignore parse errors
    }
  }
  // From plain text with regex (find http(s) and mailto)
  if (plain) {
    const urlRegex = /((https?:\/\/|mailto:|www\.)[^\s<>"]+)/gi;
    let m;
    while ((m = urlRegex.exec(plain)) !== null) {
      const raw = m[1];
      // normalize: prefix http:// if starts with www.
      const href = raw.startsWith("www.") ? "http://" + raw : raw;
      links.push({ href, text: null, contextSnippet: plain.slice(Math.max(0, m.index - 40), Math.min(plain.length, m.index + 160)) });
    }
  }
  // Deduplicate by href (simple)
  const byHref = {};
  for (const l of links) {
    if (!l.href) continue;
    const key = l.href.trim();
    if (!byHref[key]) byHref[key] = l;
  }
  return Object.values(byHref);
}

// Main: gather message data for the first selected message
async function getFirstSelectedMessageScrape() {
  try {
    const sel = await browser.mailTabs.getSelectedMessages();
    if (!sel || !sel.messages || sel.messages.length === 0) {
      return { error: "No message selected" };
    }
    const header = sel.messages[0];
    const full = await browser.messages.getFull(header.id);

    // headers object is in full.headers (map of headerName -> [values])
    const headers = full.headers || {};

    // try to find text/plain and text/html
    const plain = extractPlainFromParts(full.parts) || full.body || "";
    const html = extractHtmlFromParts(full.parts) || "";

    const textFromHtmlStr = textFromHtml(html);

    const links = extractLinks(html, plain);

    const attachments = collectAttachments(full.parts || []);

    const messageJson = {
      id: header.id,
      messageId: (headers["message-id"] && headers["message-id"][0]) || null,
      threadId: header.threadId || null,
      subject: header.subject || null,
      author: header.author || header.from || null,
      to: (headers["to"] && headers["to"]) || null,
      cc: (headers["cc"] && headers["cc"]) || null,
      bcc: (headers["bcc"] && headers["bcc"]) || null,
      date: header.date || (headers["date"] && headers["date"][0]) || null,
      headers: headers,
      plainText: plain,
      html: html,
      textFromHtml: textFromHtmlStr,
      links: links,
      attachments: attachments,
      rawSnippet: (plain || textFromHtmlStr).slice(0, 1200),
      fetchedAt: new Date().toISOString()
    };

    return { ok: true, data: messageJson };
  } catch (e) {
    console.error("Error scraping message:", e);
    return { error: String(e) };
  }
}

// Listen for popup or other callers
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.cmd) return;

  // Existing: scrape only
  if (msg.cmd === "scrapeSelected") {
    (async () => {
      const result = await getFirstSelectedMessageScrape();
      sendResponse(result);
    })();
    return true;
  }

  // NEW: scrape + analyze
  if (msg.cmd === "analyzeSelected") {
    (async () => {
      const scrape = await getFirstSelectedMessageScrape();
      if (!scrape.ok) {
        sendResponse(scrape); // { error: ... }
        return;
      }
      const analysis = scoreEmail(scrape.data);
      sendResponse({
        ok: true,
        data: scrape.data,
        analysis
      });
    })();
    return true;
  }

  // existing hello handler, if you still want it
  if (msg.cmd === "hello") {
    sendResponse({ message: "Hello from background.js 👋" });
  }
});

