// background.js
console.log("Background started (scraper ready)");

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
  if (msg.cmd === "scrapeSelected") {
    // If we want to use async sendResponse, do it this way:
    (async () => {
      const result = await getFirstSelectedMessageScrape();
      sendResponse(result);
    })();
    return true; // keep channel open for async response
  }

  // existing hello handler
  if (msg.cmd === "hello") {
    sendResponse({ message: "Hello from background.js 👋" });
  }
});
