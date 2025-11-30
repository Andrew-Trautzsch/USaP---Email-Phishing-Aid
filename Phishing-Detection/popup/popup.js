// popup/popup.js

const analyzeBtn  = document.getElementById("analyzeBtn");
const scrapeBtn   = document.getElementById("scrapeBtn");
const previewBtn  = document.getElementById("previewBtn");

const status      = document.getElementById("status");
const downloadLink = document.getElementById("downloadLink");
const previewBox  = document.getElementById("jsonPreview");

const analysisBox   = document.getElementById("analysis");
const lvl1          = document.getElementById("level1");
const lvl2          = document.getElementById("level2");
const lvl3Content   = document.getElementById("level3Content");

// ---------- Helpers ----------

function resetView() {
  downloadLink.style.display = "none";
  previewBox.style.display = "none";
  analysisBox.style.display = "none";
  lvl1.innerHTML = "";
  lvl2.innerHTML = "";
  lvl3Content.innerHTML = "";
}

// Render the 3-level explanation
function renderAnalysis(analysis, email) {
  const { trustScore, riskLevel, reasons, suspiciousLinks } = analysis;

  analysisBox.style.display = "block";

  // Level 1 – overall judgement
  const riskClass =
    riskLevel === "high" ? "risk-high" :
    riskLevel === "medium" ? "risk-medium" :
    "risk-low";

  lvl1.innerHTML = `
    <div>
      <span class="risk-badge ${riskClass}">
        Risk: ${riskLevel.toUpperCase()}
      </span>
    </div>
    <div>Trust score: <strong>${trustScore}</strong> (0 = very risky, 1 = very trustworthy)</div>
    <div style="margin-top:4px;">
      Level 1: This email is judged <strong>${riskLevel.toUpperCase()}</strong> risk overall.
    </div>
  `;

  // Level 2 – concise reasons
  if (!reasons || reasons.length === 0) {
    lvl2.innerHTML = `
      <div style="margin-top:6px;">
        <strong>Level 2:</strong> No obvious red flags found.
      </div>`;
  } else {
    const items = reasons.map(r => `<li>${r}</li>`).join("");
    lvl2.innerHTML = `
      <div style="margin-top:6px;">
        <strong>Level 2:</strong> Key reasons for this judgement:
        <ul>${items}</ul>
      </div>
    `;
  }

  // Level 3 – deep dive: links, headers, etc.
  const blocks = [];

  if (suspiciousLinks && suspiciousLinks.length) {
    blocks.push(`<h4>Suspicious links (${suspiciousLinks.length})</h4>`);
    suspiciousLinks.forEach((link, idx) => {
      const reasonsHtml = (link.reasons || [])
        .map(r => `<li>${r}</li>`).join("");
      blocks.push(`
        <div class="link-block">
          <div><strong>Link ${idx + 1}</strong></div>
          <div>Domain: <code>${link.domain || "(unknown)"}</code></div>
          <div>URL: <code>${link.href}</code></div>
          <div>Why it looks suspicious:</div>
          <ul>${reasonsHtml}</ul>
        </div>
      `);
    });
  }

  // Small header summary section
  const headers = email.headers || {};
  const authResults = (headers["authentication-results"] || []).join(" ");

  blocks.push(`
    <h4>Header signals</h4>
    <div><strong>authentication-results:</strong></div>
    <pre class="header-block">${authResults || "(none found)"}</pre>
  `);


  lvl3Content.innerHTML = blocks.join("");
}

// ---------- Scrape helpers (existing behaviour) ----------

async function scrapeAndHandle({ download = true, preview = false } = {}) {
  resetView();
  status.textContent = "Scraping selected message…";

  try {
    const resp = await browser.runtime.sendMessage({ cmd: "scrapeSelected" });
    if (!resp) throw new Error("No response from background script");
    if (resp.error) {
      status.textContent = "Error: " + resp.error;
      return;
    }

    const obj = resp.data;
    const jsonStr = JSON.stringify(obj, null, 2);

    if (preview) {
      previewBox.textContent = jsonStr;
      previewBox.style.display = "block";
    }

    if (download) {
      const filename = `${(obj.subject || "message")
        .replace(/[\\/:*?"<>|]/g, "_")
        .slice(0, 60)
      }_${(new Date()).toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;

      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.style.display = "none";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      status.textContent = "JSON file saved locally.";
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    } else {
      status.textContent = "Scrape complete.";
    }
  } catch (e) {
    console.error(e);
    status.textContent = "Exception: " + e.message;
  }
}

// ---------- Analyze button ----------

async function analyzeEmail() {
  // Clear previous UI bits
  resetView();
  status.textContent = "Scraping and analyzing selected message…";

  try {
    // 1) Ask background.js to scrape + analyze the currently selected message
    const resp = await browser.runtime.sendMessage({ cmd: "analyzeSelected" });

    if (!resp) {
      status.textContent = "Error: no response from background script.";
      return;
    }
    if (!resp.ok || resp.error) {
      status.textContent = "Error: " + (resp.error || "Analysis failed.");
      return;
    }

    // 2) Show the three-level explanation in the popup
    renderAnalysis(resp.analysis, resp.data);
    status.textContent = "Analysis complete.";

    // 3) Tell the message-display content script to show/update the banner
    try {
      const tabs = await browser.mailTabs.query({
        active: true,
        currentWindow: true,
      });

      if (tabs && tabs.length) {
        await browser.tabs.sendMessage(tabs[0].id, {
          type: "phishAnalysis",
          analysis: resp.analysis,
        });
      }
    } catch (e) {
      // Not fatal if the banner can't be updated; popup still works.
      console.warn("Could not send banner update:", e);
    }
  } catch (e) {
    console.error("analyzeEmail failed:", e);
    status.textContent = "Exception during analysis: " + e.message;
  }
}


// ---------- Wire up buttons ----------

analyzeBtn.addEventListener("click", () => analyzeEmail());
scrapeBtn.addEventListener("click", () =>
  scrapeAndHandle({ download: true, preview: false })
);
previewBtn.addEventListener("click", () =>
  scrapeAndHandle({ download: false, preview: true })
);
