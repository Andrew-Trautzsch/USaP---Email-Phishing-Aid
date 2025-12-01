// content/banner.js
(() => {
  let analysisCache = null;

  function describeRisk(risk) {
    if (risk === "high")
      return "High risk – treat this as suspicious unless you are sure it is legitimate.";
    if (risk === "medium")
      return "Medium risk – some warning signs present, verify before clicking links.";
    return "Low risk – no major red flags detected, but still use normal caution.";
  }

  function renderDetails(banner, analysis, email) {
    const details = banner.querySelector(".phish-details");
    const { riskLevel, trustScore, reasons, suspiciousLinks } = analysis;

    // Level 2 block
    let level2Html;
    if (reasons && reasons.length) {
        level2Html = `
        <div class="phish-level">
            <h4>Level 2: Key reasons</h4>
            <ul>${reasons.map((r) => `<li>${r}</li>`).join("")}</ul>
        </div>
        `;
    } else {
        level2Html = `
        <div class="phish-level">
            <h4>Level 2</h4>
            <div>No obvious red flags found.</div>
        </div>
        `;
    }

    // Header info
    const headers = email.headers || {};
    const authResults = (headers["authentication-results"] || []).join(" ");

    // Links block
    let linksHtml = "";
    if (suspiciousLinks && suspiciousLinks.length) {
        linksHtml = `
        <h4>Suspicious links (${suspiciousLinks.length})</h4>
        ${suspiciousLinks
            .map(
            (link, i) => `
            <div style="margin-top:4px;">
            <div><strong>Link ${i + 1}</strong></div>
            <div>Domain: <code>${link.domain || "(unknown)"}</code></div>
            <div style="font-size:11px; word-break:break-all;">URL: ${
                link.href
            }</div>
            <div>Why it looks suspicious:</div>
            <ul>${(link.reasons || [])
                .map((r) => `<li>${r}</li>`)
                .join("")}</ul>
            </div>
        `
            )
            .join("")}
        `;
    }

    details.innerHTML = `
        <div class="phish-level">
        <strong>Level 1:</strong> This email is judged
        <strong>${riskLevel.toUpperCase()}</strong> risk overall.<br/>
        Trust score: <strong>${trustScore}</strong> (0 = very risky, 1 = very trustworthy)
        </div>
        ${level2Html}
        <div class="phish-level">
        
        <div><strong>Level 3: Authentication Results</strong></div>
        <pre class="phish-header-block">${authResults || "(none found)"}</pre>
        ${linksHtml}
        </div>
    `;
  }


  function updateBannerVisual(banner, analysis) {
    const badge = banner.querySelector(".phish-badge");
    const text = banner.querySelector(".phish-text");
    const toggle = banner.querySelector(".phish-toggle");
    const risk = analysis.riskLevel || "low";

    banner.dataset.state = "done";
    banner.dataset.risk = risk;

    badge.textContent = `Risk: ${risk.toUpperCase()}`;
    text.textContent = describeRisk(risk);
    toggle.textContent = "Show details ▾";
  }

  async function runAnalysisFromBanner(banner) {
    const badge = banner.querySelector(".phish-badge");
    const text = banner.querySelector(".phish-text");

    badge.textContent = "Analyzing…";
    text.textContent = "Checking this message for phishing signals…";

    try {
      const resp = await browser.runtime.sendMessage({ cmd: "analyzeSelected" });

      if (!resp || !resp.ok || resp.error) {
        badge.textContent = "Error";
        text.textContent =
          resp && resp.error
            ? resp.error
            : "Could not analyze this message.";
        return;
      }

      analysisCache = resp.analysis;

      updateBannerVisual(banner, resp.analysis);
      renderDetails(banner, resp.analysis, resp.data);
    } catch (e) {
      console.error("banner analysis failed:", e);
      badge.textContent = "Error";
      text.textContent = "Exception while analyzing: " + e.message;
    }
  }

  function injectBanner() {
    if (!document.body) return;

    let banner = document.getElementById("phish-banner");
    if (banner) return; // already added

    banner = document.createElement("div");
    banner.id = "phish-banner";
    banner.dataset.state = "idle";
    banner.dataset.risk = "none";

    banner.innerHTML = `
      <div class="phish-banner-main">
        <span class="phish-badge">Analyze email</span>
        <span class="phish-text">
          Click to analyze this message for phishing risk.
        </span>
        <span class="phish-toggle">Show details ▾</span>
      </div>
      <div class="phish-details"></div>
    `;

    const first = document.body.firstElementChild;
    if (first) {
      document.body.insertBefore(banner, first);
    } else {
      document.body.appendChild(banner);
    }

    banner.addEventListener("click", () => {
    const toggle = banner.querySelector(".phish-toggle");

    if (!analysisCache) {
        // First click: run analysis, keep details collapsed
        runAnalysisFromBanner(banner);
    } else {
        // Later clicks: just toggle details
        banner.classList.toggle("open");
        if (banner.classList.contains("open")) {
        toggle.textContent = "Hide details ▴";
        } else {
        toggle.textContent = "Show details ▾";
        }
    }
    });
  }

  // Make sure we run after the message body exists
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", injectBanner);
  } else {
    injectBanner();
  }
})();
