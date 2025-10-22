// popup/popup.js
const scrapeBtn = document.getElementById("scrapeBtn");
const previewBtn = document.getElementById("previewBtn");
const status = document.getElementById("status");
const downloadLink = document.getElementById("downloadLink");
const previewBox = document.getElementById("jsonPreview");

async function scrapeAndHandle({ download = true, preview = false } = {}) {
  status.textContent = "Scraping selected message…";
  downloadLink.style.display = "none";
  previewBox.style.display = "none";
  try {
    const resp = await browser.runtime.sendMessage({ cmd: "scrapeSelected" });
    if (!resp) throw new Error("No response");
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
      // Create a blob and use the downloads API if available, else create an anchor fallback.
      try {
        const filename = `${(obj.subject || "message").replace(/[\\/:*?"<>|]/g, "_").slice(0,60)}_${(new Date()).toISOString().slice(0,19).replace(/[:T]/g,'-')}.json`;
        const blob = new Blob([jsonStr], { type: "application/json" });
        // Try using browser.downloads if permission exists
        if (browser.downloads && browser.downloads.download) {
          const url = URL.createObjectURL(blob);
          const downloadId = await browser.downloads.download({ url: url, filename: filename, saveAs: true });
          status.textContent = "Download started.";
          // Revoke after short time
          setTimeout(() => URL.revokeObjectURL(url), 30000);
        } else {
          // Fallback: create an anchor and click it (should open Save dialog in many environments)
          const url = URL.createObjectURL(blob);
          downloadLink.href = url;
          downloadLink.download = filename;
          downloadLink.textContent = "Click here to download JSON";
          downloadLink.style.display = "inline-block";
          status.textContent = "Ready to download (use the link).";
          // Revoke later
          setTimeout(() => {
            try { URL.revokeObjectURL(url); } catch(e){}
          }, 30000);
        }
      } catch (e) {
        console.error("Download failed, falling back to link:", e);
        // fallback to link
        downloadLink.href = "data:application/json;charset=utf-8," + encodeURIComponent(jsonStr);
        downloadLink.download = "message.json";
        downloadLink.style.display = "inline-block";
        status.textContent = "Download link ready (fallback).";
      }
    } else {
      status.textContent = "Scrape complete.";
    }
  } catch (e) {
    console.error(e);
    status.textContent = "Exception: " + e.message;
  }
}

scrapeBtn.addEventListener("click", () => scrapeAndHandle({ download: true, preview: false }));
previewBtn.addEventListener("click", () => scrapeAndHandle({ download: false, preview: true }));
