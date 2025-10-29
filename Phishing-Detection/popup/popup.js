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
      const filename = `${(obj.subject || "message").replace(/[\\/:*?"<>|]/g, "_").slice(0,60)}_${(new Date()).toISOString().slice(0,19).replace(/[:T]/g,'-')}.json`;
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);

      // Create a hidden <a> element to trigger the download manually
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      status.textContent = "JSON file saved locally.";
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    }
  } catch (e) {
    console.error(e);
    status.textContent = "Exception: " + e.message;
  }
}

scrapeBtn.addEventListener("click", () => scrapeAndHandle({ download: true, preview: false }));
previewBtn.addEventListener("click", () => scrapeAndHandle({ download: false, preview: true }));
