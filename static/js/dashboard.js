const urlInput    = document.getElementById("urlInput");
const scanBtn     = document.getElementById("scanBtn");
const logSection  = document.getElementById("logSection");
const terminalLog = document.getElementById("terminalLog");
const resultsGrid = document.getElementById("resultsGrid");
const statusLabel = document.getElementById("statusLabel");

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

function log(text, type = "info") {
  const line = document.createElement("span");
  line.className = `log-${type}`;
  line.textContent = `[${new Date().toTimeString().slice(0, 8)}] ${text}`;
  terminalLog.appendChild(line);
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

async function startScan() {
  const rawUrl = urlInput.value.trim();
  if (!rawUrl) { urlInput.focus(); return; }

  terminalLog.innerHTML = "";
  logSection.style.display = "block";
  resultsGrid.style.display = "none";
  scanBtn.disabled = true;
  statusLabel.textContent = "SCANNING...";

  log(`Target: ${rawUrl}`);
  log("Running SSL analysis...");

  try {
    const response = await fetch("/api/ssl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    log("Done!", "ok");

    renderSSL(data);

    resultsGrid.style.display = "flex";
    statusLabel.textContent = "COMPLETE";

  } catch (err) {
    log(`Error: ${err.message}`, "error");
    statusLabel.textContent = "ERROR";
  } finally {
    scanBtn.disabled = false;
  }
}

function renderSSL(data) {
  const body = document.getElementById("sslBody");
  const status = document.getElementById("sslStatus");

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }

  const daysClass = data.days_remaining > 30 ? "ok" : data.days_remaining > 7 ? "warn" : "bad";

  status.textContent = data.is_expired ? "EXPIRED" : `${data.days_remaining} days left`;

  body.innerHTML = `
    <div class="data-row">
      <span class="data-key">Issued To</span>
      <span class="data-val">${esc(data.issued_to)}</span>
    </div>
    <div class="data-row">
      <span class="data-key">Issued By</span>
      <span class="data-val">${esc(data.issued_by)}</span>
    </div>
    <div class="data-row">
      <span class="data-key">Valid From</span>
      <span class="data-val">${esc(data.valid_from)}</span>
    </div>
    <div class="data-row">
      <span class="data-key">Valid Until</span>
      <span class="data-val">${esc(data.valid_until)}</span>
    </div>
    <div class="data-row">
      <span class="data-key">Days Remaining</span>
      <span class="data-val ${daysClass}">${data.days_remaining}</span>
    </div>
    <div class="data-row">
      <span class="data-key">Expired</span>
      <span class="data-val ${data.is_expired ? 'bad' : 'ok'}">${data.is_expired ? "YES" : "NO"}</span>
    </div>`;
}

function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
