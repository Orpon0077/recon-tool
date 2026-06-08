// ── Dashboard Controller ───────────────────────────────────
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
  log("Running Security Headers analysis...");
  log("Running Port Scan... (This may take a moment)");
  log("Taking screenshot... (This may take a moment)");

  try {
    // ── SSL Analysis ─────────────────────────────────────
    const sslResponse = await fetch("/api/ssl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });
    if (!sslResponse.ok) throw new Error(`SSL API error: ${sslResponse.status}`);
    const sslData = await sslResponse.json();
    log("SSL analysis done!", "ok");

    // ── Security Headers Analysis ─────────────────────────
    const secResponse = await fetch("/api/security-headers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });
    if (!secResponse.ok) throw new Error(`Security Headers API error: ${secResponse.status}`);
    const secData = await secResponse.json();
    log("Security Headers analysis done!", "ok");

    // ── Port Scanning ─────────────────────────────────────
    const portsResponse = await fetch("/api/ports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });
    if (!portsResponse.ok) throw new Error(`Port Scan API error: ${portsResponse.status}`);
    const portsData = await portsResponse.json();
    log(`Port scan done! ${portsData.total_open} open ports found.`, "ok");

    // ── Screenshot ────────────────────────────────────────
    const ssResponse = await fetch("/api/screenshot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });
    if (!ssResponse.ok) throw new Error(`Screenshot API error: ${ssResponse.status}`);
    const ssData = await ssResponse.json();
    log("Screenshot done!", "ok");

    // ── Results দেখাও ────────────────────────────────────
    renderSSL(sslData);
    renderSecurity(secData);
    renderPorts(portsData);
    renderScreenshot(ssData);

    resultsGrid.style.display = "grid";
    statusLabel.textContent = "COMPLETE";
    log("All done!", "ok");

  } catch (err) {
    log(`Error: ${err.message}`, "error");
    statusLabel.textContent = "ERROR";
  } finally {
    scanBtn.disabled = false;
  }
}

// ── SSL Result দেখাও ──────────────────────────────────────
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

// ── Security Headers Result দেখাও ─────────────────────────
function renderSecurity(data) {
  const body = document.getElementById("securityBody");
  const status = document.getElementById("securityStatus");

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }

  const scoreClass = data.score >= 70 ? "ok" : data.score >= 40 ? "warn" : "bad";
  status.textContent = `Score: ${data.score}/100`;

  const present = data.present || {};
  const missing = data.missing || [];

  const presentHtml = Object.entries(present).map(([header, value]) => `
    <div class="data-row">
      <span class="data-key ok">✓ ${esc(header)}</span>
      <span class="data-val">${esc(value.slice(0, 50))}${value.length > 50 ? '...' : ''}</span>
    </div>`).join("");

  const missingHtml = missing.map(header => `
    <div class="data-row">
      <span class="data-key bad">✗ ${esc(header)}</span>
      <span class="data-val bad">Missing</span>
    </div>`).join("");

  body.innerHTML = `
    <div class="score-box ${scoreClass}">Security Score: ${data.score}/100</div>
    ${presentHtml}
    ${missingHtml}`;
}

// ── Port Scan Result দেখাও ────────────────────────────────
function renderPorts(data) {
  const body = document.getElementById("portsBody");
  const status = document.getElementById("portsStatus");

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }

  status.textContent = `${data.total_open} open ports`;

  if (data.total_open === 0) {
    body.innerHTML = `<p class="no-data">No open ports found.</p>`;
    return;
  }

  const rows = data.open_ports.map(p => `
    <tr>
      <td><span class="port-num">${p.port}</span></td>
      <td>${esc(p.service)}</td>
      <td><span class="port-open">${esc(p.state)}</span></td>
      <td>${esc(p.version)}</td>
    </tr>`).join("");

  body.innerHTML = `
    <table class="port-table">
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>State</th>
          <th>Version / Banner</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── Screenshot Result দেখাও ───────────────────────────────
function renderScreenshot(data) {
  const body = document.getElementById("screenshotBody");
  const status = document.getElementById("screenshotStatus");

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }

  if (!data.screenshot_path) {
    body.innerHTML = `<p class="no-data">No screenshot captured.</p>`;
    status.textContent = "N/A";
    return;
  }

  status.textContent = "Captured";

  body.innerHTML = `
    <div class="screenshot-wrap">
      <img src="/static/${esc(data.screenshot_path)}" alt="Screenshot of ${esc(data.url)}"
           onerror="this.parentElement.innerHTML='<p class=no-data>Image failed to load.</p>'" />
      <div class="screenshot-overlay">${esc(data.url)}</div>
    </div>`;
}

// ── XSS থেকে রক্ষা করো ────────────────────────────────────
function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}