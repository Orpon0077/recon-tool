// ── Dashboard Controller ───────────────────────────────────
const urlInput    = document.getElementById("urlInput");
const scanBtn     = document.getElementById("scanBtn");
const logSection  = document.getElementById("logSection");
const terminalLog = document.getElementById("terminalLog");
const resultsGrid = document.getElementById("resultsGrid");
const statusLabel = document.getElementById("statusLabel");
const statusDot   = document.getElementById("statusDot");

// ── Check URL for scan_id on load ──
document.addEventListener("DOMContentLoaded", function() {
  const customRadio = document.getElementById("customPortRadio");
  const customInput = document.getElementById("customPorts");
  
  if (customRadio && customInput) {
    customRadio.addEventListener("change", function() {
      customInput.disabled = !this.checked;
    });
    customInput.disabled = !customRadio.checked;
  }
  
  // ── Check for scan_id in URL ──
  const urlParams = new URLSearchParams(window.location.search);
  const scanId = urlParams.get('scan_id');
  
  if (scanId) {
    console.log("Loading scan from URL:", scanId);
    // Small delay to ensure DOM is ready
    setTimeout(() => loadScan(scanId), 500);
  } else {
    loadHistory();
  }
});

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

function setStatus(state, text) {
  if (statusDot) statusDot.className = `status-dot ${state}`;
  if (statusLabel) statusLabel.textContent = text;
}

function log(text, type = "info") {
  if (!terminalLog) return;
  const line = document.createElement("span");
  line.className = `log-${type}`;
  line.textContent = `[${new Date().toTimeString().slice(0, 8)}] ${text}`;
  terminalLog.appendChild(line);
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

// ── Load History ──────────────────────────────────────────
async function loadHistory() {
  const historyList = document.getElementById("historyList");
  if (!historyList) return;
  
  try {
    historyList.innerHTML = `<div class="history-empty">Loading...</div>`;
    const response = await fetch("/api/history");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const scans = await response.json();
    
    if (!scans || scans.length === 0) {
      historyList.innerHTML = `<div class="history-empty">No scans yet. Run a scan!</div>`;
      return;
    }
    
    const last20 = scans.slice(0, 20);
    historyList.innerHTML = last20.map(scan => `
      <div class="history-item" onclick="loadScan('${scan.id}')">
        <div class="history-url">${esc(scan.url)}</div>
        <div class="history-time">${esc(scan.timestamp)}</div>
      </div>
    `).join("");
  } catch (err) {
    historyList.innerHTML = `<div class="history-empty">Error loading history</div>`;
  }
}

// ── Load Scan by ID ────────────────────────────────────────
async function loadScan(scanId) {
  try {
    console.log("Loading scan:", scanId);
    setStatus("loading", "LOADING...");
    
    const response = await fetch(`/api/history/${scanId}`);
    const data = await response.json();
    
    if (data.error) {
      console.error("Scan not found:", data.error);
      setStatus("error", "NOT FOUND");
      return;
    }
    
    console.log("Scan data:", data);
    
    if (!data.results) {
      console.error("No results in data");
      return;
    }
    
    // Show results grid
    if (resultsGrid) resultsGrid.style.display = "grid";
    if (logSection) logSection.style.display = "none";
    
    // Render all panels
    renderSSL(data.results.ssl);
    renderSecurity(data.results.security_headers);
    renderPorts(data.results.ports);
    renderScreenshot(data.results.screenshot);
    renderFirewall(data.results.firewall);
    renderTech(data.results.tech);
    renderCrawl(data.results.crawl);
    
    if (data.results.js_scanner) {
      renderJSScanner(data.results.js_scanner);
    }
    if (data.results.subdomains) {
      renderSubdomains(data.results.subdomains);
    }
    
    setStatus("done", "LOADED FROM HISTORY");
    
    // Update URL
    const url = new URL(window.location);
    url.searchParams.set('scan_id', scanId);
    window.history.replaceState({}, '', url);
    
  } catch (err) {
    console.error("Failed to load scan:", err);
    setStatus("error", "ERROR");
  }
}

// ── Main Scan Function ─────────────────────────────────────
async function startScan() {
  let rawUrl = urlInput.value.trim();
  if (!rawUrl) { urlInput.focus(); return; }

  let targetUrl = rawUrl;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const portOptionEl = document.querySelector('input[name="portOption"]:checked');
  const portOption = portOptionEl ? portOptionEl.value : "top1000";
  const customPortsEl = document.getElementById("customPorts");
  let customPorts = customPortsEl ? customPortsEl.value.trim() : "";
  
  if (customPorts === "") {
    customPorts = null;
  }

  if (terminalLog) terminalLog.innerHTML = "";
  if (logSection) logSection.style.display = "block";
  if (resultsGrid) resultsGrid.style.display = "none";
  if (scanBtn) scanBtn.disabled = true;
  
  setStatus("active", "SCANNING...");

  log(`Target: ${targetUrl}`);
  log(`Port option: ${portOption.toUpperCase()}`);
  if (customPorts) log(`Custom ports: ${customPorts}`);
  log("Running all modules...");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: targetUrl,
        port_option: portOption,
        custom_ports: customPorts,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      log(`API Error: ${response.status} - ${errorText}`, "error");
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    log("Main modules done!", "ok");
    log(`Saved to database. ID: ${data.scan_id}`, "ok");

    if (resultsGrid) resultsGrid.style.display = "grid";

    renderSSL(data.ssl);
    renderSecurity(data.security_headers);
    renderPorts(data.ports);
    renderScreenshot(data.screenshot);
    renderFirewall(data.firewall);
    renderTech(data.tech);
    renderCrawl(data.crawl);
    
    if (data.subdomains) {
      renderSubdomains(data.subdomains);
    }

    setStatus("loading", "WAITING FOR JS...");
    
    // ── JS Scanner ──
    log("Running JavaScript scanner...", "info");
    try {
      const jsResponse = await fetch("/api/js-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });
      const jsData = await jsResponse.json();
      
      if (jsData && !jsData.error) {
        log(`JS Scan: ${jsData.total_js_files || 0} JS files`, "ok");
        renderJSScanner(jsData);
      }
    } catch (jsErr) {
      log(`JS Scan failed: ${jsErr.message}`, "warn");
    }

    // ── Subdomain Discovery ──
    log("Running subdomain discovery...", "info");
    try {
      const subResponse = await fetch("/api/subdomains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });
      const subData = await subResponse.json();
      
      if (subData && !subData.error) {
        log(`Subdomains: ${subData.total_found || 0} found`, "ok");
        renderSubdomains(subData);
      }
    } catch (subErr) {
      log(`Subdomain discovery failed: ${subErr.message}`, "warn");
    }

    log("All modules complete! PDF ready.", "ok");
    setStatus("done", "COMPLETE");
    window._lastScanData = data;
    
    // Update URL with scan_id
    const url = new URL(window.location);
    url.searchParams.set('scan_id', data.scan_id);
    window.history.replaceState({}, '', url);
    
    loadHistory();
    
    const pdfBtn = document.getElementById("downloadPdfBtn");
    if (pdfBtn) {
      pdfBtn.style.display = "inline-block";
    }

  } catch (err) {
    log(`Error: ${err.message}`, "error");
    setStatus("error", "ERROR");
  } finally {
    if (scanBtn) scanBtn.disabled = false;
  }
}

// ── Render Functions ──────────────────────────────────────

function renderSSL(data) {
  const body = document.getElementById("sslBody");
  const status = document.getElementById("sslStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  const daysClass = data.days_remaining > 30 ? "ok" : data.days_remaining > 7 ? "warn" : "bad";
  if (status) status.textContent = data.is_expired ? "EXPIRED" : `${data.days_remaining} days left`;
  body.innerHTML = `
    <div class="data-row"><span class="data-key">Issued To</span><span class="data-val">${esc(data.issued_to)}</span></div>
    <div class="data-row"><span class="data-key">Issued By</span><span class="data-val">${esc(data.issued_by)}</span></div>
    <div class="data-row"><span class="data-key">Valid From</span><span class="data-val">${esc(data.valid_from)}</span></div>
    <div class="data-row"><span class="data-key">Valid Until</span><span class="data-val">${esc(data.valid_until)}</span></div>
    <div class="data-row"><span class="data-key">Days Remaining</span><span class="data-val ${daysClass}">${data.days_remaining}</span></div>
    <div class="data-row"><span class="data-key">Expired</span><span class="data-val ${data.is_expired ? 'bad' : 'ok'}">${data.is_expired ? "YES" : "NO"}</span></div>`;
}

function renderSecurity(data) {
  const body = document.getElementById("securityBody");
  const status = document.getElementById("securityStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  const scoreClass = data.score >= 70 ? "ok" : data.score >= 40 ? "warn" : "bad";
  if (status) status.textContent = `Score: ${data.score}/100`;
  const present = data.present || {};
  const missing = data.missing || [];
  const presentHtml = Object.entries(present).map(([header, value]) => `
    <div class="data-row"><span class="data-key ok">✓ ${esc(header)}</span><span class="data-val">${esc(value)}</span></div>`).join("");
  const missingHtml = missing.map(header => `
    <div class="data-row"><span class="data-key bad">✗ ${esc(header)}</span><span class="data-val bad">Missing</span></div>`).join("");
  body.innerHTML = `<div class="score-box ${scoreClass}">Security Score: ${data.score}/100</div>${presentHtml}${missingHtml}`;
}

function renderPorts(data) {
  const body = document.getElementById("portsBody");
  const status = document.getElementById("portsStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  if (status) status.textContent = `${data.total_open} open ports`;
  if (data.total_open === 0) {
    body.innerHTML = `<p class="no-data">No open ports found.</p>`;
    return;
  }
  let html = `<table class="port-table"><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Version</th></tr></thead><tbody>`;
  data.open_ports.forEach(p => {
    html += `<tr><td><span class="port-num">${p.port}</span></td><td>${esc(p.service)}</td><td><span class="port-open">${esc(p.state)}</span></td><td>${esc(p.version)}</td></tr>`;
  });
  html += `</tbody></table>`;
  body.innerHTML = html;
}

function renderScreenshot(data) {
  const body = document.getElementById("screenshotBody");
  const status = document.getElementById("screenshotStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  if (!data.screenshot_path) {
    body.innerHTML = `<p class="no-data">No screenshot</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  if (status) status.textContent = "Captured";
  body.innerHTML = `
    <div class="screenshot-wrap">
      <img src="/static/${esc(data.screenshot_path)}" alt="Screenshot" onerror="this.parentElement.innerHTML='<p class=no-data>Image failed to load.</p>'" />
      <div class="screenshot-overlay">${esc(data.url)}</div>
    </div>`;
}

function renderFirewall(data) {
  const body = document.getElementById("firewallBody");
  const status = document.getElementById("firewallStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  if (data.detected) {
    if (status) status.textContent = data.firewall_name;
    body.innerHTML = `<div class="firewall-box detected">⚠ Firewall Detected: ${esc(data.firewall_name)}</div><div class="data-row"><span class="data-key">Evidence</span><span class="data-val">${esc(data.evidence)}</span></div>`;
  } else {
    if (status) status.textContent = "Not Detected";
    body.innerHTML = `<div class="firewall-box not-detected">✓ No Firewall Detected</div><div class="data-row"><span class="data-key">Evidence</span><span class="data-val">${esc(data.evidence)}</span></div>`;
  }
}

function renderTech(data) {
  const body = document.getElementById("techBody");
  const status = document.getElementById("techStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  if (status) status.textContent = `${data.total_found} found`;
  if (data.total_found === 0) {
    body.innerHTML = `<p class="no-data">No technologies detected.</p>`;
    return;
  }
  let html = "";
  for (const [category, techs] of Object.entries(data.technologies)) {
    const techList = Array.isArray(techs) ? techs : [techs];
    html += `<div class="tech-category"><div class="tech-category-title">${esc(category)}</div><div class="tech-badges">${techList.map(t => `<span class="tech-badge">${esc(t)}</span>`).join("")}</div></div>`;
  }
  body.innerHTML = html;
}

function renderCrawl(data) {
  const body = document.getElementById("crawlBody");
  const status = document.getElementById("crawlStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  if (status) status.textContent = `${data.total_found} endpoints`;
  if (data.total_found === 0) {
    body.innerHTML = `<p class="no-data">No endpoints found.</p>`;
    return;
  }
  const rows = data.endpoints.map(e => {
    const cls = !e.status_code ? "" : e.status_code < 300 ? "status-2xx" : e.status_code < 400 ? "status-3xx" : e.status_code < 500 ? "status-4xx" : "status-5xx";
    return `<tr><td><a href="${esc(e.url)}" target="_blank" style="color:#00ff88;">${esc(e.url)}</a></td><td><span class="port-open">${esc(e.method)}</span></td><td><span class="${cls}">${e.status_code || "N/A"}</span></td><td>${esc(e.content_type || "")}</td></tr>`;
  }).join("");
  body.innerHTML = `<table class="crawl-table"><thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Content Type</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderJSScanner(data) {
  const body = document.getElementById("jsScannerBody");
  const status = document.getElementById("jsScannerStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  if (status) status.textContent = `${data.total_js_files || 0} JS files`;
  let html = `<div class="data-row"><span class="data-key">Total JS Files</span><span class="data-val">${data.total_js_files || 0}</span></div>`;
  if (data.emails && data.emails.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📧 Emails (${data.emails.length})</div><div class="tech-badges">${data.emails.map(e => `<span class="tech-badge">${esc(e)}</span>`).join("")}</div></div>`;
  }
  if (data.internal_paths && data.internal_paths.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📁 Internal Paths (${data.internal_paths.length})</div><div class="tech-badges">${data.internal_paths.slice(0, 15).map(p => `<span class="tech-badge">${esc(p)}</span>`).join("")}</div></div>`;
  }
  if (!data.emails?.length && !data.internal_paths?.length) {
    html += `<p class="no-data">No valuable information found in JavaScript files.</p>`;
  }
  body.innerHTML = html;
}

function renderSubdomains(data) {
  const body = document.getElementById("subdomainBody");
  const status = document.getElementById("subdomainStatus");
  if (!body) return;
  if (!data) { body.innerHTML = `<p class="no-data">No data</p>`; return; }
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  const total = data.total_found || 0;
  if (status) status.textContent = `${total} subdomains`;
  if (total === 0 || !data.subdomains || data.subdomains.length === 0) {
    body.innerHTML = `<p class="no-data">No subdomains found.</p>`;
    return;
  }
  let html = `<table class="crawl-table"><thead><tr><th>🌐 Subdomain</th><th>📡 IP Address</th></tr></thead><tbody>`;
  data.subdomains.forEach(sd => {
    const sub = sd.subdomain || sd;
    const ip = sd.ip || 'N/A';
    html += `<tr><td><a href="https://${esc(sub)}" target="_blank" style="color:#00ff88;">${esc(sub)}</a></td><td>${esc(ip)}</td></tr>`;
  });
  html += `</tbody></table>`;
  body.innerHTML = html;
}

// ── Download PDF Report ───────────────────────────────────
async function downloadPDF() {
  const scanData = window._lastScanData;
  if (!scanData) {
    alert("No scan data available. Please run a scan first.");
    return;
  }
  try {
    log("Generating PDF report...", "info");
    const pdfBtn = document.getElementById("downloadPdfBtn");
    if (pdfBtn) { pdfBtn.disabled = true; pdfBtn.textContent = "⏳ GENERATING..."; }
    const response = await fetch("/api/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(scanData)
    });
    const result = await response.json();
    if (result.success) {
      log("PDF generated successfully!", "ok");
      window.location.href = result.download_url;
    } else {
      log(`PDF generation failed: ${result.error}`, "error");
      alert("Failed to generate PDF: " + result.error);
    }
  } catch (err) {
    log(`PDF generation error: ${err.message}`, "error");
    alert("Error generating PDF: " + err.message);
  } finally {
    const pdfBtn = document.getElementById("downloadPdfBtn");
    if (pdfBtn) { pdfBtn.disabled = false; pdfBtn.textContent = "📄 DOWNLOAD PDF"; }
  }
}

// ── XSS Protection ────────────────────────────────────────
function esc(str) {
  if (str == null) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
