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
  
  const urlParams = new URLSearchParams(window.location.search);
  const scanId = urlParams.get('scan_id');
  
  if (scanId) {
    console.log("🔍 Loading scan from URL:", scanId);
    setTimeout(() => loadScan(scanId), 500);
  } else {
    loadHistory();
  }
  
  loadAutomationStatus();
  loadEmailConfig();
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
    console.log("📥 Loading scan:", scanId);
    setStatus("loading", "LOADING...");
    
    const response = await fetch(`/api/history/${scanId}`);
    const data = await response.json();
    
    console.log("📊 Full Scan Data:", data);
    
    if (data.error || !data.results) {
      setStatus("error", "NOT FOUND");
      return;
    }
    
    if (resultsGrid) resultsGrid.style.display = "grid";
    if (logSection) logSection.style.display = "none";
    
    const results = data.results;
    console.log("📊 Results:", results);
    
    renderSSL(results.ssl);
    renderSecurity(results.security_headers);
    renderPorts(results.ports);
    renderScreenshot(results.screenshot);
    renderFirewall(results.firewall);
    renderTech(results.tech);
    renderCrawl(results.crawl);
    
    if (results.js_scanner) renderJSScanner(results.js_scanner);
    if (results.subdomains) renderSubdomains(results.subdomains);
    
    setStatus("done", "LOADED FROM HISTORY");
    
    const url = new URL(window.location);
    url.searchParams.set('scan_id', scanId);
    window.history.replaceState({}, '', url);
    
  } catch (err) {
    console.error("❌ Failed to load scan:", err);
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
  if (customPorts === "") customPorts = null;

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
    
    if (data.subdomains) renderSubdomains(data.subdomains);

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
    
    const url = new URL(window.location);
    url.searchParams.set('scan_id', data.scan_id);
    window.history.replaceState({}, '', url);
    
    loadHistory();
    
    const pdfBtn = document.getElementById("downloadPdfBtn");
    if (pdfBtn) pdfBtn.style.display = "inline-block";

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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No SSL data available</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  const daysClass = data.days_remaining > 30 ? "ok" : data.days_remaining > 7 ? "warn" : "bad";
  if (status) status.textContent = data.is_expired ? "EXPIRED" : `${data.days_remaining} days left`;
  body.innerHTML = `
    <div class="data-row"><span class="data-key">Issued To</span><span class="data-val">${esc(data.issued_to || 'N/A')}</span></div>
    <div class="data-row"><span class="data-key">Issued By</span><span class="data-val">${esc(data.issued_by || 'N/A')}</span></div>
    <div class="data-row"><span class="data-key">Valid From</span><span class="data-val">${esc(data.valid_from || 'N/A')}</span></div>
    <div class="data-row"><span class="data-key">Valid Until</span><span class="data-val">${esc(data.valid_until || 'N/A')}</span></div>
    <div class="data-row"><span class="data-key">Days Remaining</span><span class="data-val ${daysClass}">${data.days_remaining ?? 'N/A'}</span></div>
    <div class="data-row"><span class="data-key">Expired</span><span class="data-val ${data.is_expired ? 'bad' : 'ok'}">${data.is_expired ? "YES" : "NO"}</span></div>`;
}

function renderSecurity(data) {
  const body = document.getElementById("securityBody");
  const status = document.getElementById("securityStatus");
  if (!body) return;
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No security headers data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No port scan data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  if (status) status.textContent = `${data.total_open || 0} open ports`;
  
  if (!data.open_ports || data.open_ports.length === 0) {
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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No screenshot available</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  if (!data.screenshot_path) {
    body.innerHTML = `<p class="no-data">No screenshot captured</p>`;
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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No firewall data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No technology data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  if (status) status.textContent = `${data.total_found || 0} found`;
  
  if (!data.technologies || Object.keys(data.technologies).length === 0) {
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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No crawl data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  if (status) status.textContent = `${data.total_found || 0} endpoints`;
  
  if (!data.endpoints || data.endpoints.length === 0) {
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
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No JS data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  if (status) status.textContent = `${data.total_js_files || 0} JS files`;
  
  let html = `<div class="data-row"><span class="data-key">Total JS Files</span><span class="data-val">${data.total_js_files || 0}</span></div>`;
  
  if (data.js_files && data.js_files.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📄 JS Files (${data.js_files.length})</div><div class="tech-badges">`;
    data.js_files.forEach(js => {
      const name = js.name || js.url?.split('/').pop() || js.url || 'unknown';
      html += `<span class="tech-badge" title="${esc(js.url || '')}">${esc(name)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.emails && data.emails.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📧 Emails (${data.emails.length})</div><div class="tech-badges">`;
    data.emails.forEach(email => {
      html += `<span class="tech-badge" style="color: #ffaa00;">${esc(email)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.internal_paths && data.internal_paths.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📁 Internal Paths (${data.internal_paths.length})</div><div class="tech-badges">`;
    data.internal_paths.slice(0, 15).forEach(path => {
      html += `<span class="tech-badge" style="color: #00ccff;">${esc(path)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (!data.js_files?.length && !data.emails?.length && !data.internal_paths?.length) {
    html += `<p class="no-data">No valuable information found in JavaScript files.</p>`;
  }
  
  body.innerHTML = html;
}

// ── NO LIMIT: Shows ALL subdomains ──
function renderSubdomains(data) {
  const body = document.getElementById("subdomainBody");
  const status = document.getElementById("subdomainStatus");
  if (!body) return;
  
  console.log("Subdomain Data:", data);
  
  if (!data) {
    body.innerHTML = `<p class="no-data">No subdomain data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }
  
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
  
  // ── NO SLICE LIMIT: Shows ALL subdomains ──
  let html = `
    <div style="overflow-x: auto; max-height: 500px; overflow-y: auto;">
      <table style="width: 100%; border-collapse: collapse; font-size: 0.7rem;">
        <thead style="position: sticky; top: 0; background: #0d1210; z-index: 10;">
          <tr style="background: #0d1210; border-bottom: 2px solid #00ff88;">
            <th style="padding: 8px 10px; text-align: left;">Subdomain</th>
            <th style="padding: 8px 10px; text-align: left;">IP</th>
            <th style="padding: 8px 10px; text-align: center;">Status</th>
            <th style="padding: 8px 10px; text-align: left;">Tech</th>
            <th style="padding: 8px 10px; text-align: center;">Ports</th>
            <th style="padding: 8px 10px; text-align: center;">Screenshot</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  // ── Loop through ALL subdomains (NO LIMIT) ──
  data.subdomains.forEach(sd => {
    const sub = sd.subdomain || sd;
    const ip = sd.ip || 'N/A';
    const statusCode = sd.http_status || 'N/A';
    
    let statusClass = "";
    if (statusCode >= 200 && statusCode < 300) statusClass = "status-2xx";
    else if (statusCode >= 400 && statusCode < 500) statusClass = "status-4xx";
    else if (statusCode >= 500) statusClass = "status-5xx";
    
    let techHtml = `<span style="color: #666;">None</span>`;
    if (sd.technologies && sd.technologies.length > 0) {
      techHtml = sd.technologies.map(t => 
        `<span style="background: #1a1a2e; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block; font-size: 0.6rem;">${esc(t)}</span>`
      ).join('');
    }
    
    let portsHtml = `<span style="color: #666;">None</span>`;
    if (sd.open_ports && sd.open_ports.length > 0) {
      portsHtml = sd.open_ports.map(p => 
        `<span style="background: #003d20; padding: 2px 6px; border-radius: 3px; margin: 2px; display: inline-block; font-size: 0.6rem; color: #00ff88;">${esc(p)}</span>`
      ).join('');
    }
    
    let screenshotHtml = `<span style="color: #666;">N/A</span>`;
    if (sd.screenshot) {
      screenshotHtml = `<a href="/static/${sd.screenshot}" target="_blank">
        <img src="/static/${sd.screenshot}" style="width: 60px; height: 40px; object-fit: cover; border-radius: 4px; border: 1px solid #2a2a35;" 
             onerror="this.style.display='none'; this.parentElement.innerHTML='<span style=&quot;color:#666;&quot;>N/A</span>'">
      </a>`;
    }
    
    html += `
      <tr style="border-bottom: 1px solid #1a2e20;">
        <td style="padding: 8px 10px;">
          <a href="https://${esc(sub)}" target="_blank" style="color: #00ff88; text-decoration: none; font-size: 0.7rem;">${esc(sub)}</a>
        </td>
        <td style="padding: 8px 10px; font-family: monospace; font-size: 0.65rem;">${esc(ip)}</td>
        <td style="padding: 8px 10px; text-align: center;">
          <span class="${statusClass}" style="padding: 2px 8px; border-radius: 3px; display: inline-block; font-size: 0.65rem;">${statusCode}</span>
        </td>
        <td style="padding: 8px 10px;">${techHtml}</td>
        <td style="padding: 8px 10px; text-align: center;">${portsHtml}</td>
        <td style="padding: 8px 10px; text-align: center;">${screenshotHtml}</td>
      </tr>
    `;
  });
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  body.innerHTML = html;
}

// ── Automation Functions ──
async function loadAutomationStatus() {
  try {
    const response = await fetch('/api/automation/status');
    const data = await response.json();
    
    const statusEl = document.getElementById('autoStatus');
    const totalEl = document.getElementById('totalJobs');
    const jobList = document.getElementById('jobList');
    
    if (statusEl) statusEl.textContent = data.status || 'Unknown';
    if (totalEl) totalEl.textContent = data.total_jobs || 0;
    
    if (jobList && data.jobs && data.jobs.length > 0) {
      jobList.innerHTML = data.jobs.map(job => `
        <div class="data-row" style="font-size: 0.75rem;">
          <span class="data-key">${job.name}</span>
          <span class="data-val">Next: ${job.next_run ? new Date(job.next_run).toLocaleString() : 'N/A'}</span>
        </div>
      `).join('');
    } else if (jobList) {
      jobList.innerHTML = '<p class="no-data">No scheduled jobs</p>';
    }
  } catch (err) {
    console.error('Failed to load automation status:', err);
  }
}

async function triggerAutoScan() {
  const url = urlInput.value.trim();
  if (!url) {
    alert('Please enter a URL first!');
    return;
  }
  
  const btn = event.target;
  btn.textContent = '⏳ Scanning...';
  btn.disabled = true;
  
  try {
    const response = await fetch('/api/automation/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls: [url], notify: false })
    });
    
    const data = await response.json();
    
    if (data.success > 0) {
      alert(`✅ Scan started for ${url}\nScan ID: ${data.results[0].scan_id}`);
      window.location.href = `/?scan_id=${data.results[0].scan_id}`;
    } else {
      alert('❌ Scan failed: ' + (data.results[0].error || 'Unknown error'));
    }
  } catch (err) {
    alert('❌ Error: ' + err.message);
  } finally {
    btn.textContent = '⚡ Trigger Scan Now';
    btn.disabled = false;
  }
}

// ── Email Functions ──
async function loadEmailConfig() {
  const statusEl = document.getElementById('emailStatus');
  if (!statusEl) return;
  
  statusEl.textContent = '⏳ Loading...';
  statusEl.className = 'email-status loading';
  
  try {
    const response = await fetch('/api/email/config');
    const data = await response.json();
    
    const senderEmail = document.getElementById('senderEmail');
    const senderPassword = document.getElementById('senderPassword');
    const recipientEmails = document.getElementById('recipientEmails');
    
    if (senderEmail) senderEmail.value = data.sender_email || '';
    if (senderPassword) senderPassword.value = data.sender_password || '';
    if (recipientEmails) recipientEmails.value = (data.recipients || []).join(', ');
    
    statusEl.textContent = '✅ Config loaded';
    statusEl.className = 'email-status success';
  } catch (err) {
    statusEl.textContent = '❌ Failed to load: ' + err.message;
    statusEl.className = 'email-status error';
  }
}

async function saveEmailConfig() {
  const statusEl = document.getElementById('emailStatus');
  if (!statusEl) return;
  
  const senderEmail = document.getElementById('senderEmail').value.trim();
  const senderPassword = document.getElementById('senderPassword').value.trim();
  const recipients = document.getElementById('recipientEmails').value.trim();
  
  if (!senderEmail) {
    statusEl.textContent = '⚠️ Please enter sender email';
    statusEl.className = 'email-status error';
    return;
  }
  if (!senderPassword) {
    statusEl.textContent = '⚠️ Please enter app password';
    statusEl.className = 'email-status error';
    return;
  }
  if (!recipients) {
    statusEl.textContent = '⚠️ Please enter at least one recipient email';
    statusEl.className = 'email-status error';
    return;
  }
  
  statusEl.textContent = '⏳ Saving...';
  statusEl.className = 'email-status loading';
  
  try {
    const response = await fetch('/api/email/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender_email: senderEmail,
        sender_password: senderPassword,
        recipients: recipients.split(',').map(e => e.trim())
      })
    });
    
    const data = await response.json();
    if (data.success) {
      statusEl.textContent = '✅ Email configuration saved successfully!';
      statusEl.className = 'email-status success';
    } else {
      statusEl.textContent = '❌ Failed: ' + data.error;
      statusEl.className = 'email-status error';
    }
  } catch (err) {
    statusEl.textContent = '❌ Error: ' + err.message;
    statusEl.className = 'email-status error';
  }
}

async function testEmailConfig() {
  const statusEl = document.getElementById('emailStatus');
  if (!statusEl) return;
  
  statusEl.textContent = '⏳ Sending test email...';
  statusEl.className = 'email-status loading';
  
  try {
    const response = await fetch('/api/email/test', { method: 'POST' });
    const data = await response.json();
    
    if (data.success) {
      statusEl.textContent = '✅ Test email sent successfully! Check your inbox.';
      statusEl.className = 'email-status success';
    } else {
      statusEl.textContent = '❌ Failed: ' + data.error;
      statusEl.className = 'email-status error';
    }
  } catch (err) {
    statusEl.textContent = '❌ Error: ' + err.message;
    statusEl.className = 'email-status error';
  }
}

// ── XSS Protection ────────────────────────────────────────
function esc(str) {
  if (str == null) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
