// ── Dashboard Controller ───────────────────────────────────
const urlInput    = document.getElementById("urlInput");
const scanBtn     = document.getElementById("scanBtn");
const logSection  = document.getElementById("logSection");
const terminalLog = document.getElementById("terminalLog");
const resultsGrid = document.getElementById("resultsGrid");
const statusLabel = document.getElementById("statusLabel");

// ── Port Option Handler ───────────────────────────────────
document.addEventListener("DOMContentLoaded", function() {
  const customRadio = document.getElementById("customPortRadio");
  const customInput = document.getElementById("customPorts");
  
  if (customRadio && customInput) {
    customRadio.addEventListener("change", function() {
      customInput.disabled = !this.checked;
    });
    customInput.disabled = !customRadio.checked;
  }
});

// Page load হলে history দেখাও
window.onload = () => loadHistory();

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

// ── Log function ───────────────────────────────────────────
function log(text, type = "info") {
  const line = document.createElement("span");
  line.className = `log-${type}`;
  line.textContent = `[${new Date().toTimeString().slice(0, 8)}] ${text}`;
  terminalLog.appendChild(line);
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

// ── History load করো ──────────────────────────────────────
async function loadHistory() {
  const historyList = document.getElementById("historyList");
  try {
    const response = await fetch("/api/history");
    const scans = await response.json();
    if (scans.length === 0) {
      historyList.innerHTML = `<p class="no-data">No scans yet.</p>`;
      return;
    }
    historyList.innerHTML = scans.map(scan => `
      <div class="history-item" onclick="loadScan('${scan.id}')">
        <div class="history-url">${esc(scan.url)}</div>
        <div class="history-time">${esc(scan.timestamp)}</div>
      </div>`).join("");
  } catch (err) {
    historyList.innerHTML = `<p class="no-data">Failed to load history.</p>`;
  }
}

// ── পুরনো scan load করো ───────────────────────────────────
async function loadScan(scanId) {
  try {
    const response = await fetch(`/api/history/${scanId}`);
    const data = await response.json();
    if (data.error) return;

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

    resultsGrid.style.display = "grid";
    logSection.style.display = "none";
    statusLabel.textContent = "LOADED FROM HISTORY";
  } catch (err) {
    console.error("Failed to load scan:", err);
  }
}

// ── Main Scan Function ─────────────────────────────────────
async function startScan() {
  let rawUrl = urlInput.value.trim();
  if (!rawUrl) { urlInput.focus(); return; }

  // URL normalize
  let targetUrl = rawUrl;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  // Port options
  const portOptionEl = document.querySelector('input[name="portOption"]:checked');
  const portOption = portOptionEl ? portOptionEl.value : "top50";
  const customPortsEl = document.getElementById("customPorts");
  let customPorts = customPortsEl ? customPortsEl.value.trim() : "";
  
  if (customPorts === "") {
    customPorts = null;
  }

  terminalLog.innerHTML = "";
  logSection.style.display = "block";
  resultsGrid.style.display = "none";
  scanBtn.disabled = true;
  statusLabel.textContent = "SCANNING...";

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
    log("All modules done!", "ok");
    log(`Saved to database. ID: ${data.scan_id}`, "ok");

    renderSSL(data.ssl);
    renderSecurity(data.security_headers);
    renderPorts(data.ports);
    renderScreenshot(data.screenshot);
    renderFirewall(data.firewall);
    renderTech(data.tech);
    renderCrawl(data.crawl);

    resultsGrid.style.display = "grid";
    statusLabel.textContent = "COMPLETE";
    log("All done!", "ok");

    loadHistory();

    // ── JS Scanner ──
    try {
      log("Running JavaScript scanner...", "info");
      const jsResponse = await fetch("/api/js-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          url: targetUrl, 
          port_option: portOption, 
          custom_ports: customPorts 
        }),
      });
      const jsData = await jsResponse.json();
      
      if (jsData && !jsData.error) {
        log(`JS Scan: ${jsData.total_js_files || 0} JS files found`, "ok");
        renderJSScanner(jsData);
        if (jsData.emails && jsData.emails.length > 0) {
          log(`  📧 Found ${jsData.emails.length} email addresses`, "info");
        }
        if (jsData.internal_paths && jsData.internal_paths.length > 0) {
          log(`  📁 Found ${jsData.internal_paths.length} internal paths`, "info");
        }
      } else if (jsData && jsData.error) {
        log(`JS Scan error: ${jsData.error}`, "warn");
      }
    } catch (jsErr) {
      log(`JS Scan failed: ${jsErr.message}`, "warn");
    }

  } catch (err) {
    log(`Error: ${err.message}`, "error");
    statusLabel.textContent = "ERROR";
  } finally {
    scanBtn.disabled = false;
  }
}

// ── SSL Result ─────────────────────────────────────────────
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
    <div class="data-row"><span class="data-key">Issued To</span><span class="data-val">${esc(data.issued_to)}</span></div>
    <div class="data-row"><span class="data-key">Issued By</span><span class="data-val">${esc(data.issued_by)}</span></div>
    <div class="data-row"><span class="data-key">Valid From</span><span class="data-val">${esc(data.valid_from)}</span></div>
    <div class="data-row"><span class="data-key">Valid Until</span><span class="data-val">${esc(data.valid_until)}</span></div>
    <div class="data-row"><span class="data-key">Days Remaining</span><span class="data-val ${daysClass}">${data.days_remaining}</span></div>
    <div class="data-row"><span class="data-key">Expired</span><span class="data-val ${data.is_expired ? 'bad' : 'ok'}">${data.is_expired ? "YES" : "NO"}</span></div>`;
}

// ── Security Headers Result ────────────────────────────────
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
    ${presentHtml}${missingHtml}`;
}

// ── Port Scan Result (with OS Detection) ───────────────────
function renderPorts(data) {
  const body = document.getElementById("portsBody");
  const status = document.getElementById("portsStatus");
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }
  
  status.textContent = `${data.total_open} open ports`;
  
  let html = "";
  
  // OS Detection Section
  if (data.os_info && Object.keys(data.os_info).length > 0) {
    html += `<div class="tech-category" style="margin-bottom: 15px; border: 1px solid #00ff88; background: #0d1210; border-radius: 4px;">
      <div class="tech-category-title" style="color: #00ff88; padding: 8px;">💻 Operating System Detection</div>
      <div class="tech-badges" style="padding: 8px;">`;
    for (const [os, accuracy] of Object.entries(data.os_info)) {
      let accuracyClass = accuracy >= 90 ? "ok" : (accuracy >= 70 ? "warn" : "bad");
      html += `<span class="tech-badge" style="background: #1a1a2e; border: 1px solid #00ff88;">
        🖥️ ${esc(os)} <span class="${accuracyClass}" style="font-size: 0.65rem;">(${accuracy}% accurate)</span>
      </span>`;
    }
    html += `</div></div>`;
  } else {
    html += `<div class="tech-category" style="margin-bottom: 15px;">
      <div class="tech-category-title">💻 OS Detection</div>
      <div class="tech-badges">
        <span class="tech-badge" style="background:#3d3d00;">Unable to determine OS (may be behind CDN/WAF)</span>
      </div>
    </div>`;
  }
  
  // Open ports table
  if (data.total_open > 0) {
    html += `<table class="port-table"><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Version</th></tr></thead><tbody>`;
    data.open_ports.forEach(p => {
      html += `<tr><td><span class="port-num">${p.port}</span></td><td>${esc(p.service)}</span></td>。<span class="port-open">${esc(p.state)}</span></td><td>${esc(p.version)}</span></tr>`;
    });
    html += `</tbody></table>`;
  } else {
    html += `<p class="no-data">No open ports found.</p>`;
  }
  
  // Vulnerabilities (if any)
  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    html += `<div class="tech-category" style="margin-top: 15px;">
      <div class="tech-category-title">⚠️ Vulnerabilities Found (${data.vulnerabilities.length})</div>
      <div class="tech-badges">`;
    data.vulnerabilities.forEach(v => {
      html += `<span class="tech-badge" style="background:#3d0000; color:#ff4444;">Port ${v.port}: ${v.service}</span>`;
    });
    html += `</div></div>`;
  }
  
  body.innerHTML = html;
}

// ── Screenshot Result ──────────────────────────────────────
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
      <img src="/static/${esc(data.screenshot_path)}" alt="Screenshot"
           onerror="this.parentElement.innerHTML='<p class=no-data>Image failed to load.</p>'" />
      <div class="screenshot-overlay">${esc(data.url)}</div>
    </div>`;
}

// ── Firewall Result ────────────────────────────────────────
function renderFirewall(data) {
  const body = document.getElementById("firewallBody");
  const status = document.getElementById("firewallStatus");
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }
  if (data.detected) {
    status.textContent = data.firewall_name;
    body.innerHTML = `
      <div class="firewall-box detected">⚠ Firewall Detected: ${esc(data.firewall_name)}</div>
      <div class="data-row"><span class="data-key">Evidence</span><span class="data-val">${esc(data.evidence)}</span></div>`;
  } else {
    status.textContent = "Not Detected";
    body.innerHTML = `
      <div class="firewall-box not-detected">✓ No Firewall Detected</div>
      <div class="data-row"><span class="data-key">Evidence</span><span class="data-val">${esc(data.evidence)}</span></div>`;
  }
}

// ── Tech Detection Result (FIXED - React এবং Next.js আলাদা) ──
function renderTech(data) {
  const body = document.getElementById("techBody");
  const status = document.getElementById("techStatus");
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }
  
  status.textContent = `${data.total_found} found`;
  
  if (data.total_found === 0) {
    body.innerHTML = `<p class="no-data">No technologies detected.</p>`;
    return;
  }
  
  let categoriesHtml = "";
  
  for (const [category, techs] of Object.entries(data.technologies)) {
    let techArray = Array.isArray(techs) ? techs : [techs];
    let cleanedTechs = [];
    
    for (let tech of techArray) {
      let techStr = String(tech);
      
      if (techStr === "ReactNext.js" || techStr === "Next.jsReact") {
        if (!cleanedTechs.includes("React")) cleanedTechs.push("React");
        if (!cleanedTechs.includes("Next.js")) cleanedTechs.push("Next.js");
      }
      else if (techStr.includes("React") && techStr.includes("Next.js")) {
        if (!cleanedTechs.includes("React")) cleanedTechs.push("React");
        if (!cleanedTechs.includes("Next.js")) cleanedTechs.push("Next.js");
      }
      else if (techStr.includes(",")) {
        let parts = techStr.split(",").map(p => p.trim());
        for (let part of parts) {
          if (!cleanedTechs.includes(part)) cleanedTechs.push(part);
        }
      }
      else {
        if (!cleanedTechs.includes(techStr)) cleanedTechs.push(techStr);
      }
    }
    
    cleanedTechs = [...new Set(cleanedTechs.filter(t => t && t.length > 0))];
    
    categoriesHtml += `
      <div class="tech-category">
        <div class="tech-category-title">${esc(category)}</div>
        <div class="tech-badges">
          ${cleanedTechs.map(tech => `<span class="tech-badge">${esc(tech)}</span>`).join("")}
        </div>
      </div>
    `;
  }
  
  body.innerHTML = categoriesHtml;
}

// ── Crawl Result ──────────────────────────────────────────
function renderCrawl(data) {
  const body = document.getElementById("crawlBody");
  const status = document.getElementById("crawlStatus");
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    status.textContent = "FAILED";
    return;
  }
  status.textContent = `${data.total_found} endpoints`;
  if (data.total_found === 0) {
    body.innerHTML = `<p class="no-data">No endpoints found.</p>`;
    return;
  }
  const rows = data.endpoints.map(e => {
    const statusClass = !e.status_code ? "" :
      e.status_code < 300 ? "status-2xx" :
      e.status_code < 400 ? "status-3xx" :
      e.status_code < 500 ? "status-4xx" : "status-5xx";
    return `
      <tr>
        <td><a href="${esc(e.url)}" target="_blank" style="color:#00ff88;">${esc(e.url)}</a></td>
        <td><span class="port-open">${esc(e.method)}</span></td>
        <td><span class="${statusClass}">${e.status_code || "N/A"}</span></td>
        <td>${esc(e.content_type || "")}</span></td>
      </tr>`;
  }).join("");
  body.innerHTML = `
    <table class="crawl-table">
      <thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Content Type</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── JS Scanner Result ─────────────────────────────────────
function renderJSScanner(data) {
  const body = document.getElementById("jsScannerBody");
  const status = document.getElementById("jsScannerStatus");
  
  if (!body) return;
  
  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }
  
  if (status) status.textContent = `${data.total_js_files || 0} JS files`;
  
  let html = `
    <div class="data-row">
      <span class="data-key">Total JS Files</span>
      <span class="data-val">${data.total_js_files || 0}</span>
    </div>
  `;
  
  if (data.emails && data.emails.length > 0) {
    html += `<div class="tech-category">
      <div class="tech-category-title">📧 Emails (${data.emails.length})</div>
      <div class="tech-badges">`;
    data.emails.forEach(email => {
      html += `<span class="tech-badge">${esc(email)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.internal_paths && data.internal_paths.length > 0) {
    html += `<div class="tech-category">
      <div class="tech-category-title">📁 Internal Paths (${data.internal_paths.length})</div>
      <div class="tech-badges">`;
    data.internal_paths.slice(0, 15).forEach(path => {
      html += `<span class="tech-badge">${esc(path)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.social_media && data.social_media.length > 0) {
    html += `<div class="tech-category">
      <div class="tech-category-title">📱 Social Media (${data.social_media.length})</div>
      <div class="tech-badges">`;
    data.social_media.forEach(social => {
      html += `<span class="tech-badge">${esc(social)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.total_js_files === 0 || (!data.emails?.length && !data.internal_paths?.length)) {
    html += `<p class="no-data">No valuable information found in JavaScript files.</p>`;
  }
  
  body.innerHTML = html;
}

// ── XSS Protection ────────────────────────────────────────
function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}