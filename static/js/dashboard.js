// ── Dashboard Controller ───────────────────────────────────
const urlInput    = document.getElementById("urlInput");
const scanBtn     = document.getElementById("scanBtn");
const logSection  = document.getElementById("logSection");
const terminalLog = document.getElementById("terminalLog");
const resultsGrid = document.getElementById("resultsGrid");
const statusLabel = document.getElementById("statusLabel");
const statusDot   = document.getElementById("statusDot");

// ── Chat Elements ──────────────────────────────────────────
const chatMessages = document.getElementById("chatMessages");
const chatInput = document.getElementById("chatInput");
const sendChatBtn = document.getElementById("sendChatBtn");
const reasoningBox = document.getElementById("reasoningBox");
const reasoningContent = document.getElementById("reasoningContent");

// ── Scan lock ──
let _scanRunning = false;

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
    console.log("Loading scan from URL:", scanId);
    setTimeout(() => loadScan(scanId), 500);
  } else {
    loadHistory();
  }

  loadAutomationStatus();
  loadEmailConfig();

  // ── Chat event listeners ──
  if (sendChatBtn) {
    sendChatBtn.addEventListener("click", sendChatMessage);
  }
  if (chatInput) {
    chatInput.addEventListener("keydown", function(e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage();
      }
    });
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

// ── Chat Functions ─────────────────────────────────────────
function appendChatMessage(text, isUser = false) {
  if (!chatMessages) return;
  const div = document.createElement("div");
  div.className = isUser ? "chat-message user" : "chat-message assistant";
  div.innerHTML = text;
  chatMessages.appendChild(div);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function setReasoning(text) {
  if (!reasoningContent) return;
  reasoningContent.innerHTML = text;
  if (reasoningBox) {
    reasoningBox.style.display = text ? "block" : "none";
  }
}

async function sendChatMessage() {
  if (!chatInput) return;
  const prompt = chatInput.value.trim();
  if (!prompt) return;

  chatInput.disabled = true;
  if (sendChatBtn) sendChatBtn.disabled = true;

  appendChatMessage(esc(prompt), true);
  chatInput.value = "";
  setReasoning("");

  try {
    const sessionId = localStorage.getItem("chatSessionId") || crypto.randomUUID();
    localStorage.setItem("chatSessionId", sessionId);

    const response = await fetch("/api/llm/chat/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: prompt,
        session_id: sessionId,
        show_reasoning: true,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let assistantMessage = "";
    let reasoningText = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const dataStr = line.slice(6);
          if (dataStr === "[DONE]") continue;
          try {
            const data = JSON.parse(dataStr);
            if (data.type === "reasoning") {
              reasoningText += data.content;
              setReasoning(reasoningText);
            } else if (data.type === "reasoning_done") {
              // keep visible
            } else if (data.type === "response") {
              assistantMessage += data.content;
              const lastMsg = chatMessages.lastElementChild;
              if (lastMsg && lastMsg.className === "chat-message assistant") {
                lastMsg.innerHTML = assistantMessage;
              } else {
                appendChatMessage(assistantMessage, false);
              }
            } else if (data.type === "error") {
              appendChatMessage(`❌ Error: ${data.content}`, false);
            }
          } catch (e) {
            // ignore
          }
        }
      }
    }

    if (!assistantMessage) {
      appendChatMessage("No response received.", false);
    }

  } catch (err) {
    console.error("Chat error:", err);
    appendChatMessage(`❌ Error: ${err.message}`, false);
  } finally {
    chatInput.disabled = false;
    if (sendChatBtn) sendChatBtn.disabled = false;
    chatInput.focus();
  }
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
      <div class="history-item" onclick="loadScan('${scan.id || scan.scan_id}')">
        <div class="history-url">${esc(scan.url)}</div>
        <div class="history-time">${esc(scan.timestamp || 'Just now')}</div>
      </div>
    `).join("");
  } catch (err) {
    historyList.innerHTML = `<div class="history-empty">Error loading history</div>`;
  }
}

// ── Load Scan by ID ────────────────────────────────────────
async function loadScan(scanId) {
  try {
    console.log("Loading scan ID:", scanId);
    setStatus("loading", "LOADING...");

    const response = await fetch(`/api/history/${scanId}`);
    const data = await response.json();

    console.log("Full Scan Data:", data);

    if (!data || data.error) {
      setStatus("error", "NOT FOUND");
      return;
    }

    if (resultsGrid) resultsGrid.style.display = "grid";
    if (logSection) logSection.style.display = "none";

    const targetData = data.results ? data.results : data;

    renderSSL(targetData.ssl);
    renderSecurity(targetData.security_headers);
    renderPorts(targetData.ports);
    renderScreenshot(targetData.screenshot);
    renderFirewall(targetData.firewall);
    renderTech(targetData.tech);
    renderCrawl(targetData.crawl);
    renderJSScanner(targetData.js_scanner || targetData.js);
    renderSubdomains(targetData.subdomains);
    renderOSINT(targetData.osint);
    renderRisk(targetData.risk);
    renderThreatIntel(targetData.threat_intel);

    setStatus("done", "LOADED FROM HISTORY");

    const url = new URL(window.location);
    url.searchParams.set('scan_id', scanId);
    window.history.replaceState({}, '', url);
    window._lastScanData = targetData;

    const pdfBtn = document.getElementById("downloadPdfBtn");
    if (pdfBtn) pdfBtn.style.display = "inline-block";

  } catch (err) {
    console.error("Failed to load scan:", err);
    setStatus("error", "ERROR");
  }
}

// ── Main Scan Function ──
async function startScan() {
  if (_scanRunning) {
    log("Scan already in progress. Please wait.", "error");
    return;
  }

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

  _scanRunning = true;
  setStatus("active", "SCANNING...");

  log(`Target: ${targetUrl}`);
  log(`Port option: ${portOption.toUpperCase()}`);
  if (customPorts) log(`Custom ports: ${customPorts}`);
  log("Running engine modules in parallel...");

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      console.log("[startScan] 30-minute timeout reached, aborting.");
      controller.abort();
    }, 1800000);

    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: targetUrl,
        port_option: portOption,
        custom_ports: customPorts,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      log(`API Error: ${response.status} - ${errorText}`, "error");
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    console.log("[startScan] Full scan data received:", data);
    console.log("[startScan] scan_id:", data.scan_id);
    console.log("[startScan] Keys:", Object.keys(data));

    log("All modules completed successfully!", "ok");
    log(`Saved to database. ID: ${data.scan_id}`, "ok");

    if (resultsGrid) resultsGrid.style.display = "grid";

    renderSSL(data.ssl);
    renderSecurity(data.security_headers);
    renderPorts(data.ports);
    renderScreenshot(data.screenshot);
    renderFirewall(data.firewall);
    renderTech(data.tech);
    renderCrawl(data.crawl);
    renderJSScanner(data.js_scanner || data.js);
    renderSubdomains(data.subdomains);
    renderOSINT(data.osint);
    renderRisk(data.risk);
    renderThreatIntel(data.threat_intel);

    setStatus("done", "COMPLETE");
    window._lastScanData = data;

    const url = new URL(window.location);
    url.searchParams.set('scan_id', data.scan_id);
    window.history.replaceState({}, '', url);

    loadHistory();

    const pdfBtn = document.getElementById("downloadPdfBtn");
    if (pdfBtn) pdfBtn.style.display = "inline-block";

  } catch (err) {
    if (err.name === "AbortError") {
      log("Scan timed out after 30 minutes.", "error");
      setStatus("error", "TIMEOUT");
    } else {
      log(`Error: ${err.message}`, "error");
      setStatus("error", "ERROR");
    }
    console.error("[startScan] Error:", err);
  } finally {
    _scanRunning = false;
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

  if (data.detected || data.cdn_detected || data.waf_detected) {
    const parts = [];
    if (data.cdn_detected) parts.push(`CDN: ${esc(data.cdn_name || data.firewall_name || "Unknown")}`);
    if (data.waf_detected) parts.push(`WAF: ${esc(data.waf_name || data.firewall_name || "Unknown")}`);
    if (status) status.textContent = parts.join(" · ") || data.firewall_name || "Detected";
    body.innerHTML = `
      <div class="firewall-box detected">${parts.length ? parts.join("<br>") : `Protection layer detected: ${esc(data.firewall_name || "Unknown")}`}</div>
      <div class="data-row"><span class="data-key">Evidence</span><span class="data-val">${esc(data.evidence)}</span></div>`;
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

  if (data.api_endpoints && data.api_endpoints.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">🔗 API Endpoints (${data.api_endpoints.length})</div><div class="tech-badges">`;
    data.api_endpoints.slice(0, 10).forEach(path => {
      html += `<span class="tech-badge" style="color: #ffaa00;">${esc(path)}</span>`;
    });
    html += `</div></div>`;
  }

  if (data.path_leakage && data.path_leakage.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">⚠ Build Path Leakage (${data.path_leakage.length})</div><div class="tech-badges">`;
    data.path_leakage.slice(0, 10).forEach(path => {
      html += `<span class="tech-badge" style="color: #ff4444;">${esc(path)}</span>`;
    });
    html += `</div></div>`;
  }

  if (data.tokens && data.tokens.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">🔑 Potential Secrets</div>`;
    html += `<table style="width:100%; font-size:0.75rem; border-collapse:collapse;">`;
    html += `<tr><th style="color:#ffaa00; text-align:left;">Value</th><th style="color:#ffaa00; text-align:left;">Confidence</th><th style="color:#ffaa00; text-align:left;">Context</th></tr>`;
    data.tokens.slice(0, 5).forEach(token => {
      const value = token.value || 'N/A';
      const confidence = token.confidence || 'unknown';
      const context = token.context || 'N/A';
      const color = confidence === 'high' ? '#ff4444' : confidence === 'medium' ? '#ff8800' : '#ffaa00';
      html += `<tr><td style="padding:4px; font-family:monospace;">${esc(value)}</td><td style="padding:4px; color:${color}; font-weight:bold;">${esc(confidence)}</td><td style="padding:4px; font-size:0.7rem; color:#aaa;">${esc(context)}</td></tr>`;
    });
    html += `</table>`;
    html += `<p class="no-data" style="margin-top:8px;">Potential credentials detected in client-side JavaScript. Review and rotate if confirmed.</p>`;
    html += `</div>`;
  }

  if (data.source_maps && data.source_maps.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">🗺 Source Maps (${data.source_maps.length})</div><p class="no-data">Public source maps may expose application internals.</p></div>`;
  }

  if (!data.js_files?.length && !data.emails?.length && !data.internal_paths?.length && !data.api_endpoints?.length && !data.path_leakage?.length && !data.tokens?.length) {
    html += `<p class="no-data">No valuable information found in JavaScript files.</p>`;
  }

  body.innerHTML = html;
}

// ── UPDATED renderSubdomains with Resolved Column ──
function renderSubdomains(data) {
  const body = document.getElementById("subdomainBody");
  const status = document.getElementById("subdomainStatus");
  if (!body) return;

  if (!data || data.error) {
    body.innerHTML = `<p class="no-data">Subdomain discovery failed: ${data ? data.error : 'No data'}</p>`;
    if (status) status.textContent = "Failed";
    return;
  }

  const subdomains = data.subdomains || [];
  const total = data.total_found || subdomains.length || 0;
  const live = data.live_count || 0;
  const dead = data.dead_count || 0;
  const zombie = data.zombie_count || 0;
  const parsingErrors = data.parsing_error_count || 0;

  if (status) {
    let statusText = `${total} subdomains (🟢${live} · ⚫${dead} · 🟡${zombie})`;
    if (parsingErrors > 0) {
      statusText += ` ⚠️${parsingErrors} parsing errors`;
    }
    status.textContent = statusText;
  }

  if (total === 0 || subdomains.length === 0) {
    body.innerHTML = `<p class="no-data">No subdomains found.</p>`;
    return;
  }

  let html = `
    <div style="overflow-x: auto;">
    <table style="width: 100%; border-collapse: collapse; font-size: 0.82rem;">
      <thead>
        <tr style="background: #1a2e20;">
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Subdomain</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">IP</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Resolved</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Status</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Sensitive</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Technologies</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Open Ports</th>
          <th style="padding: 10px 12px; text-align: left; color: #00ff88; border-bottom: 1px solid #2a4a3a;">Screenshot</th>
        </tr>
      </thead>
      <tbody>
  `;

  subdomains.forEach((sd, index) => {
    const subdomain = sd.subdomain || sd.name || "Unknown";
    const ip = sd.ip || sd.ip_address || "N/A";
    const statusVal = sd.status || "dead";
    const resolved = sd.resolved === true;
    const parsingError = sd.possible_parsing_error === true;
    const statusColor = statusVal === "live" ? "#00aa55" : statusVal === "zombie" ? "#ff8800" : "#6a8070";
    const statusLabel = statusVal === "live" ? "🟢 Live" : statusVal === "zombie" ? "🟡 Zombie" : "⚫ Dead";
    const resolvedLabel = resolved ? "✅ Yes" : "❌ No";
    const resolvedColor = resolved ? "#00aa55" : "#6a8070";

    // Fix #1: Sensitive flag visual distinction
    const sensitive = sd.sensitive === true;
    const sensitiveDisplay = sensitive && resolved ? "🔴 YES (live)" : sensitive && !resolved ? "⚠️ Name match only" : "NO";
    const sensitiveColor = sensitive && resolved ? "#ff4444" : sensitive && !resolved ? "#ff8800" : "#6a8070";

    const rowBg = index % 2 === 0 ? "#050807" : "#080d0b";
    const errorBg = parsingError ? "#2a1a1a" : rowBg;

    let techHtml = '<span style="color: #6a8070;">N/A</span>';
    if (sd.technologies && Array.isArray(sd.technologies) && sd.technologies.length > 0) {
      techHtml = sd.technologies.slice(0, 3).map(t =>
        `<span style="background: #1a2e20; color: #00ff88; padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; margin: 1px;">${esc(String(t))}</span>`
      ).join(" ");
    }

    let portsHtml = '<span style="color: #6a8070;">N/A</span>';
    if (sd.open_ports && Array.isArray(sd.open_ports) && sd.open_ports.length > 0) {
      portsHtml = sd.open_ports.slice(0, 5).map(p => {
        const portNum = p.port || p;
        return `<span style="background: #1a1a2e; color: #ff8800; padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; margin: 1px;">${esc(String(portNum))}</span>`;
      }).join(" ");
    }

    let screenshotHtml = '<span style="color: #6a8070;">N/A</span>';
    if (sd.screenshot) {
      screenshotHtml = `<a href="/static/${esc(sd.screenshot)}" target="_blank" rel="noopener">
        <img src="/static/${esc(sd.screenshot)}"
             style="width: 60px; height: 40px; object-fit: cover; border-radius: 4px; border: 1px solid #2a4a3a;"
             onerror="this.parentElement.innerHTML='<span style=color:#6a8070;>Failed</span>'"
             alt="Screenshot of ${esc(subdomain)}">
      </a>`;
    }

    // Fix #2: Show warning for parsing errors
    const domainDisplay = parsingError
      ? `${esc(subdomain)} <span style="color:#ff8800; font-size:0.6rem;">⚠️ malformed</span>`
      : esc(subdomain);

    html += `
      <tr style="background: ${errorBg}; border-bottom: 1px solid #1a2e20;">
        <td style="padding: 8px 12px; color: #00ff88; font-family: monospace;">
          <a href="https://${esc(subdomain)}" target="_blank" rel="noopener"
             style="color: #00ff88; text-decoration: none;"
             onmouseover="this.style.textDecoration='underline'"
             onmouseout="this.style.textDecoration='none'">${domainDisplay}</a>
        </td>
        <td style="padding: 8px 12px; color: #b8cfbe; font-family: monospace;">${esc(String(ip))}</td>
        <td style="padding: 8px 12px; color: ${resolvedColor}; font-weight: bold;">${resolvedLabel}</td>
        <td style="padding: 8px 12px; color: ${statusColor}; font-weight: bold;">${statusLabel}</td>
        <td style="padding: 8px 12px; color: ${sensitiveColor}; font-weight: bold;">${sensitiveDisplay}</td>
        <td style="padding: 8px 12px;">${techHtml}</td>
        <td style="padding: 8px 12px;">${portsHtml}</td>
        <td style="padding: 8px 12px; text-align: center;">${screenshotHtml}</td>
      </tr>
    `;
  });

  html += `</tbody></table></div>`;
  body.innerHTML = html;
}

// ============================================================
// OSINT Render
// ============================================================
function renderOSINT(data) {
  const body = document.getElementById("osintBody");
  const status = document.getElementById("osintStatus");
  if (!body) return;

  if (!data) {
    body.innerHTML = `<p class="no-data">No OSINT data available</p>`;
    if (status) status.textContent = "N/A";
    return;
  }

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }

  let html = "";

  const whois = data.whois || {};
  if (whois && !whois.error) {
    html += `<div class="tech-category"><div class="tech-category-title">📋 WHOIS</div>`;
    html += `<div class="data-row"><span class="data-key">Registrar</span><span class="data-val">${esc(whois.registrar || 'N/A')}</span></div>`;
    html += `<div class="data-row"><span class="data-key">Creation Date</span><span class="data-val">${esc(whois.creation_date || 'N/A')}</span></div>`;
    html += `<div class="data-row"><span class="data-key">Expiration Date</span><span class="data-val">${esc(whois.expiration_date || 'N/A')}</span></div>`;
    if (whois.name_servers && whois.name_servers.length) {
      html += `<div class="data-row"><span class="data-key">Name Servers</span><span class="data-val">${esc(whois.name_servers.join(', '))}</span></div>`;
    }
    html += `</div>`;
  }

  const dns = data.dns_records || {};
  if (Object.keys(dns).length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">🌐 DNS Records</div>`;
    for (const [type, values] of Object.entries(dns)) {
      if (values && values.length > 0) {
        html += `<div class="data-row"><span class="data-key">${esc(type)}</span><span class="data-val">${esc(values.join(', '))}</span></div>`;
      }
    }
    html += `</div>`;
  }

  const wayback = data.wayback_urls || [];
  if (wayback.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📜 Wayback Machine (${wayback.length} URLs)</div>`;
    const display = wayback.slice(0, 10);
    display.forEach(url => {
      html += `<div class="data-row"><span class="data-val" style="word-break:break-all;">${esc(url)}</span></div>`;
    });
    if (wayback.length > 10) {
      html += `<div class="data-row"><span class="data-val">... and ${wayback.length - 10} more</span></div>`;
    }
    html += `</div>`;
  }

  const crt = data.crt_subdomains || [];
  if (crt.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">🔍 crt.sh Subdomains (${crt.length})</div>`;
    const display = crt.slice(0, 20);
    display.forEach(sub => {
      html += `<div class="data-row"><span class="data-val">${esc(sub)}</span></div>`;
    });
    if (crt.length > 20) {
      html += `<div class="data-row"><span class="data-val">... and ${crt.length - 20} more</span></div>`;
    }
    html += `</div>`;
  }

  if (!html) {
    html = `<p class="no-data">No OSINT information found.</p>`;
  }

  body.innerHTML = html;
  if (status) status.textContent = "Complete";
}

// ============================================================
// Risk Prioritization Render
// ============================================================
function renderRisk(data) {
  const body = document.getElementById("riskBody");
  const status = document.getElementById("riskStatus");
  if (!body) return;

  if (!data) {
    body.innerHTML = `<p class="no-data">No risk assessment data</p>`;
    if (status) status.textContent = "N/A";
    return;
  }

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }

  const overall = data.overall_risk || "UNKNOWN";
  const score = data.score !== undefined ? data.score : "—";
  const headline = data.headline || "";
  const findings = data.findings || [];
  const observations = data.observations || [];
  const summary = data.summary || {};

  let riskColor = "#6c757d";
  if (overall === "CRITICAL") riskColor = "#dc3545";
  else if (overall === "HIGH") riskColor = "#fd7e14";
  else if (overall === "MEDIUM") riskColor = "#ffc107";
  else if (overall === "LOW") riskColor = "#28a745";

  let html = `
    <div style="display:flex; align-items:center; gap:20px; flex-wrap:wrap; margin-bottom:16px;">
      <div style="background:${riskColor}; color:white; padding:8px 20px; border-radius:20px; font-weight:bold; font-size:1.1rem;">${overall}</div>
      <div style="background:#1a2e20; color:#00ff88; padding:8px 20px; border-radius:20px; font-weight:bold;">Score: ${score}/100</div>
    </div>
  `;

  if (headline) {
    html += `<p style="color:#aaa; margin-bottom:12px;"><em>${esc(headline)}</em></p>`;
  }

  if (Object.keys(summary).length > 0) {
    html += `<div style="display:flex; gap:16px; flex-wrap:wrap; margin-bottom:12px;">`;
    const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
    for (const [key, count] of Object.entries(summary)) {
      if (count > 0) {
        html += `<span style="background:#1a1a2e; padding:4px 12px; border-radius:12px; color:white;">${labels[key] || key}: ${count}</span>`;
      }
    }
    html += `</div>`;
  }

  if (findings.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">⚠️ Findings (${findings.length})</div>`;
    const display = findings.slice(0, 10);
    display.forEach(f => {
      const sev = f.severity || 'Info';
      let sevColor = "#6c757d";
      if (sev === "CRITICAL") sevColor = "#dc3545";
      else if (sev === "HIGH") sevColor = "#fd7e14";
      else if (sev === "MEDIUM") sevColor = "#ffc107";
      else if (sev === "LOW") sevColor = "#28a745";
      html += `<div class="data-row"><span style="color:${sevColor}; font-weight:bold;">[${sev}]</span> <span class="data-val">${esc(f.description || '')}</span></div>`;
      if (f.recommendation) {
        html += `<div class="data-row" style="padding-left:20px;"><span class="data-key" style="color:#888;">💡</span><span class="data-val" style="font-size:0.85rem; color:#aaa;">${esc(f.recommendation)}</span></div>`;
      }
    });
    if (findings.length > 10) {
      html += `<div class="data-row"><span class="data-val" style="color:#888;">... and ${findings.length - 10} more</span></div>`;
    }
    html += `</div>`;
  } else {
    html += `<p style="color:#00aa55;">✅ No significant risks found.</p>`;
  }

  if (observations.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">ℹ️ Observations (${observations.length})</div>`;
    observations.slice(0, 5).forEach(obs => {
      html += `<div class="data-row"><span class="data-key" style="color:#888;">[${esc(obs.severity || 'Info')}]</span><span class="data-val">${esc(obs.description || '')}</span></div>`;
    });
    html += `</div>`;
  }

  body.innerHTML = html;
  if (status) status.textContent = overall;
}

// ============================================================
// Threat Intelligence Render
// ============================================================
function renderThreatIntel(data) {
  const body = document.getElementById("threatIntelBody");
  const status = document.getElementById("threatIntelStatus");
  if (!body) return;

  if (!data) {
    body.innerHTML = `<p class="no-data">No threat intelligence data available.</p>`;
    if (status) status.textContent = "N/A";
    return;
  }

  if (data.error) {
    body.innerHTML = `<div class="error-msg">${esc(data.error)}</div>`;
    if (status) status.textContent = "FAILED";
    return;
  }

  const summary = data.summary || {};
  const malicious = data.malicious_entities || [];
  const highRisk = data.high_risk_entities || [];

  let html = `
    <div style="display:flex; gap:20px; flex-wrap:wrap; margin-bottom:12px;">
      <div style="background:#1a2e20; padding:8px 16px; border-radius:4px; color:#00ff88;">Checked: ${summary.total_entities || 0}</div>
      <div style="background:#2a1a1a; padding:8px 16px; border-radius:4px; color:#ff4444;">Malicious: ${summary.malicious_count || 0}</div>
      <div style="background:#2a1a1a; padding:8px 16px; border-radius:4px; color:#ff8800;">High Risk: ${summary.high_risk_count || 0}</div>
    </div>
  `;

  if (malicious.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">⚠️ Malicious Entities</div>`;
    malicious.forEach(entity => {
      html += `<div class="data-row"><span class="data-val" style="color:#ff4444;">${esc(entity)}</span></div>`;
    });
    html += `</div>`;
  }

  if (highRisk.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">🔥 High-Risk Entities</div>`;
    highRisk.forEach(entity => {
      html += `<div class="data-row"><span class="data-val" style="color:#ff8800;">${esc(entity)}</span></div>`;
    });
    html += `</div>`;
  }

  const details = data.details || {};
  const scored = [];
  for (const [entity, entityData] of Object.entries(details)) {
    if (entityData && entityData.risk_score !== undefined) {
      scored.push({ entity, score: entityData.risk_score });
    }
  }
  scored.sort((a, b) => b.score - a.score);
  if (scored.length > 0) {
    html += `<div class="tech-category"><div class="tech-category-title">📊 Risk Scores (Top 5)</div>`;
    scored.slice(0, 5).forEach(({ entity, score }) => {
      const color = score > 70 ? "#ff4444" : score > 40 ? "#ff8800" : "#00ff88";
      html += `<div class="data-row"><span class="data-key">${esc(entity)}</span><span class="data-val" style="color:${color}; font-weight:bold;">${score}/100</span></div>`;
    });
    html += `</div>`;
  }

  if (!malicious.length && !highRisk.length && !scored.length) {
    html += `<p style="color:#00aa55;">✅ No threats detected from available intelligence sources.</p>`;
  }

  body.innerHTML = html;
  if (status) status.textContent = "Complete";
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

  const btn = document.querySelector("#automationPanel button");
  btn.textContent = 'Processing Background Workers...';
  btn.disabled = true;

  try {
    const response = await fetch('/api/automation/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls: [url], notify: false })
    });

    const data = await response.json();
    if (data.status === "processing") {
      alert(`Automation Engine Fired:\n${data.message}`);
      loadAutomationStatus();
    } else {
      alert('Scan initiation error.');
    }
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    btn.textContent = 'Trigger Scan Now';
    btn.disabled = false;
  }
}

// ── Email Functions ──
async function loadEmailConfig() {
  const statusEl = document.getElementById('emailStatus');
  if (!statusEl) return;

  statusEl.textContent = 'Loading...';
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

    statusEl.textContent = 'Config loaded';
    statusEl.className = 'email-status success';
  } catch (err) {
    statusEl.textContent = 'Ready';
    statusEl.className = 'email-status success';
  }
}

async function saveEmailConfig() {
  const statusEl = document.getElementById('emailStatus');
  if (!statusEl) return;

  const senderEmail = document.getElementById('senderEmail').value.trim();
  const senderPassword = document.getElementById('senderPassword').value.trim();
  const recipients = document.getElementById('recipientEmails').value.trim();

  if (!senderEmail || !senderPassword || !recipients) {
    statusEl.textContent = 'Please fill out all required fields';
    statusEl.className = 'email-status error';
    return;
  }

  statusEl.textContent = 'Saving...';
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
      statusEl.textContent = 'Email configuration saved successfully!';
      statusEl.className = 'email-status success';
    } else {
      statusEl.textContent = 'Failed: ' + data.error;
      statusEl.className = 'email-status error';
    }
  } catch (err) {
    statusEl.textContent = 'Error: ' + err.message;
    statusEl.className = 'email-status error';
  }
}

async function testEmailConfig() {
  const statusEl = document.getElementById('emailStatus');
  if (!statusEl) return;

  statusEl.textContent = 'Sending test email...';
  statusEl.className = 'email-status loading';

  try {
    const response = await fetch('/api/email/test', { method: 'POST' });
    const data = await response.json();

    if (data.success) {
      statusEl.textContent = 'Test email sent successfully!';
      statusEl.className = 'email-status success';
    } else {
      statusEl.textContent = 'Failed: ' + data.error;
      statusEl.className = 'email-status error';
    }
  } catch (err) {
    statusEl.textContent = 'Error: ' + err.message;
    statusEl.className = 'email-status error';
  }
}

async function downloadPDF() {
  if (!window._lastScanData) {
    alert("No active scan data available to export.");
    return;
  }
  try {
    setStatus("loading", "EXPORTING PDF...");
    const response = await fetch("/api/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(window._lastScanData)
    });
    const data = await response.json();
    if (data.success && data.download_url) {
      window.open(data.download_url, '_blank');
      setStatus("done", "PDF EXPORTED");
    } else {
      alert("Failed to export PDF: " + (data.error || "Unknown error"));
      setStatus("done", "COMPLETE");
    }
  } catch (err) {
    alert("PDF generator connection error: " + err.message);
    setStatus("error", "ERROR");
  }
}

// ── XSS Protection ────────────────────────────────────────
function esc(str) {
  if (str == null) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}