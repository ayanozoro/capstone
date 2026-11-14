/**
 * VulnWatch Client Application
 * Handles Real-Time SSE updates, interactive tabs, filtering, and manual scans.
 */

// State
let currentScan = null;
let scansHistory = [];
let activeSeverityFilter = 'ALL';
let sseConnection = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  initSSE();
  fetchInitialStatus();
  fetchScansHistory();
  fetchLogs();
  initGitHubAuth();
});

// ==========================================
// 1. Server-Sent Events (SSE) Real-Time Sync
// ==========================================
function initSSE() {
  try {
    sseConnection = new EventSource('/api/events');

    sseConnection.addEventListener('connected', (e) => {
      console.log('[SSE] Connected to real-time events stream');
    });

    sseConnection.addEventListener('smee_status', (e) => {
      const data = JSON.parse(e.data);
      updateSmeePill(data.connected, data.message);
    });

    sseConnection.addEventListener('webhook_received', (e) => {
      const data = JSON.parse(e.data);
      showToast(`GitHub Webhook received: ${data.event.toUpperCase()} on ${data.repo}`, 'info');
      appendLogLine('info', `[Delivery] Event: ${data.event} for repo ${data.repo}`);
    });

    sseConnection.addEventListener('scan_completed', (e) => {
      const scan = JSON.parse(e.data);
      showToast(`Scan completed for ${scan.repoName}: ${scan.vulnerableCount} vulnerabilities found`, scan.vulnerableCount > 0 ? 'error' : 'success');
      applyScanData(scan);
      fetchScansHistory(); // refresh history tab
    });

    sseConnection.addEventListener('scan_failed', (e) => {
      const scan = JSON.parse(e.data);
      showToast(`Scan failed for ${scan.repoName}: ${scan.error}`, 'error');
      applyFailedScan(scan);
    });

    sseConnection.addEventListener('activity_log', (e) => {
      const log = JSON.parse(e.data);
      appendLogLine(log.type, `[${log.type.toUpperCase()}] ${log.message}`);
    });

    sseConnection.onerror = () => {
      console.warn('[SSE] EventSource disconnected. Browser will auto-reconnect...');
    };
  } catch (err) {
    console.error('Failed to initialize EventSource:', err);
  }
}

// ==========================================
// 2. Initial Data Fetching
// ==========================================
async function fetchInitialStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.smee) {
      updateSmeePill(data.smee.connected, data.smee.message);
    }
  } catch (err) {
    console.warn('Could not fetch server status:', err);
  }
}

async function fetchScansHistory() {
  try {
    const res = await fetch('/api/scans');
    const data = await res.json();
    scansHistory = data.scans || [];
    document.getElementById('tab-history-count').innerText = scansHistory.length;
    renderHistoryList();

    // If no active scan loaded yet and history exists, load the latest
    if (!currentScan && scansHistory.length > 0) {
      applyScanData(scansHistory[0]);
    }
  } catch (err) {
    console.warn('Could not fetch scans history:', err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    const data = await res.json();
    const logs = data.logs || [];
    const container = document.getElementById('logs-terminal');
    if (logs.length > 0) {
      container.innerHTML = '';
      for (const log of logs.slice().reverse()) {
        appendLogLine(log.type, `[${log.type.toUpperCase()}] ${log.message}`, log.timestamp);
      }
    }
  } catch (err) {
    console.warn('Could not fetch logs:', err);
  }
}

// ==========================================
// 3. UI State Application
// ==========================================
function applyScanData(scan) {
  currentScan = scan;

  // Banner Updates
  document.getElementById('banner-event').innerText = (scan.event || 'SCAN').toUpperCase();
  document.getElementById('banner-repo').innerText = scan.repoName || 'Custom Scan';
  document.getElementById('banner-branch-text').innerText = scan.branch || 'main';
  document.getElementById('banner-commit').innerText = `SHA: ${scan.commitSha || 'HEAD'}`;
  document.getElementById('banner-message').innerText = scan.commitMessage || 'Automated dependency audit';
  document.getElementById('banner-author').innerText = `👤 ${scan.authorName || 'Author'}`;
  document.getElementById('banner-time').innerText = `Scanned: ${new Date(scan.scannedAt).toLocaleTimeString()}`;

  const pathBadge = document.getElementById('banner-path');
  if (pathBadge) {
    if (scan.packagePath || scan._detectedPath) {
      pathBadge.style.display = 'inline-flex';
      pathBadge.innerText = `📁 ${scan.packagePath || scan._detectedPath}`;
    } else {
      pathBadge.style.display = 'none';
    }
  }

  // Verdict update
  const verdict = document.getElementById('banner-verdict');
  const verdictIcon = verdict.querySelector('.verdict-icon');
  const verdictTitle = document.getElementById('verdict-title');
  const verdictSub = document.getElementById('verdict-sub');

  if (scan.vulnerableCount > 0) {
    verdictIcon.className = 'verdict-icon danger';
    verdictIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    verdictTitle.innerText = `${scan.vulnerableCount} Vulnerabilities Found`;
    verdictSub.innerText = `${scan.criticalCount} Critical • ${scan.highCount} High`;
  } else {
    verdictIcon.className = 'verdict-icon safe';
    verdictIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 11 12 14 22 4"></polyline></svg>`;
    verdictTitle.innerText = `All Clear! Safe`;
    verdictSub.innerText = `All ${scan.totalPackages} packages scanned clean`;
  }

  // Stat Counters with numbers animation
  animateCounter('stat-total', scan.totalPackages);
  animateCounter('stat-vulnerable', scan.vulnerabilities ? scan.vulnerabilities.length : 0);
  animateCounter('stat-critical', scan.criticalCount);
  animateCounter('stat-high', scan.highCount);
  animateCounter('stat-medium-low', (scan.mediumCount || 0) + (scan.lowCount || 0));

  document.getElementById('stat-clean-sub').innerText = `${scan.cleanCount} Clean packages`;
  document.getElementById('stat-vuln-pkg-sub').innerText = `In ${scan.vulnerableCount} affected packages`;
  document.getElementById('stat-medium').innerText = scan.mediumCount || 0;
  document.getElementById('stat-low').innerText = scan.lowCount || 0;

  // Tab counters
  document.getElementById('tab-vuln-count').innerText = scan.vulnerabilities ? scan.vulnerabilities.length : 0;
  document.getElementById('tab-pkg-count').innerText = scan.totalPackages || 0;

  // Render lists
  renderVulnerabilitiesList();
  renderPackagesTable();
}

function applyFailedScan(scan) {
  document.getElementById('banner-event').innerText = 'FAILED';
  document.getElementById('banner-repo').innerText = scan.repoName || 'Scan Failed';
  document.getElementById('banner-message').innerText = `Error: ${scan.error || 'package.json could not be located'}`;

  const verdict = document.getElementById('banner-verdict');
  const verdictIcon = verdict.querySelector('.verdict-icon');
  verdictIcon.className = 'verdict-icon danger';
  document.getElementById('verdict-title').innerText = 'Scan Failed';
  document.getElementById('verdict-sub').innerText = (scan.error || 'Check repo path').substring(0, 60);
}

function animateCounter(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const start = parseInt(el.innerText, 10) || 0;
  const target = targetValue || 0;
  if (start === target) {
    el.innerText = target;
    return;
  }
  const duration = 500;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const current = Math.floor(start + (target - start) * progress);
    el.innerText = current;
    if (progress < 1) requestAnimationFrame(update);
    else el.innerText = target;
  }
  requestAnimationFrame(update);
}

// ==========================================
// 4. Vulnerabilities List & Filtering
// ==========================================
function renderVulnerabilitiesList() {
  const container = document.getElementById('vulns-list');
  if (!currentScan || !currentScan.vulnerabilities || currentScan.vulnerabilities.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <h3>No Vulnerabilities Detected</h3>
        <p>All dependencies scanned in <strong>${currentScan ? currentScan.repoName : 'this project'}</strong> have no known security advisories in OSV.dev.</p>
      </div>`;
    return;
  }

  const query = (document.getElementById('vuln-search').value || '').toLowerCase().trim();
  const filtered = currentScan.vulnerabilities.filter(v => {
    // Severity Filter
    if (activeSeverityFilter !== 'ALL' && v.severity !== activeSeverityFilter) {
      return false;
    }
    // Search Query Filter
    if (query) {
      const matchPkg = v.packageName.toLowerCase().includes(query);
      const matchSummary = (v.summary || '').toLowerCase().includes(query);
      const matchCve = (v.cve || '').toLowerCase().includes(query);
      const matchGhsa = (v.ghsa || '').toLowerCase().includes(query);
      const matchId = (v.id || '').toLowerCase().includes(query);
      return matchPkg || matchSummary || matchCve || matchGhsa || matchId;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No vulnerabilities match your filter criteria.</p>
        <button class="btn btn-xs mt-4" onclick="setSeverityFilter('ALL')">Clear Filters</button>
      </div>`;
    return;
  }

  container.innerHTML = filtered.map(v => {
    const sevClass = v.severity ? v.severity.toLowerCase() : 'medium';
    const cveLink = v.cve ? `https://nvd.nist.gov/vuln/detail/${v.cve}` : (v.ghsa ? `https://github.com/advisories/${v.ghsa}` : `https://osv.dev/vulnerability/${v.id}`);
    const fixCommand = v.fixedIn && !v.fixedIn.includes('No fix') ? `npm i ${v.packageName}@${v.fixedIn.split(',')[0].trim()}` : null;

    return `
      <div class="vuln-card border-${sevClass}">
        <div class="vuln-header">
          <div class="vuln-title-group">
            <span class="pkg-badge">${v.packageName}</span>
            <span class="pkg-version">installed: ${v.installedVersion}</span>
            <span class="sev-badge ${sevClass}">${v.severity}</span>
          </div>
          <div class="vuln-identifiers">
            <a href="${cveLink}" target="_blank" rel="noopener noreferrer" class="cve-tag">
              ${v.cve || v.ghsa || v.id} ↗
            </a>
          </div>
        </div>

        <div class="vuln-summary">${escapeHtml(v.summary)}</div>

        <div class="vuln-remediation">
          <div class="fix-info">
            <span class="fix-icon">🔧</span>
            <div>
              <span>Recommended Fix: </span>
              <strong class="fix-pkg">${v.fixedIn}</strong>
            </div>
          </div>
          ${fixCommand ? `
            <div class="remediation-code" onclick="copyText('${fixCommand}')" title="Click to copy upgrade command">
              <code>${fixCommand}</code>
              <span>📋</span>
            </div>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function filterVulns() {
  renderVulnerabilitiesList();
}

function setSeverityFilter(sev) {
  activeSeverityFilter = sev;
  document.querySelectorAll('#severity-filters .filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.sev === sev);
  });
  renderVulnerabilitiesList();
}

// ==========================================
// 5. All Packages Table (SBOM)
// ==========================================
function renderPackagesTable() {
  const tbody = document.getElementById('packages-tbody');
  if (!currentScan || !currentScan.packages || currentScan.packages.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-muted">No package data available</td></tr>`;
    return;
  }

  const query = (document.getElementById('pkg-search').value || '').toLowerCase().trim();
  const filtered = currentScan.packages.filter(p => {
    if (!query) return true;
    return p.name.toLowerCase().includes(query) || (p.rawVersion || '').toLowerCase().includes(query);
  });

  tbody.innerHTML = filtered.map(pkg => {
    const isVuln = pkg.isVulnerable;
    const sevBadge = isVuln && pkg.highestSeverity !== 'NONE'
      ? `<span class="sev-badge ${pkg.highestSeverity.toLowerCase()}">${pkg.highestSeverity}</span>`
      : `<span class="text-muted">—</span>`;

    return `
      <tr>
        <td><strong>${pkg.name}</strong></td>
        <td><code>${pkg.rawVersion}</code></td>
        <td><code>${pkg.version}</code></td>
        <td><span class="badge" style="background: rgba(255,255,255,0.06);">${pkg.type}</span></td>
        <td>
          <span class="status-badge ${isVuln ? 'vulnerable' : 'clean'}">
            ${isVuln ? '⚠️ Vulnerable' : '✓ Clean'}
          </span>
        </td>
        <td>${pkg.vulnerabilityCount > 0 ? `<strong>${pkg.vulnerabilityCount}</strong>` : '0'}</td>
        <td>${sevBadge}</td>
      </tr>
    `;
  }).join('');
}

function filterPackages() {
  renderPackagesTable();
}

// ==========================================
// 6. Manual Scan Handlers
// ==========================================
async function handleRepoScan(e) {
  e.preventDefault();
  const repoInput = document.getElementById('input-repo-name').value.trim();
  const branchInput = document.getElementById('input-repo-branch').value.trim() || 'main';
  const tokenInput = document.getElementById('input-repo-token').value.trim();
  const btn = document.getElementById('btn-submit-repo-scan');

  btn.disabled = true;
  btn.innerText = 'Scanning Repository...';

  try {
    const res = await fetch('/api/scan-repo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo: repoInput, branch: branchInput, token: tokenInput || undefined })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to scan repository');

    showToast(`Scan successful! Audited ${data.totalPackages} packages.`, 'success');
    applyScanData(data);
    switchTab('tab-vulns');
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerText = 'Run OSV Vulnerability Scan';
  }
}

async function handleRawScan(e) {
  e.preventDefault();
  const jsonContent = document.getElementById('input-raw-json').value;
  const btn = document.getElementById('btn-submit-raw-scan');

  btn.disabled = true;
  btn.innerText = 'Auditing Dependencies...';

  try {
    const res = await fetch('/api/scan-raw', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: jsonContent })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to parse and scan JSON');

    showToast(`Audit complete: Found ${data.vulnerableCount} vulnerable packages`, 'success');
    applyScanData(data);
    switchTab('tab-vulns');
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerText = 'Analyze Dependencies';
  }
}

// Sample loaders
function fillTestRepo(name, version) {
  document.getElementById('input-raw-json').value = JSON.stringify({
    name: "test-vulnerable-app",
    version: "1.0.0",
    dependencies: {
      [name]: version
    }
  }, null, 2);
  switchTab('tab-manual');
}

function loadVulnerableSampleJson() {
  document.getElementById('input-raw-json').value = JSON.stringify({
    "name": "sample-vulnerable-node-app",
    "version": "1.0.0",
    "dependencies": {
      "lodash": "4.17.15",
      "axios": "0.21.1",
      "jsonwebtoken": "8.5.1",
      "express": "4.16.0",
      "minimist": "1.2.5"
    },
    "devDependencies": {
      "mocha": "8.0.0"
    }
  }, null, 2);
  showToast('Loaded sample vulnerable package.json! Click "Analyze Dependencies" to test.', 'info');
}

// ==========================================
// 7. History List
// ==========================================
function renderHistoryList() {
  const container = document.getElementById('history-container');
  if (scansHistory.length === 0) {
    container.innerHTML = `<div class="empty-state"><p>No previous scans found.</p></div>`;
    return;
  }

  container.innerHTML = scansHistory.map(item => `
    <div class="card glass-card mb-4" style="margin-bottom: 12px; cursor: pointer;" onclick="loadHistoryScan('${item.id}')">
      <div class="vuln-header">
        <div>
          <strong style="font-size: 1.05rem;">${item.repoName}</strong>
          <span class="pkg-version" style="margin-left: 8px;">branch: ${item.branch || 'main'}</span>
        </div>
        <div>
          <span class="status-badge ${item.vulnerableCount > 0 ? 'vulnerable' : 'clean'}">
            ${item.vulnerableCount > 0 ? `${item.vulnerableCount} Vulnerabilities` : 'All Clean'}
          </span>
        </div>
      </div>
      <div style="font-size: 0.82rem; color: var(--text-dim); margin-top: 6px;">
        Scanned: ${new Date(item.scannedAt).toLocaleString()} • Total Packages: ${item.totalPackages}
      </div>
    </div>
  `).join('');
}

function loadHistoryScan(id) {
  const scan = scansHistory.find(s => s.id === id);
  if (scan) {
    applyScanData(scan);
    switchTab('tab-vulns');
    showToast(`Loaded scan for ${scan.repoName}`, 'info');
  }
}

// ==========================================
// 8. Terminal Logs Stream
// ==========================================
function appendLogLine(type, message, timestamp = null) {
  const container = document.getElementById('logs-terminal');
  if (!container) return;
  const timeStr = timestamp ? new Date(timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = `log-line ${type}`;
  div.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="log-msg">${escapeHtml(message)}</span>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function clearLogs() {
  const container = document.getElementById('logs-terminal');
  if (container) container.innerHTML = '';
}

// ==========================================
// 9. UI Helpers & Navigation
// ==========================================
function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

  const targetPane = document.getElementById(tabId);
  if (targetPane) targetPane.classList.add('active');

  const targetBtn = document.getElementById(`btn-${tabId}`);
  if (targetBtn) targetBtn.classList.add('active');
}

function updateSmeePill(connected, message) {
  const text = document.getElementById('smee-status-text');
  const dot = document.querySelector('#smee-pill .dot');
  if (text) text.innerText = connected ? 'Online' : 'Reconnecting';
  if (dot) {
    dot.className = `dot ${connected ? 'pulse-green' : 'pulse-amber'}`;
  }
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function copyText(str) {
  navigator.clipboard.writeText(str).then(() => {
    showToast('Copied to clipboard!', 'success');
  }).catch(() => {
    prompt('Copy value:', str);
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m];
  });
}

// ==========================================
// 10. GITHUB OAUTH & AUTOMATED WEBHOOK SETUP
// ==========================================

let authenticatedUser = null;
let userRepositories = [];
let currentSelectedHookId = null;

async function initGitHubAuth() {
  const urlParams = new URLSearchParams(window.location.search);

  if (urlParams.get('auth') === 'success') {
    showToast('GitHub authorized successfully! Ready to configure webhooks.', 'success');
    switchTab('tab-setup');
    window.history.replaceState({}, document.title, window.location.pathname);
  } else if (urlParams.get('auth') === 'failed' || urlParams.get('auth') === 'error') {
    const errorMsg = urlParams.get('error') || urlParams.get('message') || 'Unknown error';
    showToast(`GitHub authorization failed: ${errorMsg}`, 'error');
    switchTab('tab-setup');
    window.history.replaceState({}, document.title, window.location.pathname);
  } else if (urlParams.get('tab')) {
    switchTab(urlParams.get('tab'));
  }

  await checkAuthStatus();
}

async function checkAuthStatus() {
  const authPillDot = document.getElementById('github-auth-dot');
  const authPillText = document.getElementById('github-auth-text');
  const unauthBox = document.getElementById('github-unauthenticated-box');
  const authBox = document.getElementById('github-authenticated-box');

  try {
    const res = await fetch('/api/auth/status');
    const data = await res.json();

    if (data.smeeUrl) {
      const smeeCode = document.getElementById('auto-setup-smee');
      if (smeeCode) smeeCode.innerText = data.smeeUrl;
    }

    if (data.authenticated && data.user) {
      authenticatedUser = data.user;

      if (authPillDot) authPillDot.className = 'dot pulse-green';
      if (authPillText) authPillText.innerText = `@${data.user.login}`;

      if (unauthBox) unauthBox.style.display = 'none';
      if (authBox) authBox.style.display = 'block';

      // Update User Profile Card
      const avatarImg = document.getElementById('user-avatar-img');
      const displayName = document.getElementById('user-display-name');
      const displayLogin = document.getElementById('user-display-login');

      if (avatarImg) avatarImg.src = data.user.avatar_url;
      if (displayName) displayName.innerText = data.user.name || data.user.login;
      if (displayLogin) displayLogin.innerText = `@${data.user.login}`;

      await loadUserRepos();
    } else {
      authenticatedUser = null;
      if (authPillDot) authPillDot.className = 'dot pulse-amber';
      if (authPillText) authPillText.innerText = 'Not Linked';

      if (unauthBox) unauthBox.style.display = 'block';
      if (authBox) authBox.style.display = 'none';
    }
  } catch (err) {
    console.warn('Could not check GitHub auth status:', err);
  }
}

async function loadUserRepos() {
  const select = document.getElementById('select-user-repo');
  if (!select) return;

  select.innerHTML = '<option value="">Loading your repositories...</option>';

  try {
    const res = await fetch('/api/user/repos');
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Failed to fetch repositories.');
    }

    userRepositories = data.repos || [];

    if (userRepositories.length === 0) {
      select.innerHTML = '<option value="">No repositories found where you have Admin permissions</option>';
      return;
    }

    select.innerHTML = userRepositories.map(r => {
      const lock = r.private ? '🔒 ' : '🌐 ';
      return `<option value="${escapeHtml(r.full_name)}">${lock}${escapeHtml(r.full_name)} (${escapeHtml(r.default_branch)})</option>`;
    }).join('');

    // Check status of first repo
    await onRepoSelectionChanged();
  } catch (err) {
    select.innerHTML = `<option value="">Error: ${escapeHtml(err.message)}</option>`;
    showToast(`Error loading repositories: ${err.message}`, 'error');
  }
}

async function onRepoSelectionChanged() {
  const select = document.getElementById('select-user-repo');
  const statusBadge = document.getElementById('selected-repo-status');
  const btnInstall = document.getElementById('btn-install-webhook');
  const btnRemove = document.getElementById('btn-remove-webhook');

  if (!select || !select.value) return;

  const repo = select.value;
  if (statusBadge) {
    statusBadge.className = 'webhook-status-badge checking';
    statusBadge.innerHTML = '<span>Checking GitHub...</span>';
  }

  try {
    const res = await fetch(`/api/repos/check-webhook?repo=${encodeURIComponent(repo)}`);
    const data = await res.json();

    if (data.installed) {
      currentSelectedHookId = data.hookId;
      if (statusBadge) {
        statusBadge.className = 'webhook-status-badge active';
        statusBadge.innerHTML = `<span>Active ✅ (Hook ID: ${data.hookId || 'Live'})</span>`;
      }
      if (btnInstall) btnInstall.querySelector('span').innerText = '🔄 Re-register Webhook';
      if (btnRemove) btnRemove.style.display = 'inline-flex';
    } else {
      currentSelectedHookId = null;
      if (statusBadge) {
        statusBadge.className = 'webhook-status-badge inactive';
        statusBadge.innerHTML = '<span>Not Configured ⚠️</span>';
      }
      if (btnInstall) btnInstall.querySelector('span').innerText = '⚡ Auto-Install Webhook';
      if (btnRemove) btnRemove.style.display = 'none';
    }
  } catch (err) {
    if (statusBadge) {
      statusBadge.className = 'webhook-status-badge inactive';
      statusBadge.innerHTML = '<span>Status Unknown</span>';
    }
  }
}

async function handleAutoInstallWebhook() {
  const select = document.getElementById('select-user-repo');
  const btnInstall = document.getElementById('btn-install-webhook');

  if (!select || !select.value) {
    showToast('Please select a repository first.', 'error');
    return;
  }

  const repo = select.value;
  const originalText = btnInstall.querySelector('span').innerText;
  btnInstall.disabled = true;
  btnInstall.querySelector('span').innerText = 'Installing Webhook...';

  try {
    const res = await fetch('/api/repos/setup-webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Failed to install webhook');
    }

    showToast(`Webhook successfully configured on ${repo}! GitHub sent a ping event.`, 'success');
    await onRepoSelectionChanged();
  } catch (err) {
    showToast(`Failed to install webhook: ${err.message}`, 'error');
  } finally {
    btnInstall.disabled = false;
    btnInstall.querySelector('span').innerText = originalText;
  }
}

async function scanSelectedRepoNow() {
  const select = document.getElementById('select-user-repo');
  if (!select || !select.value) return;

  const repo = select.value;
  showToast(`Starting on-demand vulnerability scan for ${repo}...`, 'info');

  try {
    const res = await fetch('/api/scan-repo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo, branch: 'main' })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    applyScanData(data);
    showToast(`Scan complete for ${repo}!`, 'success');
    switchTab('tab-vulns');
  } catch (err) {
    showToast(`Scan failed: ${err.message}`, 'error');
  }
}

async function handleRemoveWebhook() {
  const select = document.getElementById('select-user-repo');
  if (!select || !select.value || !currentSelectedHookId) return;

  const repo = select.value;
  if (!confirm(`Are you sure you want to remove the VulnWatch webhook from ${repo}?`)) {
    return;
  }

  try {
    const res = await fetch('/api/repos/webhook', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo, hookId: currentSelectedHookId })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    showToast(`Webhook removed from ${repo}`, 'info');
    await onRepoSelectionChanged();
  } catch (err) {
    showToast(`Failed to remove webhook: ${err.message}`, 'error');
  }
}

async function saveManualToken() {
  const input = document.getElementById('input-pat-token');
  if (!input || !input.value.trim()) {
    showToast('Please enter a GitHub Personal Access Token.', 'error');
    return;
  }

  try {
    const res = await fetch('/api/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: input.value.trim() })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    input.value = '';
    showToast(`Connected as @${data.user.login}!`, 'success');
    await checkAuthStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function disconnectGitHub() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    showToast('GitHub disconnected.', 'info');
    await checkAuthStatus();
  } catch (err) {
    showToast('Failed to disconnect.', 'error');
  }
}

function refreshUserRepos() {
  showToast('Reloading repositories from GitHub...', 'info');
  loadUserRepos();
}

