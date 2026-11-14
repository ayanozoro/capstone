/**
 * GitHub Webhook & OSV Vulnerability Scanner Server
 */

// Load .env variables with fallback
try {
  require('dotenv').config();
} catch (e) {
  // Simple fallback .env parser if dotenv is not yet installed
  const fs = require('fs');
  const path = require('path');
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const idx = trimmed.indexOf('=');
        if (idx > 0) {
          const k = trimmed.substring(0, idx).trim();
          const v = trimmed.substring(idx + 1).trim().replace(/^["']|["']$/g, '');
          if (!process.env[k]) process.env[k] = v;
        }
      }
    }
  }
}

const express = require('express');
const cors = require('cors');
const path = require('path');
const { scanPackageJson } = require('./services/osvScanner');
const {
  verifyWebhookSignature,
  fetchPackageJson,
  isPackageJsonModified,
  findModifiedPackageJsonPath,
  extractEventDetails,
  exchangeOAuthCode,
  getAuthenticatedUser,
  getUserRepositories,
  checkRepoWebhook,
  createRepoWebhook,
  deleteRepoWebhook
} = require('./services/githubService');
const SmeeListener = require('./services/smeeClient');

const app = express();
const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || '';
const SMEE_URL = process.env.SMEE_URL || '';
let lastKnownRepo = process.env.DEFAULT_REPO || 'ayanozoro/openMesh';

// In-Memory Storage for Dashboard
const scansHistory = [];
const webhookLogs = [];
let inMemoryUserToken = null;

// Parse HTTP cookies helper
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const key = parts.shift().trim();
      if (key) list[key] = decodeURIComponent(parts.join('='));
    });
  }
  return list;
}

// Resolve GitHub token from Authorization header, Cookie, Memory, or .env
function resolveGitHubToken(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  const cookies = parseCookies(req);
  if (cookies.gh_token) return cookies.gh_token;
  if (inMemoryUserToken) return inMemoryUserToken;
  return process.env.GITHUB_TOKEN || null;
}
const sseClients = new Set();
let smeeStatus = { connected: false, message: 'Initializing...', source: SMEE_URL };

// Express middleware
app.use(cors());

// Capture raw body for GitHub signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));
app.use(express.urlencoded({ extended: true }));

// Serve Dashboard static assets
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Broadcast event to all connected dashboard SSE clients
 */
function broadcastSSE(type, data) {
  const message = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(message);
    } catch (err) {
      sseClients.delete(client);
    }
  }
}

/**
 * Log webhook activity
 */
function logActivity(type, message, details = {}) {
  const logItem = {
    id: 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
    type, // 'info', 'warn', 'error', 'scan', 'ping'
    message,
    details,
    timestamp: new Date().toISOString()
  };
  webhookLogs.unshift(logItem);
  if (webhookLogs.length > 100) webhookLogs.pop();
  broadcastSSE('activity_log', logItem);
  console.log(`[Activity] [${type.toUpperCase()}] ${message}`);
  return logItem;
}

/**
 * Perform vulnerability scan on a package.json and save to history
 */
async function executeScan(meta, packageJson) {
  const scanId = 'scan_' + Date.now();
  logActivity('scan', `Starting vulnerability scan for ${meta.repoName} (${meta.branch})`, { scanId, meta });

  try {
    const scanResult = await scanPackageJson(packageJson);

    const fullRecord = {
      id: scanId,
      ...meta,
      ...scanResult,
      status: 'completed',
      scannedAt: new Date().toISOString()
    };

    scansHistory.unshift(fullRecord);
    if (scansHistory.length > 50) scansHistory.pop();

    logActivity('scan', `Scan complete for ${meta.repoName}: Found ${fullRecord.vulnerableCount} vulnerable packages (${fullRecord.criticalCount} Critical, ${fullRecord.highCount} High)`, {
      scanId,
      total: fullRecord.totalPackages,
      vulnerable: fullRecord.vulnerableCount,
      critical: fullRecord.criticalCount,
      high: fullRecord.highCount
    });

    broadcastSSE('scan_completed', fullRecord);
    return fullRecord;
  } catch (err) {
    const failedRecord = {
      id: scanId,
      ...meta,
      status: 'failed',
      error: err.message,
      scannedAt: new Date().toISOString(),
      totalPackages: 0,
      vulnerableCount: 0,
      cleanCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      packages: [],
      vulnerabilities: []
    };
    scansHistory.unshift(failedRecord);
    logActivity('error', `Scan failed for ${meta.repoName}: ${err.message}`, { scanId, error: err.message });
    broadcastSSE('scan_failed', failedRecord);
    throw err;
  }
}

// ==========================================
// API ROUTES
// ==========================================

/**
 * 1. GitHub Webhook Handler
 */
app.post('/api/webhook', async (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const event = req.headers['x-github-event'] || 'unknown';
  const deliveryId = req.headers['x-github-delivery'] || 'local_' + Date.now();
  // Unwrap if payload is wrapped inside req.body.body or JSON string
  let payload = req.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch (e) {}
  }
  if (payload && payload.body && typeof payload.body === 'object' && !payload.repository && !payload.commits && !payload.ref) {
    payload = payload.body;
  }

  // Extract meta with fallback to lastKnownRepo (e.g. ayanozoro/openMesh)
  const meta = extractEventDetails(event, payload, lastKnownRepo);
  if (meta.repoName && meta.repoName !== 'unknown/repo') {
    lastKnownRepo = meta.repoName;
  }

  console.log(`\n==========================================`);
  console.log(`[Webhook] Incoming GitHub Delivery: ${deliveryId} (Event: ${event})`);
  console.log(`[Webhook] Resolved Repository: ${meta.repoName} (Branch: ${meta.branch})`);

  // Verify HMAC SHA-256 signature
  if (WEBHOOK_SECRET) {
    const isSmeeForwarded = !!req.headers['x-smee-forwarded'] || (req.headers['user-agent'] && req.headers['user-agent'].includes('smee'));
    const verification = verifyWebhookSignature(req.rawBody || payload, signature, WEBHOOK_SECRET);

    if (!verification.valid) {
      if (!signature) {
        logActivity('warn', `Delivery ${deliveryId}: No X-Hub-Signature-256 header sent by GitHub. Please check if Secret is entered in GitHub Webhook settings.`, { event });
      } else {
        logActivity('warn', `Delivery ${deliveryId}: Signature mismatch. Expected: ${verification.expected?.substring(0, 16)}..., Received: ${signature.substring(0, 16)}...`, { event });
      }

      // If strict mode is enforced in .env, reject 401; otherwise allow processing in dev/Smee mode
      const isStrict = process.env.ENFORCE_WEBHOOK_SECRET === 'true';
      if (isStrict) {
        return res.status(401).json({ error: 'Invalid HMAC signature', reason: verification.reason });
      } else {
        logActivity('info', `[Dev Mode] Continuing automatic scan despite signature mismatch (Smee JSON relay). To strictly block, set ENFORCE_WEBHOOK_SECRET=true in .env`);
      }
    } else {
      logActivity('info', `Delivery ${deliveryId}: Signature verified successfully (HMAC SHA-256 matched).`);
    }
  }

  // Handle GitHub 'ping' event (sent when webhook is first added or tested)
  if (event === 'ping') {
    logActivity('ping', `GitHub Ping event received for repo: ${meta.repoName}`, { zen: payload.zen, hook_id: payload.hook_id });

    // Respond to GitHub right away
    res.json({
      message: 'Pong! Webhook connection verified successfully. Running baseline scan...',
      zen: payload.zen,
      repository: meta.repoName,
      scanning: true
    });

    // Run baseline vulnerability scan automatically on the connected repo
    if (meta.repoName && meta.repoName !== 'unknown/repo') {
      try {
        logActivity('info', `Running automatic baseline scan for newly connected repo: ${meta.repoName} (${meta.branch})...`);
        const hintPath = findModifiedPackageJsonPath(payload);
        const packageJson = await fetchPackageJson(meta.repoName, meta.branch, process.env.GITHUB_TOKEN, hintPath);
        meta.packagePath = packageJson._detectedPath || 'package.json';
        await executeScan(meta, packageJson);
      } catch (err) {
        logActivity('warn', `Baseline scan note for ${meta.repoName}: ${err.message}`, { meta, error: err.message });
      }
    }
    return;
  }

  // Handle Push or Pull Request events (Automatic on every push!)
  if (event === 'push' || event === 'pull_request') {
    const hasPackageJsonChange = isPackageJsonModified(payload);

    logActivity('info', `Automated trigger: Received ${event.toUpperCase()} on ${meta.repoName}@${meta.branch} by ${meta.authorName || 'committer'}. Package.json modified: ${hasPackageJsonChange}`, meta);

    // Respond to GitHub right away (GitHub expects HTTP 200 within 10s)
    res.json({
      message: `Webhook accepted for ${meta.repoName}`,
      event,
      branch: meta.branch,
      commit: meta.commitSha,
      scanning: true
    });

    // Automatically run vulnerability scan on the pushed commit/branch
    try {
      logActivity('info', `Automated scan starting: Searching for package.json in ${meta.repoName} (${meta.branch})...`);
      const hintPath = findModifiedPackageJsonPath(payload);
      const packageJson = await fetchPackageJson(meta.repoName, meta.branch, process.env.GITHUB_TOKEN, hintPath);
      meta.packagePath = packageJson._detectedPath || 'package.json';
      logActivity('info', `Found package file at "${meta.packagePath}". Running OSV vulnerability scan...`);
      await executeScan(meta, packageJson);
    } catch (err) {
      logActivity('error', `Automated scan failed for ${meta.repoName}: ${err.message}`, { meta, error: err.message });
    }
    return;
  }

  // Other events (issues, star, fork, etc.)
  logActivity('info', `Ignored unhandled event "${event}" from ${payload.repository ? payload.repository.full_name : 'unknown'}`);
  return res.json({ message: `Event ${event} acknowledged` });
});

/**
 * 2. Server-Sent Events (SSE) for Real-Time Dashboard Updates
 */
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.add(res);

  // Send initial handshake
  res.write(`event: connected\ndata: ${JSON.stringify({ status: 'connected', time: new Date().toISOString() })}\n\n`);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

/**
 * 3. Get Scans History
 */
app.get('/api/scans', (req, res) => {
  res.json({
    total: scansHistory.length,
    scans: scansHistory
  });
});

/**
 * 4. Get Single Scan Details
 */
app.get('/api/scans/:id', (req, res) => {
  const scan = scansHistory.find(s => s.id === req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

/**
 * 5. Get Webhook Logs
 */
app.get('/api/logs', (req, res) => {
  res.json({
    total: webhookLogs.length,
    logs: webhookLogs
  });
});

/**
 * 6. Get Server & Smee Status
 */
app.get('/api/status', (req, res) => {
  res.json({
    serverTime: new Date().toISOString(),
    port: PORT,
    smee: smeeStatus,
    webhookSecretConfigured: !!WEBHOOK_SECRET,
    githubTokenConfigured: !!process.env.GITHUB_TOKEN,
    githubAppConfigured: !!process.env.GITHUB_APP_ID,
    githubAppId: process.env.GITHUB_APP_ID || null,
    totalScans: scansHistory.length,
    activeSSEClients: sseClients.size
  });
});

/**
 * 7. Manual On-Demand Repo Scan
 */
app.post('/api/scan-repo', async (req, res) => {
  const { repo, branch = 'main', token } = req.body;
  if (!repo || !repo.includes('/')) {
    return res.status(400).json({ error: 'Please provide a valid repository in format "owner/repo"' });
  }

  const cleanRepo = repo.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
  const cleanBranch = (branch || 'main').trim();

  const meta = {
    event: 'manual_scan',
    repoName: cleanRepo,
    repoUrl: `https://github.com/${cleanRepo}`,
    isPrivate: false,
    branch: cleanBranch,
    commitSha: 'HEAD',
    commitMessage: 'Manual on-demand scan triggered via Dashboard',
    authorName: 'Dashboard User',
    authorAvatar: ''
  };

  try {
    const useToken = token || process.env.GITHUB_TOKEN;
    const packageJson = await fetchPackageJson(cleanRepo, cleanBranch, useToken);
    const result = await executeScan(meta, packageJson);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * 8. Manual Raw package.json Scan
 */
app.post('/api/scan-raw', async (req, res) => {
  const { content, name = 'custom-package.json' } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'package.json content is required' });
  }

  let parsed;
  try {
    parsed = typeof content === 'object' ? content : JSON.parse(content);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid JSON format: ' + err.message });
  }

  const meta = {
    event: 'raw_scan',
    repoName: parsed.name || name,
    repoUrl: '#',
    isPrivate: false,
    branch: 'local',
    commitSha: 'N/A',
    commitMessage: 'Raw package.json scan',
    authorName: 'Dashboard User',
    authorAvatar: ''
  };

  try {
    const result = await executeScan(meta, parsed);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 9. GITHUB OAUTH & AUTOMATED WEBHOOK SETUP
// ==========================================

/**
 * Initiate GitHub OAuth Flow
 */
app.get('/auth/github', (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return res.status(500).send('GITHUB_CLIENT_ID is not configured in .env');
  }

  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.get('host');
  const redirectUri = `${protocol}://${host}/auth/github/callback`;
  const scopes = 'repo,admin:repo_hook,read:user';

  const authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scopes)}`;
  console.log(`[OAuth] Redirecting user to GitHub authorization: ${authUrl}`);
  res.redirect(authUrl);
});

/**
 * GitHub OAuth Callback Handler
 */
app.get('/auth/github/callback', async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    logActivity('warn', `GitHub authorization was cancelled or failed: ${error_description || error}`);
    return res.redirect(`/?auth=failed&error=${encodeURIComponent(error_description || error)}`);
  }

  if (!code) {
    return res.status(400).send('Authorization code is missing from GitHub callback.');
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.get('host');
  const redirectUri = `${protocol}://${host}/auth/github/callback`;

  try {
    const token = await exchangeOAuthCode(code, clientId, clientSecret, redirectUri);
    inMemoryUserToken = token;

    // Set HTTP cookie valid for 30 days
    res.setHeader('Set-Cookie', `gh_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);

    // Fetch user details for logging
    try {
      const user = await getAuthenticatedUser(token);
      logActivity('info', `GitHub authorization successful! Logged in as @${user.login} (${user.name || 'User'})`);
    } catch (e) {
      logActivity('info', `GitHub authorization successful with user token.`);
    }

    res.redirect('/?auth=success&tab=tab-setup');
  } catch (err) {
    console.error('[OAuth] Token exchange error:', err);
    logActivity('error', `GitHub token exchange failed: ${err.message}`);
    res.redirect(`/?auth=error&message=${encodeURIComponent(err.message)}`);
  }
});

/**
 * Get GitHub Authentication Status & Current User Profile
 */
app.get('/api/auth/status', async (req, res) => {
  const token = resolveGitHubToken(req);
  const hasOAuth = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);

  if (!token) {
    return res.json({
      authenticated: false,
      hasOAuth,
      smeeUrl: SMEE_URL,
      webhookSecretConfigured: !!WEBHOOK_SECRET
    });
  }

  try {
    const user = await getAuthenticatedUser(token);
    return res.json({
      authenticated: true,
      hasOAuth,
      user: {
        login: user.login,
        name: user.name || user.login,
        avatar_url: user.avatar_url,
        html_url: user.html_url,
        public_repos: user.public_repos,
        total_private_repos: user.total_private_repos || 0
      },
      smeeUrl: SMEE_URL,
      webhookSecretConfigured: !!WEBHOOK_SECRET
    });
  } catch (err) {
    return res.json({
      authenticated: false,
      hasOAuth,
      error: err.message,
      smeeUrl: SMEE_URL,
      webhookSecretConfigured: !!WEBHOOK_SECRET
    });
  }
});

/**
 * Manual Token Authentication (e.g. Personal Access Token)
 */
app.post('/api/auth/token', async (req, res) => {
  const { token } = req.body;
  if (!token || !token.trim()) {
    return res.status(400).json({ error: 'GitHub token cannot be empty.' });
  }

  const cleanToken = token.trim();
  try {
    const user = await getAuthenticatedUser(cleanToken);
    inMemoryUserToken = cleanToken;
    res.setHeader('Set-Cookie', `gh_token=${cleanToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);
    logActivity('info', `Personal Access Token linked for @${user.login}`);

    return res.json({
      success: true,
      user: {
        login: user.login,
        name: user.name || user.login,
        avatar_url: user.avatar_url,
        html_url: user.html_url
      }
    });
  } catch (err) {
    return res.status(400).json({ error: `Invalid GitHub token: ${err.message}` });
  }
});

/**
 * Logout / Disconnect GitHub Session
 */
app.post('/api/auth/logout', (req, res) => {
  inMemoryUserToken = null;
  res.setHeader('Set-Cookie', 'gh_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  logActivity('info', 'GitHub account disconnected from dashboard session.');
  res.json({ success: true });
});

/**
 * Fetch List of User's Repositories
 */
app.get('/api/user/repos', async (req, res) => {
  const token = resolveGitHubToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Not authorized with GitHub. Please sign in.' });
  }

  try {
    const repos = await getUserRepositories(token);
    res.json({ repos });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Check if Webhook is installed on a specific repository
 */
app.get('/api/repos/check-webhook', async (req, res) => {
  const token = resolveGitHubToken(req);
  const repo = req.query.repo;
  if (!repo) return res.status(400).json({ error: 'Repository name required (?repo=owner/repo)' });
  if (!token) return res.status(401).json({ error: 'Not authorized with GitHub.' });

  try {
    const status = await checkRepoWebhook(repo, token, SMEE_URL);
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Automatically Setup Webhook on a GitHub Repository
 */
app.post('/api/repos/setup-webhook', async (req, res) => {
  const token = resolveGitHubToken(req);
  const { repo } = req.body;

  if (!repo || !repo.includes('/')) {
    return res.status(400).json({ error: 'Valid repository in format "owner/repo" is required.' });
  }
  if (!token) {
    return res.status(401).json({ error: 'Please authorize with GitHub first.' });
  }
  if (!SMEE_URL) {
    return res.status(500).json({ error: 'SMEE_URL is not configured in .env' });
  }

  try {
    logActivity('info', `Attempting automated webhook installation on ${repo}...`);
    const result = await createRepoWebhook(repo, token, SMEE_URL, WEBHOOK_SECRET);

    logActivity('info', `Automated webhook configured for ${repo}: ${result.status} (Hook ID: ${result.hookId || 'N/A'})`, {
      repo,
      hookId: result.hookId,
      smeeUrl: SMEE_URL
    });

    res.json({
      success: true,
      repo,
      status: result.status,
      message: result.message,
      hookId: result.hookId
    });
  } catch (err) {
    logActivity('error', `Automated webhook setup failed for ${repo}: ${err.message}`, { repo, error: err.message });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Remove Webhook from a GitHub Repository
 */
app.delete('/api/repos/webhook', async (req, res) => {
  const token = resolveGitHubToken(req);
  const { repo, hookId } = req.body;

  if (!repo || !hookId) {
    return res.status(400).json({ error: 'repo and hookId are required.' });
  }
  if (!token) {
    return res.status(401).json({ error: 'Please authorize with GitHub first.' });
  }

  try {
    await deleteRepoWebhook(repo, hookId, token);
    logActivity('info', `Webhook (ID: ${hookId}) deleted from ${repo}`);
    res.json({ success: true, message: `Webhook removed from ${repo}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
const server = app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`  GitHub OSV Vulnerability Scanner is running!         `);
  console.log(`  Dashboard URL:   http://localhost:${PORT}            `);
  console.log(`  Webhook Target:  http://localhost:${PORT}/api/webhook`);
  console.log(`=======================================================`);

  // Start Smee Listener
  const smee = new SmeeListener({
    source: SMEE_URL,
    target: `http://localhost:${PORT}/api/webhook`,
    onStatusChange: (status) => {
      smeeStatus = status;
      broadcastSSE('smee_status', status);
    },
    onMessage: ({ headers, body }) => {
      broadcastSSE('webhook_received', {
        event: headers['x-github-event'],
        delivery: headers['x-github-delivery'],
        repo: body.repository ? body.repository.full_name : 'unknown',
        time: new Date().toISOString()
      });
    }
  });

  smee.start();
});

module.exports = { app, server };
