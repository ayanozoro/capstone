/**
 * GitHub Integration Service
 * Handles Webhook signature verification, package.json retrieval (Public & Private repos),
 * and GitHub App / Personal Access Token authentication.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Verify GitHub Webhook signature (HMAC SHA-256)
 * @param {string|Buffer|Object} payload Raw request body or parsed payload
 * @param {string} signature Header 'x-hub-signature-256'
 * @param {string} secret Configured webhook secret
 * @returns {{ valid: boolean, reason: string, expected?: string, received?: string }}
 */
function verifyWebhookSignature(payload, signature, secret) {
  if (!secret) {
    return { valid: true, reason: 'no_secret_configured' };
  }
  if (!signature) {
    return { valid: false, reason: 'missing_signature_header' };
  }

  // Calculate HMAC using raw string
  const rawStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(rawStr).digest('hex');

  let matches = false;
  try {
    const bufDigest = Buffer.from(digest);
    const bufSig = Buffer.from(signature);
    if (bufDigest.length === bufSig.length && crypto.timingSafeEqual(bufDigest, bufSig)) {
      matches = true;
    }
  } catch (err) {}

  // If not matched, try compact stringify if payload was an object (handles Smee re-serialization)
  if (!matches && typeof payload === 'object') {
    try {
      const compact = JSON.stringify(payload);
      const compactDigest = 'sha256=' + crypto.createHmac('sha256', secret).update(compact).digest('hex');
      const b1 = Buffer.from(compactDigest);
      const b2 = Buffer.from(signature);
      if (b1.length === b2.length && crypto.timingSafeEqual(b1, b2)) {
        matches = true;
      }
    } catch (e) {}
  }

  return {
    valid: matches,
    reason: matches ? 'verified' : 'signature_mismatch',
    expected: digest,
    received: signature
  };
}

/**
 * Fetch package.json content from GitHub.
 * Automatically checks subfolders including backend/package.json, apps/server/package.json,
 * server/package.json, and root package.json.
 * @param {string} repoFullName e.g. "ayanozoro/openMesh"
 * @param {string} ref Branch name or commit SHA (default: 'main')
 * @param {string} token Optional GitHub token
 * @param {string} hintPath Optional specific file path
 * @returns {Promise<Object>} Parsed package.json object with _detectedPath
 */
async function fetchPackageJson(repoFullName, ref = 'main', token = process.env.GITHUB_TOKEN, hintPath = null) {
  const branchesToTry = [ref, 'main', 'master'].filter((v, i, a) => v && a.indexOf(v) === i);
  
  // Prioritize hintPath if provided, followed by backend, apps/server, root, etc.
  const candidatePaths = [
    hintPath,
    'backend/package.json',
    'apps/server/package.json',
    'server/package.json',
    'package.json',
    'api/package.json',
    'apps/backend/package.json',
    'apps/web/package.json',
    'frontend/package.json'
  ].filter((v, i, a) => v && a.indexOf(v) === i);

  const headers = {
    'User-Agent': 'GitHub-OSV-Vulnerability-Scanner/1.0',
    'Accept': 'application/json, text/plain'
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // 1. Try raw.githubusercontent.com across candidate paths and branches
  for (const filePath of candidatePaths) {
    for (const b of branchesToTry) {
      const rawUrl = `https://raw.githubusercontent.com/${repoFullName}/${b}/${filePath}`;
      try {
        const rawRes = await fetch(rawUrl, { headers });
        if (rawRes.ok) {
          const text = await rawRes.text();
          const parsed = JSON.parse(text);
          console.log(`[GitHub Service] Found package.json at "${filePath}" on branch "${b}" in ${repoFullName}`);
          parsed._detectedPath = filePath;
          return parsed;
        }
      } catch (err) {
        // Continue to next path/branch
      }
    }
  }

  // 2. Fallback: GitHub Contents API across candidate paths
  for (const filePath of candidatePaths) {
    for (const b of branchesToTry) {
      const apiUrl = `https://api.github.com/repos/${repoFullName}/contents/${filePath}?ref=${encodeURIComponent(b)}`;
      const apiHeaders = {
        'User-Agent': 'GitHub-OSV-Vulnerability-Scanner/1.0',
        'Accept': 'application/vnd.github.v3+json'
      };
      if (token) apiHeaders['Authorization'] = `Bearer ${token}`;

      try {
        const apiRes = await fetch(apiUrl, { headers: apiHeaders });
        if (apiRes.ok) {
          const fileData = await apiRes.json();
          if (fileData.encoding === 'base64' && fileData.content) {
            const decoded = Buffer.from(fileData.content, 'base64').toString('utf8');
            const parsed = JSON.parse(decoded);
            console.log(`[GitHub Service] Found package.json via API at "${filePath}" on branch "${b}" in ${repoFullName}`);
            parsed._detectedPath = filePath;
            return parsed;
          }
        }
      } catch (e) {
        // Continue
      }
    }
  }

  throw new Error(`package.json not found in "${repoFullName}" (searched: ${candidatePaths.slice(0, 5).join(', ')}).`);
}

/**
 * Check if the webhook payload indicates any package.json was modified
 * @param {Object} payload GitHub webhook payload
 * @returns {boolean}
 */
function isPackageJsonModified(payload) {
  const actual = (payload && payload.body && typeof payload.body === 'object' && !payload.commits) ? payload.body : payload;
  if (Array.isArray(actual.commits)) {
    for (const commit of actual.commits) {
      const modified = [
        ...(commit.added || []),
        ...(commit.modified || []),
        ...(commit.removed || [])
      ];
      if (modified.some(file => file.toLowerCase().endsWith('package.json'))) {
        return true;
      }
    }
  }

  if (actual.pull_request) {
    return true;
  }

  return false;
}

/**
 * Find the specific package.json file path from modified commit files
 */
function findModifiedPackageJsonPath(payload) {
  const actual = (payload && payload.body && typeof payload.body === 'object' && !payload.commits) ? payload.body : payload;
  if (Array.isArray(actual.commits)) {
    for (const commit of actual.commits) {
      const files = [...(commit.added || []), ...(commit.modified || [])];
      const match = files.find(f => f.toLowerCase().endsWith('package.json'));
      if (match) return match;
    }
  }
  return null;
}

/**
 * Extract human-readable commit / event info from webhook payload
 */
function extractEventDetails(eventName, payload, fallbackRepo = null) {
  // Unwrap if payload is wrapped inside a .body object by Smee or proxies
  const actual = (payload && payload.body && typeof payload.body === 'object' && !payload.repository && !payload.commits)
    ? payload.body
    : payload;

  let repoName = 'unknown/repo';
  let repoUrl = '#';
  let isPrivate = false;

  if (actual.repository) {
    repoName = actual.repository.full_name || actual.repository.name || 'unknown/repo';
    repoUrl = actual.repository.html_url || `https://github.com/${repoName}`;
    isPrivate = !!actual.repository.private;
  } else if (Array.isArray(actual.repositories) && actual.repositories.length > 0) {
    repoName = actual.repositories[0].full_name || actual.repositories[0].name;
    repoUrl = `https://github.com/${repoName}`;
  } else if (Array.isArray(actual.repositories_added) && actual.repositories_added.length > 0) {
    repoName = actual.repositories_added[0].full_name || actual.repositories_added[0].name;
    repoUrl = `https://github.com/${repoName}`;
  } else if (actual.hook && actual.hook.repository) {
    repoName = actual.hook.repository.full_name;
    repoUrl = actual.hook.repository.html_url || `https://github.com/${repoName}`;
  }

  // Fallback to configured or last known repo if still unknown
  if (repoName === 'unknown/repo' && fallbackRepo) {
    repoName = fallbackRepo;
    repoUrl = `https://github.com/${fallbackRepo}`;
  }

  let branch = (actual.repository && actual.repository.default_branch) || 'main';
  let commitSha = '';
  let commitMessage = '';
  let authorName = '';
  let authorAvatar = '';

  if (eventName === 'push') {
    branch = (actual.ref || '').replace('refs/heads/', '') || branch;
    const headCommit = actual.head_commit || (actual.commits && actual.commits[actual.commits.length - 1]);
    if (headCommit) {
      commitSha = (headCommit.id || '').substring(0, 7);
      commitMessage = headCommit.message || 'Git push update';
      authorName = headCommit.author ? (headCommit.author.name || headCommit.author.username) : 'GitHub User';
    }
    if (actual.sender) {
      authorAvatar = actual.sender.avatar_url;
      if (!authorName) authorName = actual.sender.login;
    }
  } else if (eventName === 'pull_request') {
    const pr = actual.pull_request;
    branch = pr ? pr.head.ref : 'pr-branch';
    commitSha = pr && pr.head ? pr.head.sha.substring(0, 7) : '';
    commitMessage = pr ? pr.title : 'Pull Request';
    authorName = pr && pr.user ? pr.user.login : 'PR Author';
    authorAvatar = pr && pr.user ? pr.user.avatar_url : '';
  } else if (eventName === 'ping') {
    commitSha = 'PING';
    commitMessage = `Connected Webhook (${actual.zen || 'Baseline Scan'})`;
    authorName = actual.sender ? actual.sender.login : 'GitHub';
    authorAvatar = actual.sender ? actual.sender.avatar_url : '';
  }

  return {
    event: eventName,
    repoName,
    repoUrl,
    isPrivate,
    branch,
    commitSha,
    commitMessage,
    authorName,
    authorAvatar
  };
}

/**
 * Exchange temporary OAuth code for GitHub user access token
 * @param {string} code Authorization code from GitHub OAuth callback
 * @param {string} clientId GitHub Client ID
 * @param {string} clientSecret GitHub Client Secret
 * @param {string} redirectUri Optional OAuth redirect URI
 * @returns {Promise<string>} Access token
 */
async function exchangeOAuthCode(code, clientId, clientSecret, redirectUri) {
  const bodyData = {
    client_id: clientId,
    client_secret: clientSecret,
    code
  };
  if (redirectUri) bodyData.redirect_uri = redirectUri;

  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'VulnWatch-OSV-Scanner/1.0'
    },
    body: JSON.stringify(bodyData)
  });

  if (!res.ok) {
    throw new Error(`GitHub token exchange HTTP error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  if (data.error) {
    throw new Error(data.error_description || data.error);
  }

  return data.access_token;
}

/**
 * Fetch authenticated GitHub user profile
 * @param {string} token GitHub user token
 * @returns {Promise<Object>} User details (login, avatar_url, name, etc.)
 */
async function getAuthenticatedUser(token) {
  const res = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'VulnWatch-OSV-Scanner/1.0'
    }
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch user profile: ${res.statusText}`);
  }

  return await res.json();
}

/**
 * Fetch repositories accessible to the user
 * @param {string} token GitHub user token
 * @returns {Promise<Array>} List of repositories
 */
async function getUserRepositories(token) {
  const res = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'VulnWatch-OSV-Scanner/1.0'
    }
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Failed to fetch repos: ${res.statusText}`);
  }

  const repos = await res.json();
  return repos.map(r => ({
    id: r.id,
    name: r.name,
    full_name: r.full_name,
    private: !!r.private,
    html_url: r.html_url,
    default_branch: r.default_branch || 'main',
    permissions: r.permissions || { admin: false, push: false, pull: true },
    canAdmin: !!(r.permissions && r.permissions.admin)
  }));
}

/**
 * Check if the webhook is already installed on a repository
 * @param {string} repoFullName e.g. "owner/repo"
 * @param {string} token GitHub user or app token
 * @param {string} targetUrl Target delivery URL (Smee.io or public host)
 */
async function checkRepoWebhook(repoFullName, token, targetUrl) {
  const res = await fetch(`https://api.github.com/repos/${repoFullName}/hooks`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'VulnWatch-OSV-Scanner/1.0'
    }
  });

  if (!res.ok) {
    if (res.status === 404 || res.status === 403) {
      return { installed: false, error: 'insufficient_permissions' };
    }
    return { installed: false, error: res.statusText };
  }

  const hooks = await res.json();
  const normalizedTarget = (targetUrl || '').trim().replace(/\/$/, '');
  const existing = hooks.find(h => {
    const hookUrl = (h.config && h.config.url ? h.config.url : '').trim().replace(/\/$/, '');
    return hookUrl === normalizedTarget;
  });

  return {
    installed: !!existing,
    hookId: existing ? existing.id : null,
    active: existing ? existing.active : false,
    events: existing ? existing.events : []
  };
}

/**
 * Automatically create a webhook on a GitHub repository
 * @param {string} repoFullName e.g. "owner/repo"
 * @param {string} token GitHub user or app token
 * @param {string} targetUrl Webhook delivery URL (e.g. Smee.io)
 * @param {string} secret Webhook HMAC secret
 */
async function createRepoWebhook(repoFullName, token, targetUrl, secret) {
  if (!targetUrl) {
    throw new Error('Target Webhook Delivery URL (SMEE_URL) is not configured.');
  }

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'VulnWatch-OSV-Scanner/1.0'
  };

  // 1. Check if already exists
  const statusCheck = await checkRepoWebhook(repoFullName, token, targetUrl);
  if (statusCheck.installed) {
    return {
      status: 'already_exists',
      message: `Webhook is already configured and active on ${repoFullName}`,
      hookId: statusCheck.hookId
    };
  }

  // 2. Create the webhook
  const body = {
    name: 'web',
    active: true,
    events: ['push', 'pull_request', 'ping'],
    config: {
      url: targetUrl,
      content_type: 'json',
      secret: secret || '',
      insecure_ssl: '0'
    }
  };

  const createRes = await fetch(`https://api.github.com/repos/${repoFullName}/hooks`, {
    method: 'POST',
    headers: {
      ...headers,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  if (!createRes.ok) {
    const errData = await createRes.json().catch(() => ({}));
    const reason = errData.message || `GitHub API error ${createRes.status}`;
    if (createRes.status === 404 || createRes.status === 403) {
      throw new Error(`Permission denied: You need Admin rights on "${repoFullName}" or the "admin:repo_hook" OAuth scope to create webhooks. (${reason})`);
    }
    throw new Error(reason);
  }

  const hook = await createRes.json();
  return {
    status: 'created',
    message: `Webhook installed successfully! GitHub sent an initial ping event.`,
    hookId: hook.id,
    hook
  };
}

/**
 * Delete a repository webhook
 */
async function deleteRepoWebhook(repoFullName, hookId, token) {
  const res = await fetch(`https://api.github.com/repos/${repoFullName}/hooks/${hookId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'VulnWatch-OSV-Scanner/1.0'
    }
  });

  if (!res.ok && res.status !== 404) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Failed to delete hook: ${res.statusText}`);
  }

  return { success: true };
}

module.exports = {
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
};

