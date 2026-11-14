/**
 * OSV Vulnerability Scanner Service
 * Queries Google/OpenSSF OSV API (https://osv.dev) for npm package vulnerabilities.
 */

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

/**
 * Clean version string from package.json to standard semver
 * e.g. "^4.17.15" -> "4.17.15", "~1.0.0" -> "1.0.0", "v2.0" -> "2.0.0"
 */
function cleanVersion(raw) {
  if (!raw || typeof raw !== 'string') return '0.0.0';
  
  // Handle git/url/file dependencies
  if (raw.startsWith('git') || raw.startsWith('http') || raw.startsWith('file:') || raw.startsWith('link:')) {
    return null;
  }

  // Strip prefixes like ^, ~, >=, <=, >, <, =, v, workspace:
  let cleaned = raw.replace(/^[\^~><=\s*v]+/, '').trim();
  cleaned = cleaned.replace(/^workspace:[\^~]?/, '').trim();

  // If complex range like "1.2.0 || 1.3.0", take first
  if (cleaned.includes('||')) {
    cleaned = cleaned.split('||')[0].trim();
  }
  // If range like "1.2.0 - 2.0.0", take first
  if (cleaned.includes(' - ')) {
    cleaned = cleaned.split(' - ')[0].trim();
  }

  // Ensure semver format x.y.z
  const parts = cleaned.split('.');
  if (parts.length === 1 && /^\d+$/.test(parts[0])) cleaned = `${parts[0]}.0.0`;
  else if (parts.length === 2 && /^\d+$/.test(parts[0]) && /^\d+$/.test(parts[1])) cleaned = `${parts[0]}.${parts[1]}.0`;

  return cleaned || '0.0.0';
}

/**
 * Determine severity level from OSV vulnerability object
 */
function extractSeverity(vuln) {
  // 1. Check database_specific severity (GitHub/OSV format)
  if (vuln.database_specific && vuln.database_specific.severity) {
    const s = String(vuln.database_specific.severity).toUpperCase();
    if (['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW'].includes(s)) {
      return s === 'MODERATE' ? 'MEDIUM' : s;
    }
  }

  // 2. Check affected array database_specific
  if (Array.isArray(vuln.affected)) {
    for (const aff of vuln.affected) {
      if (aff.database_specific && aff.database_specific.severity) {
        const s = String(aff.database_specific.severity).toUpperCase();
        if (['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW'].includes(s)) {
          return s === 'MODERATE' ? 'MEDIUM' : s;
        }
      }
    }
  }

  // 3. Check CVSS score in severity array
  if (Array.isArray(vuln.severity)) {
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3' && typeof sev.score === 'string') {
        const scoreMatch = sev.score.match(/\/([0-9.]+)/) || [null, null];
        const num = parseFloat(scoreMatch[1]);
        if (!isNaN(num)) {
          if (num >= 9.0) return 'CRITICAL';
          if (num >= 7.0) return 'HIGH';
          if (num >= 4.0) return 'MEDIUM';
          return 'LOW';
        }
      }
    }
  }

  return 'MEDIUM';
}

/**
 * Extract fixed versions from vulnerability affected ranges
 */
function extractFixedVersion(vuln, packageName) {
  if (!Array.isArray(vuln.affected)) return 'No fix published yet';

  const fixedList = [];
  for (const aff of vuln.affected) {
    if (aff.package && aff.package.name && aff.package.name.toLowerCase() !== packageName.toLowerCase()) {
      continue;
    }
    if (Array.isArray(aff.ranges)) {
      for (const r of aff.ranges) {
        if (Array.isArray(r.events)) {
          for (const ev of r.events) {
            if (ev.fixed) fixedList.push(ev.fixed);
          }
        }
      }
    }
  }

  return fixedList.length > 0 ? fixedList.join(', ') : 'No fix published yet';
}

/**
 * Extract CVE and GHSA aliases
 */
function extractAliases(vuln) {
  const cves = [];
  const ghsas = [];

  const allIds = [vuln.id, ...(vuln.aliases || [])].filter(Boolean);
  for (const id of allIds) {
    if (id.startsWith('CVE-')) cves.push(id);
    else if (id.startsWith('GHSA-')) ghsas.push(id);
  }

  return {
    primaryId: vuln.id,
    cve: cves[0] || null,
    cves,
    ghsa: ghsas[0] || null,
    ghsas
  };
}

/**
 * Scan a package.json dependency map using OSV.dev Batch API
 * @param {Object} packageJson parsed package.json object
 * @returns {Promise<Object>} Scan results summary and detailed items
 */
async function scanPackageJson(packageJson) {
  if (!packageJson || typeof packageJson !== 'object') {
    throw new Error('Invalid package.json provided');
  }

  const prodDeps = packageJson.dependencies || {};
  const devDeps = packageJson.devDependencies || {};

  const allPackages = [];

  for (const [name, rawVersion] of Object.entries(prodDeps)) {
    const version = cleanVersion(rawVersion);
    allPackages.push({ name, rawVersion, version, type: 'production' });
  }

  for (const [name, rawVersion] of Object.entries(devDeps)) {
    const version = cleanVersion(rawVersion);
    allPackages.push({ name, rawVersion, version, type: 'development' });
  }

  if (allPackages.length === 0) {
    return {
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
  }

  // Build OSV Batch Query
  const queries = allPackages.map(pkg => ({
    package: {
      name: pkg.name,
      ecosystem: 'npm'
    },
    version: pkg.version
  }));

  // Fetch from OSV in batches of 500 (OSV limit is typically 1000)
  const BATCH_SIZE = 500;
  const rawResults = [];

  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const chunk = queries.slice(i, i + BATCH_SIZE);
    try {
      const response = await fetch(OSV_BATCH_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'GitHub-OSV-Vulnerability-Scanner/1.0'
        },
        body: JSON.stringify({ queries: chunk })
      });

      if (!response.ok) {
        throw new Error(`OSV API responded with status ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      if (Array.isArray(data.results)) {
        rawResults.push(...data.results);
      }
    } catch (err) {
      console.error('Error querying OSV API:', err.message);
      throw err;
    }
  }

  // Process Results
  const packagesList = [];
  const vulnerabilitiesList = [];
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (let idx = 0; idx < allPackages.length; idx++) {
    const pkg = allPackages[idx];
    const osvItem = rawResults[idx] || {};
    const vulns = Array.isArray(osvItem.vulns) ? osvItem.vulns : [];

    const packageVulns = [];

    for (const v of vulns) {
      const severity = extractSeverity(v);
      const fixedIn = extractFixedVersion(v, pkg.name);
      const ids = extractAliases(v);

      if (severity === 'CRITICAL') criticalCount++;
      else if (severity === 'HIGH') highCount++;
      else if (severity === 'MEDIUM') mediumCount++;
      else if (severity === 'LOW') lowCount++;

      const vulnSummary = {
        id: v.id,
        primaryId: ids.primaryId,
        cve: ids.cve,
        ghsa: ids.ghsa,
        packageName: pkg.name,
        installedVersion: pkg.rawVersion,
        resolvedVersion: pkg.version,
        dependencyType: pkg.type,
        severity,
        summary: v.summary || v.details || 'No summary provided',
        details: v.details || '',
        fixedIn,
        published: v.published,
        modified: v.modified,
        references: (v.references || []).map(r => r.url).filter(Boolean)
      };

      packageVulns.push(vulnSummary);
      vulnerabilitiesList.push(vulnSummary);
    }

    packagesList.push({
      name: pkg.name,
      rawVersion: pkg.rawVersion,
      version: pkg.version,
      type: pkg.type,
      isVulnerable: packageVulns.length > 0,
      vulnerabilityCount: packageVulns.length,
      vulnerabilities: packageVulns,
      highestSeverity: packageVulns.reduce((max, cur) => {
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return (order[cur.severity] || 0) > (order[max] || 0) ? cur.severity : max;
      }, 'NONE')
    });
  }

  const vulnerablePackages = packagesList.filter(p => p.isVulnerable);

  return {
    scannedAt: new Date().toISOString(),
    totalPackages: allPackages.length,
    vulnerableCount: vulnerablePackages.length,
    cleanCount: allPackages.length - vulnerablePackages.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    packages: packagesList,
    vulnerabilities: vulnerabilitiesList
  };
}

module.exports = {
  scanPackageJson,
  cleanVersion
};
