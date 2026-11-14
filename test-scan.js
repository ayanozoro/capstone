/**
 * Test script to verify OSV API integration and signature validation
 */

const { scanPackageJson } = require('./services/osvScanner');
const { verifyWebhookSignature, fetchPackageJson } = require('./services/githubService');

async function runTests() {
  console.log('--- 1. Testing OSV Vulnerability Scanner ---');
  const samplePackageJson = {
    name: 'test-app',
    version: '1.0.0',
    dependencies: {
      'lodash': '4.17.15',
      'axios': '0.21.1'
    },
    devDependencies: {
      'minimist': '1.2.0'
    }
  };

  try {
    const result = await scanPackageJson(samplePackageJson);
    console.log(`Scan Succeeded!`);
    console.log(`- Total Packages: ${result.totalPackages}`);
    console.log(`- Vulnerable Packages: ${result.vulnerableCount}`);
    console.log(`- Clean Packages: ${result.cleanCount}`);
    console.log(`- Critical: ${result.criticalCount}`);
    console.log(`- High: ${result.highCount}`);
    console.log(`- Medium: ${result.mediumCount}`);
    console.log(`- Low: ${result.lowCount}`);

    console.log('\nSample Vulnerabilities Found:');
    for (const v of result.vulnerabilities.slice(0, 3)) {
      console.log(`  [${v.severity}] ${v.packageName} (${v.installedVersion}) - ${v.cve || v.ghsa || v.id}: ${v.summary.substring(0, 60)}...`);
      console.log(`    Recommended Fix: ${v.fixedIn}`);
    }
  } catch (err) {
    console.error('OSV Scanner Test Failed:', err);
  }

  console.log('\n--- 2. Testing GitHub Webhook Signature Verification ---');
  const crypto = require('crypto');
  const secret = 'dghdfhsdfjsfgjsfgjf';
  const payload = JSON.stringify({ zen: 'Keep it logically awesome.' });
  const validSignature = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

  const isValid = verifyWebhookSignature(payload, validSignature, secret);
  console.log(`Signature match with correct secret: ${isValid.valid ? 'PASS (Valid)' : 'FAIL'}`);

  console.log('\n--- 3. Testing fetchPackageJson on ayanozoro/openMesh ---');
  try {
    const pkg = await fetchPackageJson('ayanozoro/openMesh');
    console.log(`Successfully fetched from path: "${pkg._detectedPath}"`);
    console.log(`Package Name: ${pkg.name}`);
    const deps = Object.keys(pkg.dependencies || {});
    console.log(`Total Dependencies: ${deps.length} (${deps.slice(0, 5).join(', ')}...)`);
  } catch (err) {
    console.error('Fetch failed:', err.message);
  }
}

runTests();
