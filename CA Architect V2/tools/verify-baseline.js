#!/usr/bin/env node

const childProcess = require('child_process');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const vm = require('vm');

const UPSTREAM_REPO = 'j0eyv/ConditionalAccessBaseline';
const PINNED_COMMIT = '1af233f9ab6bbf609d6e42b383bd0af5aa258774';
const PINNED_VERSION = '2026.6.1';

const APPROVED_OVERRIDES = [
  {
    sourceFile: 'Config/ConditionalAccess/CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency.json',
    path: 'sessionControls.signInFrequency.value',
    local: 4,
    upstream: 12,
    reason: 'CA Architect V2 hardening override: administrators default to a 4-hour sign-in frequency.'
  }
];

function parseArgs(argv) {
  const args = {
    local: path.resolve(process.cwd(), 'baseline-data.js'),
    upstream: '',
    report: '',
    json: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--local') args.local = path.resolve(argv[++i]);
    else if (arg === '--upstream') args.upstream = path.resolve(argv[++i]);
    else if (arg === '--report') args.report = path.resolve(argv[++i]);
    else if (arg === '--json') args.json = true;
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage: node tools/verify-baseline.js [options]

Options:
  --local <file>       Local baseline-data.js path. Defaults to ./baseline-data.js.
  --upstream <dir>     Cloned ${UPSTREAM_REPO} directory. If omitted, the pinned GitHub tarball is downloaded.
  --report <file>      Write a JSON audit report.
  --json               Print the full audit report as JSON.
  --help               Show this help.
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const tempDirs = [];

  try {
    const upstreamDir = args.upstream || await downloadPinnedUpstream(tempDirs);
    const localBaseline = loadLocalBaseline(args.local);
    const upstreamSource = args.upstream || `https://github.com/${UPSTREAM_REPO}/tree/${PINNED_COMMIT}`;
    const report = verifyBaseline(localBaseline, args.local, upstreamDir, upstreamSource);

    if (args.report) {
      fs.mkdirSync(path.dirname(args.report), { recursive: true });
      fs.writeFileSync(args.report, `${JSON.stringify(report, null, 2)}\n`);
    }

    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printSummary(report);
    }

    if (report.summary.unexpectedDifferences || report.summary.missingLocal || report.summary.missingUpstream) {
      process.exitCode = 1;
    }
  } finally {
    tempDirs.forEach(dir => fs.rmSync(dir, { recursive: true, force: true }));
  }
}

function loadLocalBaseline(file) {
  const source = fs.readFileSync(file, 'utf8');
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: file });
  if (!sandbox.window.CA_BASELINE) throw new Error(`No window.CA_BASELINE object found in ${file}`);
  return sandbox.window.CA_BASELINE;
}

async function downloadPinnedUpstream(tempDirs) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ca-baseline-'));
  tempDirs.push(tempDir);

  const archive = path.join(tempDir, 'baseline.tar.gz');
  const url = `https://codeload.github.com/${UPSTREAM_REPO}/tar.gz/${PINNED_COMMIT}`;
  await downloadFile(url, archive);
  childProcess.execFileSync('tar', ['-xzf', archive, '-C', tempDir], { stdio: 'ignore' });

  const dirs = fs.readdirSync(tempDir)
    .map(name => path.join(tempDir, name))
    .filter(item => fs.statSync(item).isDirectory());
  const upstream = dirs.find(dir => fs.existsSync(path.join(dir, 'Config', 'ConditionalAccess')));
  if (!upstream) throw new Error('Downloaded upstream archive did not contain Config/ConditionalAccess.');
  return upstream;
}

function downloadFile(url, destination) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { 'User-Agent': 'ca-architect-baseline-verifier' } }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadFile(response.headers.location, destination).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Download failed with HTTP ${response.statusCode}: ${url}`));
        return;
      }
      const file = fs.createWriteStream(destination);
      response.pipe(file);
      file.on('finish', () => file.close(resolve));
      file.on('error', reject);
    });
    request.on('error', reject);
  });
}

function verifyBaseline(localBaseline, localFile, upstreamDir, upstreamSource) {
  const upstreamPolicyDir = path.join(upstreamDir, 'Config', 'ConditionalAccess');
  const upstreamFiles = fs.readdirSync(upstreamPolicyDir)
    .filter(file => file.endsWith('.json'))
    .sort()
    .map(file => `Config/ConditionalAccess/${file}`);
  const localPolicies = localBaseline.policies || [];
  const localBySource = new Map(localPolicies.map(policy => [policy.sourceFile, policy]));
  const upstreamSet = new Set(upstreamFiles);

  const policyResults = [];
  const approvedOverrides = [];
  const unexpectedDifferences = [];
  const missingLocal = [];

  upstreamFiles.forEach(sourceFile => {
    const localPolicy = localBySource.get(sourceFile);
    if (!localPolicy) {
      missingLocal.push({ sourceFile });
      policyResults.push({ sourceFile, status: 'missing-local' });
      return;
    }

    const upstreamPolicy = readJson(path.join(upstreamDir, sourceFile));
    const diffs = diffObjects(policyShape(localPolicy.policy), policyShape(upstreamPolicy))
      .filter(item => item.path !== 'displayName');
    const unexpected = [];
    const approved = [];

    diffs.forEach(item => {
      const override = approvedOverrideFor(sourceFile, item);
      if (override) approved.push({ ...item, reason: override.reason });
      else unexpected.push(item);
    });

    if (unexpected.length) {
      const result = {
        sourceFile,
        id: localPolicy.id,
        displayName: localPolicy.displayName,
        status: approved.length ? 'unexpected-with-approved-override' : 'unexpected-difference',
        approvedOverrides: approved,
        unexpectedDifferences: unexpected
      };
      policyResults.push(result);
      unexpectedDifferences.push(result);
      return;
    }

    if (approved.length) {
      const result = {
        sourceFile,
        id: localPolicy.id,
        displayName: localPolicy.displayName,
        status: 'approved-override',
        approvedOverrides: approved
      };
      policyResults.push(result);
      approvedOverrides.push(result);
      return;
    }

    policyResults.push({
      sourceFile,
      id: localPolicy.id,
      displayName: localPolicy.displayName,
      status: 'match'
    });
  });

  const missingUpstream = localPolicies
    .filter(policy => policy.sourceFile && policy.sourceFile.startsWith('Config/ConditionalAccess/') && !upstreamSet.has(policy.sourceFile))
    .map(policy => ({ sourceFile: policy.sourceFile, id: policy.id, displayName: policy.displayName }));

  const exactMatches = policyResults.filter(result => result.status === 'match').length;

  return {
    generatedAt: new Date().toISOString(),
    upstream: {
      repo: `https://github.com/${UPSTREAM_REPO}`,
      version: PINNED_VERSION,
      commit: PINNED_COMMIT,
      source: upstreamSource
    },
    local: {
      baselineFile: displayPath(localFile),
      version: localBaseline.version,
      commit: localBaseline.commit
    },
    summary: {
      upstreamPolicies: upstreamFiles.length,
      localPolicies: localPolicies.length,
      exactMatches,
      approvedOverrides: approvedOverrides.length,
      unexpectedDifferences: unexpectedDifferences.length,
      missingLocal: missingLocal.length,
      missingUpstream: missingUpstream.length
    },
    approvedOverrides,
    unexpectedDifferences,
    missingLocal,
    missingUpstream,
    policies: policyResults
  };
}

function displayPath(file) {
  const relative = path.relative(process.cwd(), path.resolve(file));
  return relative && !relative.startsWith('..') ? relative : path.resolve(file);
}

function readJson(file) {
  const buffer = fs.readFileSync(file);
  const text = buffer[0] === 0xff && buffer[1] === 0xfe
    ? buffer.subarray(2).toString('utf16le')
    : buffer.toString('utf8').replace(/^\uFEFF/, '');
  return JSON.parse(text);
}

function policyShape(policy) {
  return normalize({
    displayName: policy.displayName,
    state: policy.state,
    conditions: policy.conditions,
    grantControls: policy.grantControls,
    sessionControls: policy.sessionControls
  }) || {};
}

function normalize(value) {
  if (value === null || value === undefined) return undefined;
  if (Array.isArray(value)) {
    const items = value.map(normalize).filter(item => item !== undefined);
    return items.length
      ? items.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
      : undefined;
  }
  if (typeof value === 'object') {
    const output = {};
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .forEach(([key, nested]) => {
        if (isGraphNoiseKey(key)) return;
        const normalized = normalize(nested);
        if (normalized !== undefined) output[key] = normalized;
      });
    return Object.keys(output).length ? output : undefined;
  }
  return value;
}

function isGraphNoiseKey(key) {
  return key.includes('@odata') ||
    key.startsWith('#microsoft.graph.') ||
    [
      'id',
      'templateId',
      'createdDateTime',
      'modifiedDateTime',
      'deletedDateTime',
      'partialEnablementStrategy'
    ].includes(key);
}

function diffObjects(local, upstream, currentPath = '', output = []) {
  if (JSON.stringify(local) === JSON.stringify(upstream)) return output;
  if (
    local === undefined ||
    upstream === undefined ||
    local === null ||
    upstream === null ||
    typeof local !== 'object' ||
    typeof upstream !== 'object' ||
    Array.isArray(local) ||
    Array.isArray(upstream)
  ) {
    output.push({ path: currentPath || '<root>', local, upstream });
    return output;
  }

  const keys = [...new Set([...Object.keys(local), ...Object.keys(upstream)])].sort();
  keys.forEach(key => diffObjects(local[key], upstream[key], currentPath ? `${currentPath}.${key}` : key, output));
  return output;
}

function approvedOverrideFor(sourceFile, diff) {
  return APPROVED_OVERRIDES.find(override =>
    override.sourceFile === sourceFile &&
    override.path === diff.path &&
    JSON.stringify(override.local) === JSON.stringify(diff.local) &&
    JSON.stringify(override.upstream) === JSON.stringify(diff.upstream)
  );
}

function printSummary(report) {
  console.log(`ConditionalAccessBaseline ${report.upstream.version} parity`);
  console.log(`Upstream commit: ${report.upstream.commit}`);
  console.log(`Policies: ${report.summary.localPolicies} local / ${report.summary.upstreamPolicies} upstream`);
  console.log(`Exact meaningful matches: ${report.summary.exactMatches}`);
  console.log(`Approved overrides: ${report.summary.approvedOverrides}`);
  console.log(`Unexpected differences: ${report.summary.unexpectedDifferences}`);

  report.approvedOverrides.forEach(result => {
    result.approvedOverrides.forEach(override => {
      console.log(`- Approved override ${result.id} ${override.path}: local ${override.local}, upstream ${override.upstream}`);
    });
  });

  report.unexpectedDifferences.forEach(result => {
    console.log(`- Unexpected difference ${result.id} ${result.sourceFile}`);
    result.unexpectedDifferences.forEach(diff => {
      console.log(`  ${diff.path}: local=${JSON.stringify(diff.local)} upstream=${JSON.stringify(diff.upstream)}`);
    });
  });
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
