/**
 * test-python-package.ts
 *
 * Ad hoc PyPI package scanner for manual validation. It reuses the production
 * planning and per-package analysis logic from `primary-analysis.ts` instead
 * of reimplementing the triage and LLM loop locally.
 */

import assert from 'node:assert/strict';
import { downloadAndExtractTarGz } from './src/supply-chain/registry/tarball.js';
import { formatTriageResults } from './src/supply-chain/llm/tools.js';
import { createChatModel } from './src/supply-chain/llm/client.js';
import { analyzePackageWithModel, planPackageInvestigation } from './src/supply-chain/nodes/primary-analysis.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from './src/supply-chain/types.js';

const PYPI_TEXT_PATTERN = /\.(py|js|ts|sh|json|yml|yaml|toml|cfg|ini|txt|md|pth|bat|ps1)$/i;
const MAX_LLM_FILES = parseInt(process.env.SC_MAX_LLM_FILES ?? '5');

// CDN URLs extracted from the OSV advisory
const TARGETS = [
  {
    label: 'litellm 1.82.8 (malware in litellm_init.pth — auto-executed .pth)',
    version: '1.82.8',
    url: 'https://files.pythonhosted.org/packages/f6/2c/731b614e6cee0bca1e010a36fd381fba69ee836fe3cb6753ba23ef2b9601/litellm-1.82.8.tar.gz',
  },
];

function buildFakeMetadata(version: string): PackageMetadata {
  const signals: RegistrySignals = {
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays: 365 * 3,
    publishedDaysAgo: 5,
    typosquatCandidate: null,
    isDependencyConfusion: false,
    hasProvenance: false,
    riskScore: 1,
  };
  return {
    name: 'litellm',
    ecosystem: 'pypi',
    latestVersion: version,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: new Date().toISOString(),
    weeklyDownloads: 2_000_000,
    maintainers: ['BerriAI'],
    hasInstallScripts: false,
    installScripts: {},
    repositoryUrl: 'https://github.com/BerriAI/litellm',
    description: 'Call all LLM APIs using the OpenAI format',
    registrySignals: signals,
  };
}

async function scanTarget(target: typeof TARGETS[0]) {
  console.log('\n' + '─'.repeat(70));
  console.log(`🎯 Target: ${target.label}`);
  console.log('─'.repeat(70));
  console.log('  ⚠️  SAFETY: tarball is decompressed to in-memory buffer only.');
  console.log('  ⚠️  No extracted code is written to disk or executed.\n');

  console.log('  Downloading tarball...');
  const res = await fetch(target.url);
  if (!res.ok) {
    console.error(`  ✗ Fetch failed: ${res.status} ${res.statusText}`);
    return;
  }
  console.log(`  ✓ Downloaded (${Math.round(Number(res.headers.get('content-length') ?? 0) / 1024)} KB)`);

  const { fileList, fileContents } = await downloadAndExtractTarGz(res, PYPI_TEXT_PATTERN);
  console.log(`  ✓ Extracted ${fileList.length} files, ${Object.keys(fileContents).length} text files read into memory`);

  const source: PackageSource = {
    name: 'litellm',
    ecosystem: 'pypi',
    version: target.version,
    installScripts: {},
    fileList,
    fileContents,
    suspiciousFiles: {},
  };

  const { allContent, triageResults, filesToInvestigate } = planPackageInvestigation(source);

  console.log('\n' + formatTriageResults(triageResults, allContent.size).split('\n').map(l => '  ' + l).join('\n'));
  console.log(`\n  ${filesToInvestigate.length} file(s) selected for LLM investigation (SC_MAX_LLM_FILES=${MAX_LLM_FILES})\n`);
  assert(
    filesToInvestigate.length > 0,
    `Expected suspicious files for ${target.label}, but triage selected none`
  );

  // Show the actual suspicious file content (first 40 lines)
  for (const entry of filesToInvestigate) {
    const content = fileContents[entry.filePath] ?? '';
    const preview = content.split('\n').slice(0, 40).join('\n');
    console.log(`  ┌── ${entry.filePath} (score: ${entry.score})`);
  }

  // Show .pth and any other auto-executed files even if score is low
  const pthFiles = Object.entries(fileContents).filter(([f]) => f.endsWith('.pth'));
  if (pthFiles.length > 0) {
    console.log('  ⚡ .pth files found (auto-executed by Python on startup):');
    for (const [path, content] of pthFiles) {
      console.log(`  ┌── ${path}`);
    }
  }

  // LLM analysis if API key provided and files cross threshold
  const apiKey = process.env.OPENROUTER_API_KEY;
  let findingsCount = 0;
  if (apiKey && filesToInvestigate.length > 0) {
    console.log(`  🤖 Running production package analysis on ${filesToInvestigate.length} file(s)...\n`);
    const chatModel = createChatModel({
      apiKey,
      model: 'anthropic/claude-sonnet-4-5',
      provider: 'openrouter',
    });
    const meta = buildFakeMetadata(target.version);
    const { findings } = await analyzePackageWithModel(meta, source, chatModel, false);
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
  } else if (!apiKey) {
    console.log('  ℹ️  Set OPENROUTER_API_KEY to run LLM analysis on flagged files.');
    console.log(`  ℹ️  ${filesToInvestigate.length} file(s) would be analyzed (SC_MAX_LLM_FILES=${MAX_LLM_FILES}).`);
  }

  return {
    triageCount: filesToInvestigate.length,
    findingsCount,
  };
}

// Run
let targetsWithIssues = 0;
for (const target of TARGETS) {
  const result = await scanTarget(target);
  if (result.triageCount > 0 || result.findingsCount > 0) {
    targetsWithIssues++;
  }
}
assert(targetsWithIssues === TARGETS.length, 'Expected every target to be flagged by the test harness');
console.log('\n✅ Done\n');
