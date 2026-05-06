/**
 * Unit tests for LLM prompt building logic.
 * Tests that registry signals and new-file warnings appear in prompts.
 */

import { buildInvestigationKickoff, buildFileAnalysisPrompt } from './prompts.js';
import type { PackageMetadata, PackageSource } from '../types.js';
import type { TriageResult } from './tools.js';

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

console.log('\n── Prompt content: registry signals and new-file warnings ──');

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
  name: 'lodahs',
  ecosystem: 'npm',
  version: '2.0.0',
  previousVersion: '1.9.9',
  fileList: ['package/index.js', 'package/lib/helper.js'],
  newFilesInVersion: ['lib/helper.js'],
  entryPoint: '',
  suspiciousFiles: {},
  installScripts: {},
  fileContents: {},
};

const kickoff = buildInvestigationKickoff(mockMeta, mockSource);

assert('kickoff prompt includes risk score',
  kickoff.includes('9/10'));
assert('kickoff prompt flags HIGH risk score',
  kickoff.includes('HIGH'));
assert('kickoff prompt shows new maintainer name',
  kickoff.includes('eve'));
assert('kickoff prompt shows replaced maintainer (old → new)',
  kickoff.includes('alice') && kickoff.includes('→'));
assert('kickoff prompt shows typosquat candidate',
  kickoff.includes('lodash'));
assert('kickoff prompt shows no-provenance',
  kickoff.includes('NO'));

// New-file warning in per-file prompt
const mockTriage: TriageResult = {
  filePath: 'package/lib/helper.js',
  score: 12,
  indicators: new Map([['eval-on-response', 3]]),
  categories: new Set(['loader']),
};

const filePromptWithNew = buildFileAnalysisPrompt(mockMeta, mockTriage, 'eval(response)', mockSource);
const filePromptNoSource = buildFileAnalysisPrompt(mockMeta, mockTriage, 'eval(response)');

assert('new-file warning appears when file is in newFilesInVersion',
  filePromptWithNew.includes('NEW FILE'));
assert('new-file warning includes previous version number',
  filePromptWithNew.includes('1.9.9'));
assert('no new-file warning when source not provided',
  !filePromptNoSource.includes('NEW FILE'));

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
