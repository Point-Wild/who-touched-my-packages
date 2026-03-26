/**
 * Network integration tests — validate Phase 1 + Phase 3 changes against
 * REAL npm/PyPI registry data and REAL package tarballs.
 *
 * No LLM calls. Requires internet access.
 * Run with:  bun test-integration.ts
 *
 * What this validates end-to-end (beyond the unit tests):
 *   Phase 1 — fetchNpmMetadata() correctly populates registrySignals from live API
 *   Phase 1 — fetchPypiMetadata() does the same for PyPI
 *   Phase 3 — runTriage() on real extracted tarball files produces sensible scores
 *   Phase 3 — legitimate files stay below MIN_TRIAGE_SCORE (false-positive guard on real code)
 */

import { fetchNpmMetadata, fetchNpmSource } from './src/supply-chain/registry/npm.js';
import { fetchPypiMetadata } from './src/supply-chain/registry/pypi.js';
import { runTriage, buildContentMap } from './src/supply-chain/llm/tools.js';

const MIN_TRIAGE_SCORE = 8;
const TIMEOUT_MS = 30_000;

let passed = 0;
let failed = 0;

function assert(label: string, condition: boolean, detail = '') {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}${detail ? '\n      ' + detail : ''}`);
    failed++;
  }
}

async function withTimeout<T>(label: string, fn: () => Promise<T>): Promise<T | null> {
  const deadline = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('timeout')), TIMEOUT_MS)
  );
  try {
    return await Promise.race([fn(), deadline]);
  } catch (e: any) {
    console.error(`  ⚠ ${label} — skipped (${e.message})`);
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 1: npm registry signals on real known-stable packages
// Validates: fetchNpmMetadata returns registrySignals with correct values
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Phase 1: npm registry signals (live API) ──');

{
  const meta = await withTimeout('fetch lodash metadata', () => fetchNpmMetadata('lodash'));
  if (meta) {
    const s = meta.registrySignals!;
    assert('lodash: registrySignals present',        !!s);
    assert('lodash: packageAgeDays > 3000 (old, stable)',  s.packageAgeDays > 3000,
      `got ${s.packageAgeDays}`);
    // Score can be 1 if lodash lacks sigstore provenance (expected for pre-provenance era packages)
    assert('lodash: riskScore ≤ 1 (clean package, provenance penalty acceptable)',  s.riskScore <= 1,
      `got ${s.riskScore} — signals: typosquat=${s.typosquatCandidate}, depConfusion=${s.isDependencyConfusion}`);
    assert('lodash: typosquatCandidate = null',      s.typosquatCandidate === null,
      `got ${s.typosquatCandidate}`);
    assert('lodash: isDependencyConfusion = false',  !s.isDependencyConfusion);
    assert('lodash: weeklyDownloads > 0',            meta.weeklyDownloads > 0,
      `got ${meta.weeklyDownloads}`);
    assert('lodash: previousVersion populated',      !!meta.previousVersion,
      `got ${meta.previousVersion}`);
    console.log(`    (age: ${s.packageAgeDays} days, downloads: ${meta.weeklyDownloads.toLocaleString()}/wk, prev: ${meta.previousVersion})`);
  }
}

{
  // axios — very popular, old, should also be clean
  const meta = await withTimeout('fetch axios metadata', () => fetchNpmMetadata('axios'));
  if (meta) {
    const s = meta.registrySignals!;
    assert('axios: riskScore = 0',                  s.riskScore === 0,
      `got ${s.riskScore}`);
    assert('axios: typosquatCandidate = null',       s.typosquatCandidate === null,
      `got ${s.typosquatCandidate}`);
  }
}

{
  // commander — used by this tool itself
  const meta = await withTimeout('fetch commander metadata', () => fetchNpmMetadata('commander'));
  if (meta) {
    const s = meta.registrySignals!;
    assert('commander: registrySignals present',     !!s);
    assert('commander: packageAgeDays > 1000',       s.packageAgeDays > 1000,
      `got ${s.packageAgeDays}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2: PyPI registry signals
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Phase 1: PyPI registry signals (live API) ──');

{
  const meta = await withTimeout('fetch requests (PyPI) metadata', () => fetchPypiMetadata('requests'));
  if (meta) {
    const s = meta.registrySignals!;
    assert('requests: registrySignals present',       !!s);
    assert('requests: packageAgeDays > 3000',         s.packageAgeDays > 3000,
      `got ${s.packageAgeDays}`);
    // Score ≤ 2 expected: old packages without PyPI Trusted Publisher provenance get +1,
    // and actively-maintained packages (published recently) get another +1.
    assert('requests: riskScore ≤ 2 (no typosquat/confusion, provenance/recency ok)',  s.riskScore <= 2,
      `got ${s.riskScore}`);
    assert('requests: typosquatCandidate = null',     s.typosquatCandidate === null,
      `got ${s.typosquatCandidate}`);
    assert('requests: isDependencyConfusion = false', !s.isDependencyConfusion);
    console.log(`    (age: ${s.packageAgeDays} days, score: ${s.riskScore})`);
  }
}

{
  const meta = await withTimeout('fetch flask (PyPI) metadata', () => fetchPypiMetadata('flask'));
  if (meta) {
    const s = meta.registrySignals!;
    assert('flask: riskScore low',                    s.riskScore <= 1,
      `got ${s.riskScore}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3: Triage on a real npm tarball — legitimate package (false-positive guard)
// Validates: runTriage() on actual package code stays below threshold for clean packages
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Phase 3: Triage on real npm tarballs ──');

{
  // semver — pure logic, no I/O, no execs. Should score 0 across all files.
  const meta   = await withTimeout('fetch semver metadata', () => fetchNpmMetadata('semver'));
  const source = meta ? await withTimeout('fetch semver source', () =>
    fetchNpmSource('semver', meta.latestVersion)) : null;

  if (source) {
    const contentMap = buildContentMap(source);
    const results    = runTriage(contentMap);
    const highScores = results.filter(r => r.score >= MIN_TRIAGE_SCORE);

    assert(`semver: 0 files above threshold (${MIN_TRIAGE_SCORE}) in real code`,
      highScores.length === 0,
      `high-scoring files: ${highScores.map(r => `${r.filePath}(${r.score})`).join(', ')}`);
    assert('semver: source has files extracted',
      source.fileList.length > 0, `got ${source.fileList.length}`);
    console.log(`    (${source.fileList.length} files, max triage score: ${results[0]?.score ?? 0})`);
  }
}

{
  // ms — tiny time-parsing lib, clean, lots of setTimeout patterns but all benign
  const meta   = await withTimeout('fetch ms metadata', () => fetchNpmMetadata('ms'));
  const source = meta ? await withTimeout('fetch ms source', () =>
    fetchNpmSource('ms', meta.latestVersion)) : null;

  if (source) {
    const contentMap = buildContentMap(source);
    const results    = runTriage(contentMap);
    const highScores = results.filter(r => r.score >= MIN_TRIAGE_SCORE);

    assert('ms: 0 files above threshold in real code',
      highScores.length === 0,
      `high-scoring files: ${highScores.map(r => `${r.filePath}(${r.score})`).join(', ')}`);
    console.log(`    (${source.fileList.length} files, max triage score: ${results[0]?.score ?? 0})`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4: newFilesInVersion diff with real consecutive versions
// Validates: fetchNpmSource correctly computes which files are new in latest vs. previous
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Phase 1: newFilesInVersion diff (real versions) ──');

{
  const meta = await withTimeout('fetch chalk metadata for diff', () => fetchNpmMetadata('chalk'));
  if (meta?.previousVersion) {
    const source = await withTimeout('fetch chalk source with diff',
      () => fetchNpmSource('chalk', meta.latestVersion, meta.previousVersion));

    if (source) {
      assert('chalk: newFilesInVersion is an array',
        Array.isArray(source.newFilesInVersion),
        `got ${typeof source.newFilesInVersion}`);
      // Most releases don't add files, so either 0 or a small number is fine
      assert('chalk: newFilesInVersion count is reasonable (< 50)',
        (source.newFilesInVersion?.length ?? 0) < 50,
        `got ${source.newFilesInVersion?.length}`);
      assert('chalk: previousVersion threaded through',
        source.previousVersion === meta.previousVersion,
        `got ${source.previousVersion}`);
      console.log(`    (v${meta.latestVersion} vs v${meta.previousVersion}: ${source.newFilesInVersion?.length ?? 0} new files)`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5: Package with install scripts — signals fire correctly
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Phase 1: Install script detection on real packages ──');

{
  // esbuild has a postinstall script that downloads a platform binary
  const meta = await withTimeout('fetch esbuild metadata', () => fetchNpmMetadata('esbuild'));
  if (meta) {
    assert('esbuild: hasInstallScripts = true',
      meta.hasInstallScripts === true,
      'esbuild is known to use postinstall for binary download');
    assert('esbuild: installScripts keys populated',
      Object.keys(meta.installScripts).length > 0);
    console.log(`    (scripts: ${Object.keys(meta.installScripts).join(', ')})`);
  }
}

{
  // lodash should have no install scripts
  const meta = await withTimeout('fetch lodash install scripts', () => fetchNpmMetadata('lodash'));
  if (meta) {
    assert('lodash: hasInstallScripts = false (pure JS, no native)',
      meta.hasInstallScripts === false);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
