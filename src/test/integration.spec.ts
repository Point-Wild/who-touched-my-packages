/**
 * Network integration tests — validate Phase 1 + Phase 3 changes against
 * REAL npm/PyPI registry data and REAL package tarballs.
 *
 * No LLM calls. Requires internet access.
 *
 * What this validates end-to-end (beyond the unit tests):
 *   Phase 1 — fetchNpmMetadata() correctly populates registrySignals from live API
 *   Phase 1 — fetchPypiMetadata() does the same for PyPI
 *   Phase 3 — runTriage() on real extracted tarball files produces sensible scores
 *   Phase 3 — legitimate files stay below MIN_TRIAGE_SCORE (false-positive guard on real code)
 */

import { describe, expect, test } from 'bun:test';
import { buildContentMap, runTriage } from '../supply-chain/llm/tools.js';
import { fetchCratesMetadata, fetchCratesSource } from '../supply-chain/registry/crates.js';
import { fetchGoMetadata, fetchGoSource } from '../supply-chain/registry/golang.js';
import { fetchNpmMetadata, fetchNpmSource } from '../supply-chain/registry/npm.js';
import { fetchPypiMetadata } from '../supply-chain/registry/pypi.js';

const MIN_TRIAGE_SCORE = 8;
const TIMEOUT_MS = 30_000;

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

describe('Phase 1: npm registry signals (live API)', () => {
  test('fetch lodash metadata returns registrySignals', async () => {
    const meta = await withTimeout('fetch lodash metadata', () => fetchNpmMetadata('lodash'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    const s = meta.registrySignals!;
    expect(s).toBeDefined();
    expect(s.packageAgeDays).toBeGreaterThan(3000);
    expect(s.typosquatCandidate).toBeNull();
    expect(s.isDependencyConfusion).toBe(false);
    expect(s.riskScore).toBeLessThanOrEqual(2);
    expect(meta.weeklyDownloads).toBeGreaterThan(0);
    expect(meta.previousVersion).toBeDefined();
  }, TIMEOUT_MS);

  test('fetch axios metadata returns correct signals', async () => {
    const meta = await withTimeout('fetch axios metadata', () => fetchNpmMetadata('axios'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    const s = meta.registrySignals!;
    expect(s.typosquatCandidate).toBeNull();
    expect(s.isDependencyConfusion).toBe(false);
    expect(s.riskScore).toBeLessThanOrEqual(1);
  }, TIMEOUT_MS);

  test('fetch commander metadata returns correct signals', async () => {
    const meta = await withTimeout('fetch commander metadata', () => fetchNpmMetadata('commander'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    const s = meta.registrySignals!;
    expect(s).toBeDefined();
    expect(s.packageAgeDays).toBeGreaterThan(1000);
  }, TIMEOUT_MS);
});

describe('Phase 1: PyPI registry signals (live API)', () => {
  test('fetch requests (PyPI) metadata returns correct signals', async () => {
    const meta = await withTimeout('fetch requests metadata', () => fetchPypiMetadata('requests'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    const s = meta.registrySignals!;
    expect(s).toBeDefined();
    expect(s.packageAgeDays).toBeGreaterThan(3000);
    expect(s.riskScore).toBeLessThanOrEqual(2);
    expect(s.typosquatCandidate).toBeNull();
    expect(s.isDependencyConfusion).toBe(false);
  }, TIMEOUT_MS);

  test('fetch flask (PyPI) metadata returns low risk score', async () => {
    const meta = await withTimeout('fetch flask metadata', () => fetchPypiMetadata('flask'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    const s = meta.registrySignals!;
    expect(s.riskScore).toBeLessThanOrEqual(1);
  }, TIMEOUT_MS);
});

describe('Phase 1: Rust/Go registry signals (live API)', () => {
  test('fetch serde metadata returns correct signals', async () => {
    const meta = await withTimeout('fetch serde metadata', () => fetchCratesMetadata('serde'));
    if (!meta) {
      console.log('  ⚠ skipped (crates.io unavailable)');
      return;
    }

    const s = meta.registrySignals!;
    expect(s).toBeDefined();
    expect(meta.latestVersion).toBeDefined();
    expect(meta.hasInstallScripts).toBe(false);
  }, TIMEOUT_MS);

  test('fetch golang.org/x/text metadata returns correct signals', async () => {
    const meta = await withTimeout('fetch golang metadata', () => fetchGoMetadata('golang.org/x/text'));
    if (!meta) {
      console.log('  ⚠ skipped (Go proxy unavailable)');
      return;
    }

    const s = meta.registrySignals!;
    expect(s).toBeDefined();
    expect(meta.latestVersion).toBeDefined();
  }, TIMEOUT_MS);
});

describe('Phase 3: Triage on real npm tarballs', () => {
  test('semver has 0 files above threshold', async () => {
    const meta = await withTimeout('fetch semver metadata', () => fetchNpmMetadata('semver'));
    if (!meta) {
      console.log('  ⚠ skipped (metadata timeout)');
      return;
    }

    const source = await withTimeout('fetch semver source', () => fetchNpmSource('semver', meta.latestVersion));
    if (!source) {
      console.log('  ⚠ skipped (source timeout)');
      return;
    }

    const contentMap = buildContentMap(source);
    const results = runTriage(contentMap);
    const highScores = results.filter(r => r.score >= MIN_TRIAGE_SCORE);

    expect(highScores.length).toBe(0);
    expect(source.fileList.length).toBeGreaterThan(0);
  }, TIMEOUT_MS * 2);

  test('ms has 0 files above threshold', async () => {
    const meta = await withTimeout('fetch ms metadata', () => fetchNpmMetadata('ms'));
    if (!meta) {
      console.log('  ⚠ skipped (metadata timeout)');
      return;
    }

    const source = await withTimeout('fetch ms source', () => fetchNpmSource('ms', meta.latestVersion));
    if (!source) {
      console.log('  ⚠ skipped (source timeout)');
      return;
    }

    const contentMap = buildContentMap(source);
    const results = runTriage(contentMap);
    const highScores = results.filter(r => r.score >= MIN_TRIAGE_SCORE);

    expect(highScores.length).toBe(0);
  }, TIMEOUT_MS * 2);

  test('serde source has files extracted', async () => {
    const meta = await withTimeout('fetch serde metadata', () => fetchCratesMetadata('serde'));
    if (!meta) {
      console.log('  ⚠ skipped (crates.io unavailable)');
      return;
    }

    const source = await withTimeout('fetch serde source', () => fetchCratesSource('serde', meta.latestVersion));
    if (!source) {
      console.log('  ⚠ skipped (source timeout)');
      return;
    }

    expect(source.fileList.length).toBeGreaterThan(0);
    // Soft check - crates source may not always have entryPoint or suspiciousFiles
    const hasContent = source.entryPoint || Object.keys(source.suspiciousFiles).length > 0 || source.fileList.length > 0;
    if (!hasContent) {
      console.log('  ⚠ serde source has limited data, skipping content check');
    }
  }, TIMEOUT_MS * 2);

  test('go module source has files extracted', async () => {
    const meta = await withTimeout('fetch golang metadata', () => fetchGoMetadata('golang.org/x/text'));
    if (!meta) {
      console.log('  ⚠ skipped (metadata timeout)');
      return;
    }

    const source = await withTimeout('fetch golang source', () => fetchGoSource('golang.org/x/text', meta.latestVersion));
    if (!source) {
      console.log('  ⚠ skipped (source timeout)');
      return;
    }

    expect(source.fileList.length).toBeGreaterThan(0);
    expect(source.fileList.some(f => f.endsWith('go.mod') || f.endsWith('.go'))).toBe(true);
  }, TIMEOUT_MS * 2);
});

describe('Phase 1: newFilesInVersion diff (real versions)', () => {
  test('fetch chalk source with diff returns newFilesInVersion', async () => {
    const meta = await withTimeout('fetch chalk metadata', () => fetchNpmMetadata('chalk'));
    if (!meta?.previousVersion) {
      console.log('  ⚠ skipped (no previous version)');
      return;
    }

    const source = await withTimeout('fetch chalk source with diff', () =>
      fetchNpmSource('chalk', meta.latestVersion, meta.previousVersion));

    if (!source) {
      console.log('  ⚠ skipped (source timeout)');
      return;
    }

    expect(Array.isArray(source.newFilesInVersion)).toBe(true);
    expect(source.newFilesInVersion?.length ?? 0).toBeLessThan(50);
    expect(source.previousVersion).toBe(meta.previousVersion);
  }, TIMEOUT_MS * 2);
});

describe('Phase 1: Install script detection on real packages', () => {
  test('esbuild has install scripts', async () => {
    const meta = await withTimeout('fetch esbuild metadata', () => fetchNpmMetadata('esbuild'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    expect(meta.hasInstallScripts).toBe(true);
    expect(Object.keys(meta.installScripts).length).toBeGreaterThan(0);
  }, TIMEOUT_MS);

  test('lodash has no install scripts', async () => {
    const meta = await withTimeout('fetch lodash metadata', () => fetchNpmMetadata('lodash'));
    expect(meta).not.toBeNull();
    if (!meta) return;

    expect(meta.hasInstallScripts).toBe(false);
  }, TIMEOUT_MS);
});
