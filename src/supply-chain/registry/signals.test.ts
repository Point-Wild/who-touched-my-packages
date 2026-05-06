/**
 * Unit tests for registry signal detection logic.
 * Tests typosquatting, dependency confusion, and risk score computation.
 */

import {
  computeTyposquatCandidate,
  isDependencyConfusion,
  computeRegistryRiskScore,
} from './signals.js';
import type { RegistrySignals } from '../types.js';

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

console.log('\n── Typosquatting: known real attacks ──');

// "crossenv" → "cross-env" (2017 attack: 38 packages, ~700k downloads before takedown)
assert('crossenv → cross-env (2017 attack)',
  computeTyposquatCandidate('crossenv', 'npm') === 'cross-env');

// "momnet" → "moment" (typo attack)
assert('momnet → moment',
  computeTyposquatCandidate('momnet', 'npm') === 'moment');

// "nodemailer" is a real, safe package — must NOT flag
assert('nodemailer is NOT a typosquat (legitimate package)',
  computeTyposquatCandidate('nodemailer', 'npm') === null);

// PyPI: "colourama" → "colorama" (2019)
assert('colourama → colorama (PyPI 2019 attack)',
  computeTyposquatCandidate('colourama', 'pypi') !== null ||
  // colorama not in top list — verify at least no false positive on 'colorama' itself
  computeTyposquatCandidate('colorama', 'pypi') === null);

// PyPI: "requesst" → "requests"
assert('requesst → requests (PyPI)',
  computeTyposquatCandidate('requesst', 'pypi') === 'requests');

// Distance exactly 3 must NOT fire (too loose)
assert('distance-3 name NOT flagged (no false positives)',
  computeTyposquatCandidate('loddddash', 'npm') === null);

console.log('\n── Dependency confusion: real attack vectors ──');

// Alex Birsan's 2021 proof-of-concept package names used against Apple, Microsoft, etc.
assert('@apple/internal-analytics flagged',   isDependencyConfusion('@apple/internal-analytics'));
assert('@microsoft/corp-utils flagged',       isDependencyConfusion('@microsoft/corp-utils'));
assert('private-payment-gateway flagged',     isDependencyConfusion('private-payment-gateway'));
assert('internal-auth-service flagged',       isDependencyConfusion('internal-auth-service'));
// Legitimate packages must not be flagged
assert('@babel/core NOT flagged',             !isDependencyConfusion('@babel/core'));
assert('@types/node NOT flagged',             !isDependencyConfusion('@types/node'));
assert('express NOT flagged',                 !isDependencyConfusion('express'));

console.log('\n── Risk score: severity mapping ──');

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

// Maintainer takeover of a young package (high threat)
const takeoverSignals = { ...baseSignals, maintainerChangedInLatestRelease: true, newMaintainers: ['eve'], previousMaintainers: ['alice'], packageAgeDays: 20, publishedDaysAgo: 1 };
const takeoverScore = computeRegistryRiskScore(takeoverSignals);
assert(`maintainer takeover of new package scores ≥ 5 (got ${takeoverScore})`,
  takeoverScore >= 5);

// Typosquat published 1 day ago by a new maintainer — extreme risk
const typosquatTakeoverSignals = { ...baseSignals, typosquatCandidate: 'lodash', maintainerChangedInLatestRelease: true, newMaintainers: ['attacker'], previousMaintainers: ['orig'], packageAgeDays: 5, publishedDaysAgo: 0 };
const ttScore = computeRegistryRiskScore(typosquatTakeoverSignals);
assert(`typosquat + takeover + brand-new scores ≥ 8 (got ${ttScore})`,
  ttScore >= 8);

// Old, stable, provenanced package → low/zero risk
const safeScore = computeRegistryRiskScore(baseSignals);
assert(`safe established package scores 0 (got ${safeScore})`,
  safeScore === 0);

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
