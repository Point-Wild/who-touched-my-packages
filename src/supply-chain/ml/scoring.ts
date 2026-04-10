/**
 * ML-based package scoring pipeline.
 *
 * Replaces the simple triage score threshold with a trained XGBoost classifier
 * that uses statistical features + triage patterns + package-level signals.
 *
 * Pipeline per package:
 *   1. For each file: extract stat features (115-d) + triage features (68-d)
 *   2. Compute package-level features across all files
 *   3. Build 183-d feature vector per file (trimmed to model's expected dimensions)
 *   4. Run XGBoost → malicious probability per file
 *   5. Return files sorted by probability (highest first)
 */

import type { PackageSource, PackageMetadata } from '../types.js';
import { buildContentMap } from '../llm/tools.js';
import {
  extractStatFeatures,
  extractTriageFeatures,
  computePackageFeatures,
  buildFeatureVector,
  type TriageFeatures,
  type PackageLevelFeatures,
} from './feature-extraction.js';
import { predictMaliciousProba, getModelInfo } from './xgboost-inference.js';

export interface ScoredFile {
  filePath: string;
  maliciousProba: number;
  triageScore: number;
  nCategories: number;
  matchedPatterns: string[];
}

export interface PackageScore {
  maxFileProba: number;
  meanFileProba: number;
  scoredFiles: ScoredFile[];
}

/**
 * Score all files in a package using ML features + XGBoost.
 * Returns scored files sorted by malicious probability (highest first).
 */
export function scorePackage(
  source: PackageSource,
  _meta?: PackageMetadata,
  existingContent?: Map<string, string>,
): PackageScore {
  const allContent = existingContent ?? buildContentMap(source);

  // Phase 1: Extract per-file features
  const fileStatFeatures = new Map<string, number[]>();
  const fileTriageResults = new Map<string, TriageFeatures>();
  const fileTriageScores = new Map<string, number>();

  for (const [filePath, content] of allContent) {
    const statFeats = extractStatFeatures(content);
    const triageFeats = extractTriageFeatures(content, filePath);

    fileStatFeatures.set(filePath, statFeats);
    fileTriageResults.set(filePath, triageFeats);
    fileTriageScores.set(filePath, triageFeats.finalScore);
  }

  // Phase 2: Package-level features
  const pkgFeatures = computePackageFeatures(
    fileTriageScores,
    fileTriageResults,
    fileStatFeatures,
  );

  // Phase 3: Build feature vectors and predict
  const scoredFiles: ScoredFile[] = [];

  for (const [filePath, content] of allContent) {
    const statFeats = fileStatFeatures.get(filePath)!;
    const triageFeats = fileTriageResults.get(filePath)!;

    // Set per-file package features
    const filePkgFeatures: PackageLevelFeatures = {
      ...pkgFeatures,
      scoreRatio: pkgFeatures.maxTriageScore > 0
        ? triageFeats.finalScore / pkgFeatures.maxTriageScore
        : 0,
    };

    let featureVec = buildFeatureVector(statFeats, triageFeats, filePkgFeatures);

    // Trim to model's expected feature count (pkg-level features exceed model dimensions)
    const { numFeatures } = getModelInfo();
    if (featureVec.length > numFeatures) {
      featureVec = featureVec.slice(0, numFeatures);
    }

    const proba = predictMaliciousProba(featureVec);

    // Collect matched pattern names for context
    const matchedPatterns: string[] = [];
    const patternNames = [
      'http-request-api', 'http-post-data', 'curl-wget-nc', 'fetch-xhr',
      'socket-connect', 'socket-import', 'dns-exfil', 'external-url',
      'known-c2', 'telegram-exfil', 'discord-webhook', 'suspicious-tld',
      'metadata-endpoint', 'credential-files', 'system-files', 'homedir-read',
      'crypto-wallets', 'seed-mnemonic', 'browser-wallets',
      'env-bulk-dump', 'env-iterate-all', 'env-filter-pattern', 'env-regex-secrets',
      'env-spread-into-payload', 'env-reduce-collect', 'env-printenv', 'env-secrets-named',
      'dynamic-exec', 'subprocess-launch', 'base64-decode-exec', 'marshal-pickle',
      'dynamic-import', 'python-pip-install', 'python-codecs-decode', 'python-compile-exec',
      'python-setup-override', 'python-pty-spawn', 'python-os-system',
      'python-socket-connect', 'python-urllib', 'python-http-client',
      'string-concat-hide', 'hex-base64-blob', 'chr-obfuscation', 'exec-chr-combo',
      'encoded-powershell', 'child-process', 'discord-token-steal',
      'install-script', 'build-injection',
      'ci-workflow-write', 'ci-tool-exec', 'proc-docker-access',
      'shell-profile', 'system-persist',
      'archive-encrypt', 'known-artifacts',
      'monkey-patch', 'prototype-pollute',
      'timebomb-date', 'timebomb-delay', 'conditional-os',
      'unicode-bidi', 'zero-width-chars',
    ];
    for (let i = 0; i < triageFeats.counts.length && i < patternNames.length; i++) {
      if (triageFeats.counts[i] > 0) {
        matchedPatterns.push(patternNames[i]);
      }
    }

    scoredFiles.push({
      filePath,
      maliciousProba: proba,
      triageScore: triageFeats.finalScore,
      nCategories: triageFeats.nCategories,
      matchedPatterns,
    });
  }

  // Sort by probability descending
  scoredFiles.sort((a, b) => b.maliciousProba - a.maliciousProba);

  const probas = scoredFiles.map(f => f.maliciousProba);

  return {
    maxFileProba: probas.length ? Math.max(...probas) : 0,
    meanFileProba: probas.length ? probas.reduce((a, b) => a + b, 0) / probas.length : 0,
    scoredFiles,
  };
}
