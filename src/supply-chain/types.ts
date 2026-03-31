import type { Dependency } from '../scanner/types.js';
import type { LLMProvider } from './llm/models.js';

export type ThreatCategory =
  | 'network-exfiltration'
  | 'credential-harvesting'
  | 'crypto-wallet-theft'
  | 'environment-scanning'
  | 'code-obfuscation'
  | 'persistence'
  | 'data-packaging'
  | 'cicd-poisoning'
  | 'time-bomb'
  | 'trojan-source'
  | 'multi-stage-loader'
  | 'registry-anomaly';

/**
 * Registry-level metadata signals collected during fetch phase.
 * Populated before LLM analysis and passed as context to the LLM.
 */
export interface RegistrySignals {
  /** A new maintainer appeared in the latest release who wasn't in the prior one. */
  maintainerChangedInLatestRelease: boolean;
  /** Maintainer list from the version before latest. */
  previousMaintainers: string[];
  /** Maintainers added in the latest release. */
  newMaintainers: string[];
  /** Days since the package was first published. */
  packageAgeDays: number;
  /** Days since the latest version was published. */
  publishedDaysAgo: number;
  /** Well-known package this name resembles (Levenshtein ≤ 2), or null. */
  typosquatCandidate: string | null;
  /** Package name looks like an internal/private package exposed publicly. */
  isDependencyConfusion: boolean;
  /** Latest release has sigstore/Trusted Publisher provenance attestation. */
  hasProvenance: boolean;
  /** Aggregated 0–10 risk score from all signals above. */
  riskScore: number;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface SupplyChainFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  category: ThreatCategory;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  deepInvestigated: boolean;
}

export interface PackageFetchError {
  packageName: string;
  packageVersion?: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  stage: 'metadata' | 'source';
  message: string;
  statusCode?: number;
}

export interface SupplyChainReport {
  findings: SupplyChainFinding[];
  fetchErrors: PackageFetchError[];
  summary: {
    packagesAnalyzed: number;
    packagesWithFindings: number;
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    byCategory: Partial<Record<ThreatCategory, number>>;
  };
  timestamp: string;
  model: string;
}

export interface SupplyChainOptions {
  apiKey?: string;
  model?: string;
  provider?: LLMProvider;
  concurrency?: number;
  verbose?: boolean;
  /** Transitive dependency depth to analyze. 1 = direct deps only (default). */
  depth?: number;
  /** Hard cap on number of packages analyzed. 0 = unlimited (default). */
  maxPackages?: number;
  dryRun?: boolean;
}

export interface PackageMetadata {
  name: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  latestVersion: string;
  /** The version published immediately before latestVersion (npm only). Used to compute version diffs. */
  previousVersion?: string;
  createdAt: string;
  updatedAt: string;
  weeklyDownloads: number;
  maintainers: string[];
  hasInstallScripts: boolean;
  installScripts: Record<string, string>;
  repositoryUrl?: string;
  description?: string;
  license?: string;
  /** Registry-level risk signals collected at fetch time. */
  registrySignals?: RegistrySignals;
}

export interface PackageSource {
  name: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  version: string;
  /** Entry point file content (index.js, __init__.py, etc.) */
  entryPoint?: string;
  /** Install script contents */
  installScripts: Record<string, string>;
  /** All extracted file names (for pattern scanning) */
  fileList: string[];
  /** All extracted text file contents keyed by path */
  fileContents: Record<string, string>;
  /** Contents of suspicious files (setup.py, postinstall.js, etc.) */
  suspiciousFiles: Record<string, string>;
  /** The previous version string, if available (used for diff context). */
  previousVersion?: string;
  /** Files that are NEW in this version vs. the previous version. */
  newFilesInVersion?: string[];
}

export interface AnalysisState {
  dependencies: Dependency[];
  metadata: Map<string, PackageMetadata>;
  sources: Map<string, PackageSource>;
  fetchErrors: PackageFetchError[];
  primaryFindings: SupplyChainFinding[];
  deepFindings: SupplyChainFinding[];
  result?: SupplyChainReport;
}
