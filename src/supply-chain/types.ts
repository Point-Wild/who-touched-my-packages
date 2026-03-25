import type { Dependency } from '../scanner/types.js';

export type ThreatCategory =
  | 'network-exfiltration'
  | 'credential-harvesting'
  | 'crypto-wallet-theft'
  | 'environment-scanning'
  | 'code-obfuscation'
  | 'persistence'
  | 'data-packaging'
  | 'cicd-poisoning';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface SupplyChainFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: 'npm' | 'pypi';
  category: ThreatCategory;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  deepInvestigated: boolean;
}

export interface SupplyChainReport {
  findings: SupplyChainFinding[];
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
  provider?: 'anthropic' | 'openrouter' | 'openai';
  concurrency?: number;
}

export interface PackageMetadata {
  name: string;
  ecosystem: 'npm' | 'pypi';
  latestVersion: string;
  createdAt: string;
  updatedAt: string;
  weeklyDownloads: number;
  maintainers: string[];
  hasInstallScripts: boolean;
  installScripts: Record<string, string>;
  repositoryUrl?: string;
  description?: string;
  license?: string;
}

export interface PackageSource {
  name: string;
  ecosystem: 'npm' | 'pypi';
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
}

export interface AnalysisState {
  dependencies: Dependency[];
  metadata: Map<string, PackageMetadata>;
  sources: Map<string, PackageSource>;
  primaryFindings: SupplyChainFinding[];
  deepFindings: SupplyChainFinding[];
  result?: SupplyChainReport;
}
