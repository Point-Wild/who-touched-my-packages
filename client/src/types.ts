export interface Vulnerability {
  id: string;
  packageName: string;
  packageVersion: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  title: string;
  description?: string;
  references: string[];
  cvss?: number;
}

export interface AuditSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface AuditResult {
  vulnerabilities: Vulnerability[];
  summary: AuditSummary;
  scannedPackages: number;
  timestamp: string;
}

export interface Dependency {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi';
  file: string;
  isDev?: boolean;
  depth?: number;
  paths?: string[][];
}

export interface DependencyEdge {
  source: string;
  target: string;
  type: 'dependency' | 'dev';
}

export interface LanguageStats {
  language: string;
  fileCount: number;
  percentage: number;
}

export interface ReportData {
  auditResult: AuditResult;
  dependencies: Dependency[];
  scanPath: string;
  repositoryUrl?: string;
  languageStats?: LanguageStats[];
  dependencyEdges?: DependencyEdge[];
}

export interface VulnerabilityWithPath extends Vulnerability {
  filePaths: string[];
}
