export interface Vulnerability {
  id: string;
  packageName: string;
  packageVersion: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  title: string;
  description?: string;
  references: string[];
  cvss?: number;
  source: string;
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

export interface SupplyChainFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';
  filePath: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  deepInvestigated: boolean;
}

export interface AggregatedPackageFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  highestSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  staticFindings: Vulnerability[];
  supplyChainFindings: SupplyChainFinding[];
}

export interface AggregatedReport {
  aggregatedFindings: AggregatedPackageFinding[];
  aggregatedSummary: {
    totalPackages: number;
    packagesWithStaticFindings: number;
    packagesWithSupplyChainFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
}

export interface ReportData {
  auditResult: AuditResult;
  dependencies: Dependency[];
  scannedDependencies: Dependency[];
  files: DependencyFile[];
  scanPath: string;
  repositoryUrl?: string;
  languageStats?: LanguageStats[];
  dependencyEdges?: DependencyEdge[];
  unresolvedDependencies?: UnresolvedDependency[];
}

export interface FinalReport {
  reportData: ReportData;
  supplyChainReport?: {
    findings: SupplyChainFinding[];
    fetchErrors: unknown[];
    summary: {
      packagesAnalyzed: number;
      packagesWithFindings: number;
      totalFindings: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      byCategory: Record<string, number>;
    };
    timestamp: string;
    model: string;
  };
  aggregatedReport: AggregatedReport;
}

export interface Dependency {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';
  file: string;
  isDev?: boolean;
  depth?: number;
  paths?: string[][];
  provenance?: boolean;
}

export interface DependencyFile {
  path: string;
  relativePath: string;
  type: string;
}

export interface UnresolvedDependency {
  name: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';
  file: string;
  isDev?: boolean;
  reason: 'not_found' | 'registry_unavailable' | 'no_access' | 'invalid_spec';
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

export interface VulnerabilityWithPath extends Vulnerability {
  filePaths: string[];
}
