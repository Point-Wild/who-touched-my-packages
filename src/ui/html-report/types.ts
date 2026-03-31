import type { AuditResult, Vulnerability } from '../../auditor/types.js';
import type { Dependency, DependencyEdge, DependencyFile, UnresolvedDependency } from '../../scanner/types.js';

export interface LanguageStats {
  language: string;
  fileCount: number;
  percentage: number;
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

export interface VulnerabilityWithPath extends Vulnerability {
  filePaths: string[];
}
