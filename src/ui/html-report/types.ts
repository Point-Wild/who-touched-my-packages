import type { AuditResult, Vulnerability } from '../../auditor/types.js';
import type { Dependency, DependencyEdge } from '../../scanner/types.js';

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
