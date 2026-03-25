import type { AuditResult, Vulnerability } from '../../auditor/types.js';
import type { Dependency } from '../../scanner/types.js';

export interface ReportData {
  auditResult: AuditResult;
  dependencies: Dependency[];
  scanPath: string;
  repositoryUrl?: string;
}

export interface VulnerabilityWithPath extends Vulnerability {
  filePaths: string[];
}
