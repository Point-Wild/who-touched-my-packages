export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface Vulnerability {
  id: string;
  packageName: string;
  packageVersion: string;
  ecosystem: 'npm' | 'pypi' | 'cargo';
  severity: Severity;
  title: string;
  description: string;
  cvss?: number;
  cwe?: string[];
  references: string[];
  affectedVersions: string;
  fixedVersions?: string;
  publishedDate?: string;
  source: string;
}

export interface AuditResult {
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  scannedPackages: number;
  timestamp: Date;
}
