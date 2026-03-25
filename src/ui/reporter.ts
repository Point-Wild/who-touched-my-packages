import type { AuditResult, Vulnerability } from '../auditor/types.js';
import type { DependencyFile } from '../scanner/types.js';
import { formatFileList, formatSummary, formatVulnerability } from './formatters.js';
import { theme } from './theme.js';

export interface ReporterOptions {
  json?: boolean;
  severityFilter?: string;
  verbose?: boolean;
}

export class Reporter {
  private options: ReporterOptions;
  
  constructor(options: ReporterOptions = {}) {
    this.options = options;
  }
  
  reportFiles(files: DependencyFile[]): void {
    if (this.options.json) {
      return;
    }
    
    console.log(formatFileList(files));
  }
  
  reportResults(result: AuditResult): void {
    if (this.options.json) {
      this.reportJson(result);
      return;
    }
    
    this.reportTerminal(result);
  }
  
  private reportTerminal(result: AuditResult): void {
    console.log(formatSummary(result));
    
    if (result.vulnerabilities.length === 0) {
      return;
    }
    
    const filtered = this.filterBySeverity(result.vulnerabilities);
    
    if (filtered.length === 0) {
      console.log(theme.info('\nNo vulnerabilities match the severity filter.\n'));
      return;
    }
    
    console.log(theme.bold('\n📋 Vulnerability Details:\n'));
    console.log(theme.dim('─'.repeat(60)));
    
    for (const vuln of filtered) {
      console.log(formatVulnerability(vuln));
      console.log(theme.dim('─'.repeat(60)));
    }
  }
  
  private reportJson(result: AuditResult): void {
    const filtered = this.filterBySeverity(result.vulnerabilities);
    
    const output = {
      summary: result.summary,
      scannedPackages: result.scannedPackages,
      timestamp: result.timestamp.toISOString(),
      vulnerabilities: filtered.map(v => ({
        id: v.id,
        packageName: v.packageName,
        packageVersion: v.packageVersion,
        ecosystem: v.ecosystem,
        severity: v.severity,
        title: v.title,
        description: v.description,
        cvss: v.cvss,
        cwe: v.cwe,
        affectedVersions: v.affectedVersions,
        fixedVersions: v.fixedVersions,
        publishedDate: v.publishedDate,
        references: v.references,
        source: v.source,
      })),
    };
    
    console.log(JSON.stringify(output, null, 2));
  }
  
  private filterBySeverity(vulnerabilities: Vulnerability[]) {
    if (!this.options.severityFilter) {
      return vulnerabilities;
    }
    
    const filter = this.options.severityFilter.toUpperCase();
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    const minIndex = severityOrder.indexOf(filter);
    
    if (minIndex === -1) {
      return vulnerabilities;
    }
    
    return vulnerabilities.filter(v => {
      const vulnIndex = severityOrder.indexOf(v.severity);
      return vulnIndex <= minIndex;
    });
  }
}
