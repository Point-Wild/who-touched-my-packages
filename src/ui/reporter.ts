import type { AuditResult, Vulnerability } from '../auditor/types.js';
import type { Dependency, DependencyFile } from '../scanner/types.js';
import { formatFileList, formatSummary, formatVulnerability } from './formatters.js';
import { generateHtmlReport } from './html-report/generator.js';
import type { ReportData } from './html-report/types.js';
import { theme } from './theme.js';

export interface ReporterOptions {
  json?: boolean;
  severityFilter?: string;
  verbose?: boolean;
  html?: boolean;
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
    
    let filtered = this.filterBySeverity(result.vulnerabilities);
    
    // Filter out unhelpful UNKNOWN vulnerabilities unless verbose mode
    if (!this.options.verbose) {
      filtered = this.filterUnhelpfulVulnerabilities(filtered);
    }
    
    if (filtered.length === 0) {
      if (this.options.severityFilter) {
        console.log(theme.info('\nNo vulnerabilities match the severity filter.\n'));
      } else {
        console.log(theme.dim('\nAll findings have insufficient information. Use --verbose to see them.\n'));
      }
      return;
    }
    
    console.log(theme.bold('\n📋 Vulnerability Details:\n'));
    console.log(theme.dim('─'.repeat(60)));
    
    for (const vuln of filtered) {
      console.log(formatVulnerability(vuln));
      console.log(theme.dim('─'.repeat(60)));
    }
    
    // Show hint about hidden vulnerabilities
    const hiddenCount = result.vulnerabilities.length - filtered.length;
    if (hiddenCount > 0 && !this.options.verbose) {
      console.log(theme.dim(`\n💡 ${hiddenCount} additional finding(s) with limited information hidden. Use --verbose to see all.\n`));
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
  
  private filterUnhelpfulVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
    return vulnerabilities.filter(v => {
      // Keep all non-UNKNOWN vulnerabilities
      if (v.severity !== 'UNKNOWN') {
        return true;
      }
      
      // For UNKNOWN, only keep if it has meaningful information
      const hasDescription = v.description && 
                            v.description !== 'No description available' && 
                            v.description.trim().length > 0;
      const hasReferences = v.references && v.references.length > 0;
      const hasCvss = v.cvss !== undefined && v.cvss !== null;
      const hasFixedVersion = v.fixedVersions && v.fixedVersions.length > 0;
      const hasAffectedVersions = v.affectedVersions && v.affectedVersions !== 'Unknown';
      
      return hasDescription || hasReferences || hasCvss || hasFixedVersion || hasAffectedVersions;
    });
  }
  
  async generateHtmlReport(result: AuditResult, dependencies: Dependency[], scanPath: string, repositoryUrl?: string): Promise<string> {
    const reportData: ReportData = {
      auditResult: result,
      dependencies,
      scanPath,
      repositoryUrl,
    };
    
    return await generateHtmlReport(reportData);
  }
}
