import { writeFile } from 'node:fs/promises';
import type { AuditResult, Vulnerability } from '../auditor/types.js';
import type { Dependency, DependencyEdge, DependencyFile } from '../scanner/types.js';
import { formatFileList, formatSummary, formatVulnerability } from './formatters.js';
import type { ReportData } from './html-report/types.js';
import { theme } from './theme.js';

export interface ReporterOptions {
  json?: boolean;
  severityFilter?: string;
  verbose?: boolean;
  html?: boolean;
  supplyChain?: boolean;
  output?: string;
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
  
  reportResults(
    result: AuditResult,
    files?: DependencyFile[],
    dependencies?: Dependency[],
    supplyChainReport?: import('../supply-chain/types.js').SupplyChainReport
  ): void {
    if (this.options.json) {
      this.reportJson(result);
      return;
    }
    
    this.reportTerminal(result, files, dependencies);
  }
  
  private reportTerminal(result: AuditResult, files?: DependencyFile[], dependencies?: Dependency[]): void {
    // Show scan overview first
    if (files && dependencies) {
      console.log(formatFileList(files));
    }
    
    console.log(formatSummary(result));
    
    if (result.vulnerabilities.length === 0) {
      this.showFinalSummary(result, files, dependencies);
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
      this.showFinalSummary(result, files, dependencies);
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
    
    this.showFinalSummary(result, files, dependencies);
  }
  
  private showFinalSummary(result: AuditResult, files?: DependencyFile[], dependencies?: Dependency[]): void {
    console.log('\n' + theme.bold('═'.repeat(60)));
    console.log(theme.bold(`📊 Final Summary`));
    console.log(theme.bold('═'.repeat(60)));
    
    if (files) {
      console.log(theme.bold(`Files Scanned: `) + `${files.length}`);
    }
    if (dependencies) {
      console.log(theme.bold(`Packages Analyzed: `) + `${dependencies.length}`);
    }
    console.log(theme.bold(`Vulnerabilities Found: `) + `${result.summary.total}`);
    
    if (result.summary.total > 0) {
      console.log('\n' + theme.bold('By Severity:'));
      if (result.summary.critical > 0) {
        console.log(theme.critical(`  🚨 Critical: ${result.summary.critical}`));
      }
      if (result.summary.high > 0) {
        console.log(theme.high(`  ⚠️  High: ${result.summary.high}`));
      }
      if (result.summary.medium > 0) {
        console.log(theme.medium(`  ⚡ Medium: ${result.summary.medium}`));
      }
      if (result.summary.low > 0) {
        console.log(theme.low(`  💡 Low: ${result.summary.low}`));
      }
      if (result.summary.unknown > 0) {
        console.log(theme.dim(`  ❓ Unknown: ${result.summary.unknown}`));
      }
    }
    
    console.log('\n' + theme.bold('═'.repeat(60)));
    
    if (result.summary.total === 0) {
      console.log(theme.success(`\n✅ All clear! No vulnerabilities found.`));
    } else {
      const criticalAndHigh = result.summary.critical + result.summary.high;
      if (criticalAndHigh > 0) {
        console.log(theme.critical(`\n❌ ${criticalAndHigh} critical/high severity vulnerabilities require immediate attention!`));
      } else {
        console.log(theme.medium(`\n⚠️  ${result.summary.total} vulnerabilities found. Review recommended.`));
      }
    }
    
    console.log(''); // Add final newline
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
    
    const jsonString = JSON.stringify(output, null, 2);
    
    if (this.options.output) {
      writeFile(this.options.output, jsonString).catch((err) => {
        console.error(`Failed to write output file: ${err.message}`);
        process.exit(1);
      });
    } else {
      console.log(jsonString);
    }
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
  
  async generateHtmlReport(
    result: AuditResult,
    dependencies: Dependency[],
    scanPath: string,
    repositoryUrl?: string,
    languageStats?: import('./html-report/types.js').LanguageStats[],
    dependencyEdges?: DependencyEdge[],
    supplyChainReport?: import('../supply-chain/types.js').SupplyChainReport
  ): Promise<{ url: string; close: () => void }> {
    const reportData: ReportData = {
      auditResult: result,
      dependencies,
      scanPath,
      repositoryUrl,
      languageStats,
      dependencyEdges,
    };
    
    const { generateAndServeReport } = await import('./html-report/new-generator.js');
    return await generateAndServeReport(reportData);
  }
}
