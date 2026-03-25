import type { Vulnerability, AuditResult } from '../auditor/types.js';
import type { DependencyFile } from '../scanner/types.js';
import { theme, getSeverityColor, icons } from './theme.js';

export function formatVulnerability(vuln: Vulnerability): string {
  const color = getSeverityColor(vuln.severity);
  const icon = getSeverityIcon(vuln.severity);
  
  let output = '\n';
  output += color(`${icon} ${vuln.severity} - ${vuln.id}\n`);
  output += theme.bold(`Package: `) + `${vuln.packageName}@${vuln.packageVersion}\n`;
  output += theme.bold(`Title: `) + `${vuln.title}\n`;
  
  if (vuln.cvss) {
    output += theme.bold(`CVSS Score: `) + `${vuln.cvss}\n`;
  }
  
  output += theme.bold(`Affected: `) + `${vuln.affectedVersions}\n`;
  
  if (vuln.fixedVersions) {
    output += theme.success(`Fixed in: ${vuln.fixedVersions}\n`);
  }
  
  if (vuln.description && vuln.description !== vuln.title) {
    const desc = vuln.description.length > 200 
      ? vuln.description.substring(0, 200) + '...' 
      : vuln.description;
    output += theme.dim(`\n${desc}\n`);
  }
  
  if (vuln.references.length > 0) {
    output += theme.dim(`\nReferences:\n`);
    vuln.references.slice(0, 3).forEach(ref => {
      output += theme.dim(`  • ${ref}\n`);
    });
  }
  
  output += theme.dim(`Source: ${vuln.source}\n`);
  
  return output;
}

export function formatSummary(result: AuditResult): string {
  let output = '\n';
  output += theme.bold('═'.repeat(60)) + '\n';
  output += theme.bold(`${icons.shield} Security Audit Summary\n`);
  output += theme.bold('═'.repeat(60)) + '\n\n';
  
  output += theme.bold(`Scanned Packages: `) + `${result.scannedPackages}\n`;
  output += theme.bold(`Total Vulnerabilities: `) + `${result.summary.total}\n\n`;
  
  if (result.summary.critical > 0) {
    output += theme.critical(`${icons.critical} Critical: ${result.summary.critical}\n`);
  }
  if (result.summary.high > 0) {
    output += theme.high(`${icons.high} High: ${result.summary.high}\n`);
  }
  if (result.summary.medium > 0) {
    output += theme.medium(`${icons.medium} Medium: ${result.summary.medium}\n`);
  }
  if (result.summary.low > 0) {
    output += theme.low(`${icons.low} Low: ${result.summary.low}\n`);
  }
  
  if (result.summary.total === 0) {
    output += theme.success(`\n${icons.success} No vulnerabilities found!\n`);
  }
  
  output += '\n' + theme.bold('═'.repeat(60)) + '\n';
  
  return output;
}

export function formatFileList(files: DependencyFile[]): string {
  let output = '\n';
  output += theme.bold(`${icons.file} Found ${files.length} dependency file(s):\n\n`);
  
  for (const file of files) {
    const icon = file.type === 'package.json' ? icons.package : icons.file;
    output += theme.dim(`  ${icon} ${file.relativePath}\n`);
  }
  
  return output;
}

function getSeverityIcon(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return icons.critical;
    case 'HIGH':
      return icons.high;
    case 'MEDIUM':
      return icons.medium;
    case 'LOW':
      return icons.low;
    default:
      return icons.info;
  }
}

export function formatProgress(message: string): string {
  return theme.info(`${icons.search} ${message}`);
}
