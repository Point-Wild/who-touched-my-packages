import type { AuditResult, Vulnerability } from '../auditor/types.js';
import type { DependencyFile } from '../scanner/types.js';
import { getSeverityColor, icons, theme } from './theme.js';

export function formatVulnerability(vuln: Vulnerability): string {
  const color = getSeverityColor(vuln.severity);
  const icon = getSeverityIcon(vuln.severity);
  
  let output = '\n';
  output += color(`${icon} ${vuln.severity} - ${vuln.id}\n`);
  output += theme.bold(`Package: `) + `${vuln.packageName}@${vuln.packageVersion}\n`;
  
  // Only show title if it's different from ID and not "No description available"
  if (vuln.title && vuln.title !== vuln.id && vuln.title !== 'No description available') {
    output += theme.bold(`Title: `) + `${vuln.title}\n`;
  }
  
  if (vuln.cvss) {
    output += theme.bold(`CVSS Score: `) + `${vuln.cvss}\n`;
  }
  
  // Only show affected versions if not "Unknown"
  if (vuln.affectedVersions && vuln.affectedVersions !== 'Unknown') {
    output += theme.bold(`Affected: `) + `${vuln.affectedVersions}\n`;
  }
  
  if (vuln.fixedVersions) {
    output += theme.success(`Fixed in: ${vuln.fixedVersions}\n`);
  }
  
  // Only show description if it exists and is meaningful
  if (vuln.description && 
      vuln.description !== vuln.title && 
      vuln.description !== 'No description available' &&
      vuln.description.trim().length > 0) {
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
  
  output += theme.dim(`\nSource: ${vuln.source}`);
  
  return output;
}

export function formatSummary(result: AuditResult): string {
  let output = '\n';
  output += theme.bold('═'.repeat(60)) + '\n';
  output += theme.bold(`${icons.shield} Security Audit Results\n`);
  output += theme.bold('═'.repeat(60)) + '\n\n';
  
  // Calculate meaningful vulnerabilities (exclude UNKNOWN with no info)
  const meaningfulCount = result.summary.critical + result.summary.high + result.summary.medium + result.summary.low;
  
  if (meaningfulCount > 0) {
    output += theme.bold(`Vulnerabilities Found: `) + `${meaningfulCount}`;
    if (result.summary.unknown > 0) {
      output += theme.dim(` (+${result.summary.unknown} unknown severity)`);
    }
    output += '\n\n';
    
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
  } else if (result.summary.unknown > 0) {
    output += theme.dim(`${result.summary.unknown} findings with unknown severity\n`);
  } else {
    output += theme.success(`${icons.success} No vulnerabilities found!\n`);
  }
  
  output += '\n' + theme.bold('═'.repeat(60));
  
  return output;
}

export function formatFileList(files: DependencyFile[]): string {
  let output = '\n';
  output += theme.bold(`${icons.file} Scanned Files (${files.length}):\n`);
  output += theme.dim('─'.repeat(40)) + '\n';
  
  for (const file of files) {
    const icon = file.type === 'package.json' ? icons.package : icons.file;
    output += theme.dim(`${icon} ${file.relativePath}\n`);
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
