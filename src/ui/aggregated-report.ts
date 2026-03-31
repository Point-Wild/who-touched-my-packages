import type { Severity as AuditSeverity, Vulnerability } from '../auditor/types.js';
import type { SupplyChainFinding, SupplyChainReport } from '../supply-chain/types.js';
import type { ReportData } from './html-report/types.js';
import { getSeverityColor, icons, theme } from './theme.js';

export type AggregatedSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface AggregatedPackageFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  highestSeverity: AggregatedSeverity;
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

export interface FinalReport {
  reportData: ReportData;
  supplyChainReport?: SupplyChainReport;
  aggregatedReport: AggregatedReport;
}

export function buildAggregatedReport(
  reportData: ReportData,
  supplyChainReport?: SupplyChainReport
): AggregatedReport {
  const grouped = new Map<string, AggregatedPackageFinding>();

  for (const vuln of reportData.auditResult.vulnerabilities) {
    const key = `${vuln.ecosystem}:${vuln.packageName}@${vuln.packageVersion}`;
    const existing = grouped.get(key) ?? {
      packageName: vuln.packageName,
      packageVersion: vuln.packageVersion,
      ecosystem: vuln.ecosystem,
      highestSeverity: 'UNKNOWN' as AggregatedSeverity,
      staticFindings: [],
      supplyChainFindings: [],
    };
    existing.staticFindings.push(vuln);
    existing.highestSeverity = maxSeverity(existing.highestSeverity, vuln.severity);
    grouped.set(key, existing);
  }

  for (const finding of supplyChainReport?.findings ?? []) {
    const key = `${finding.ecosystem}:${finding.packageName}@${finding.packageVersion}`;
    const existing = grouped.get(key) ?? {
      packageName: finding.packageName,
      packageVersion: finding.packageVersion,
      ecosystem: finding.ecosystem,
      highestSeverity: 'UNKNOWN' as AggregatedSeverity,
      staticFindings: [],
      supplyChainFindings: [],
    };
    existing.supplyChainFindings.push(finding);
    existing.highestSeverity = maxSeverity(existing.highestSeverity, finding.severity);
    grouped.set(key, existing);
  }

  const aggregatedFindings = Array.from(grouped.values())
    .filter(entry => entry.staticFindings.length > 0 || entry.supplyChainFindings.length > 0)
    .sort((left, right) => {
      const severityDelta = severityRank(right.highestSeverity) - severityRank(left.highestSeverity);
      if (severityDelta !== 0) return severityDelta;
      const countDelta =
        (right.staticFindings.length + right.supplyChainFindings.length) -
        (left.staticFindings.length + left.supplyChainFindings.length);
      if (countDelta !== 0) return countDelta;
      return left.packageName.localeCompare(right.packageName);
    });

  return {
    aggregatedFindings,
    aggregatedSummary: {
      totalPackages: aggregatedFindings.length,
      packagesWithStaticFindings: aggregatedFindings.filter(f => f.staticFindings.length > 0).length,
      packagesWithSupplyChainFindings: aggregatedFindings.filter(f => f.supplyChainFindings.length > 0).length,
      critical: aggregatedFindings.filter(f => f.highestSeverity === 'CRITICAL').length,
      high: aggregatedFindings.filter(f => f.highestSeverity === 'HIGH').length,
      medium: aggregatedFindings.filter(f => f.highestSeverity === 'MEDIUM').length,
      low: aggregatedFindings.filter(f => f.highestSeverity === 'LOW').length,
      unknown: aggregatedFindings.filter(f => f.highestSeverity === 'UNKNOWN').length,
    },
  };
}

export function buildFinalReport(
  reportData: ReportData,
  supplyChainReport?: SupplyChainReport
): FinalReport {
  return {
    reportData,
    supplyChainReport,
    aggregatedReport: buildAggregatedReport(reportData, supplyChainReport),
  };
}

export function displayAggregatedReport(finalReport: FinalReport): void {
  const output = formatAggregatedReport(finalReport.aggregatedReport);
  if (output) {
    console.log(output);
  }
}

export function formatAggregatedReport(aggregatedReport: AggregatedReport): string {
  if (aggregatedReport.aggregatedFindings.length === 0) {
    return '';
  }

  let output = '\n';
  output += theme.bold('═'.repeat(60)) + '\n';
  output += theme.bold(`${icons.search} Aggregated Findings\n`);
  output += theme.bold('═'.repeat(60)) + '\n';
  output += theme.dim('Static analysis matches and supply chain findings grouped by package.\n');

  for (const entry of aggregatedReport.aggregatedFindings) {
    const severityColor = getSeverityColor(entry.highestSeverity);
    output += '\n' + severityColor(`${getSeverityIcon(entry.highestSeverity)} ${entry.highestSeverity} `);
    output += theme.bold(`${entry.packageName}@${entry.packageVersion}`);
    output += theme.dim(` [${entry.ecosystem}]`) + '\n';

    if (entry.staticFindings.length > 0) {
      output += theme.bold('  Static Analysis:\n');
      for (const vuln of entry.staticFindings) {
        const title = vuln.title && vuln.title !== 'No description available' ? ` — ${vuln.title}` : '';
        output += `  • ${vuln.severity} rule matched: ${vuln.id}${title}\n`;
      }
    }

    if (entry.supplyChainFindings.length > 0) {
      output += theme.bold('  Supply Chain Analysis:\n');
      for (const finding of entry.supplyChainFindings) {
        output += `  • ${finding.severity} ${finding.category}: ${finding.title} `;
        output += theme.dim(`(${Math.round(finding.confidence * 100)}% confidence)`) + '\n';
      }
    }
  }

  output += '\n' + theme.bold('═'.repeat(60));
  return output;
}

function getSeverityIcon(severity: AggregatedSeverity): string {
  switch (severity) {
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

function severityRank(severity: AggregatedSeverity): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

function maxSeverity(left: AggregatedSeverity, right: AuditSeverity | SupplyChainFinding['severity']): AggregatedSeverity {
  return severityRank(left) >= severityRank(right) ? left : right;
}
