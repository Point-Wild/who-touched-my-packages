import type { PackageFetchError, SupplyChainFinding, SupplyChainLLMUsage, SupplyChainReport, Severity, ThreatCategory } from '../types.js';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * Aggregate findings into a flat SupplyChainReport with summary stats.
 */
export function aggregateNode(
  findings: SupplyChainFinding[],
  packagesAnalyzed: number,
  fetchErrors: PackageFetchError[],
  model: string,
  llmUsage: SupplyChainLLMUsage
): SupplyChainReport {
  // Deduplicate: same package + same category + same title = duplicate
  const seen = new Set<string>();
  const deduped: SupplyChainFinding[] = [];

  for (const f of findings) {
    const key = `${f.packageName}@${f.packageVersion}:${f.category}:${f.title}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }

  // Sort by severity then confidence
  deduped.sort((a, b) => {
    const si = SEVERITY_ORDER.indexOf(a.severity);
    const bi = SEVERITY_ORDER.indexOf(b.severity);
    if (si !== bi) return si - bi;
    return b.confidence - a.confidence;
  });

  // Count distinct packages with findings
  const packagesWithFindings = new Set(deduped.map(f => `${f.packageName}@${f.packageVersion}`)).size;

  // Build summary
  const byCategory = {} as Partial<Record<ThreatCategory, number>>;
  let critical = 0, high = 0, medium = 0, low = 0;

  for (const f of deduped) {
    switch (f.severity) {
      case 'CRITICAL': critical++; break;
      case 'HIGH': high++; break;
      case 'MEDIUM': medium++; break;
      case 'LOW': low++; break;
    }
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }

  return {
    findings: deduped,
    fetchErrors,
    llmUsage,
    summary: {
      packagesAnalyzed,
      packagesWithFindings,
      totalFindings: deduped.length,
      critical,
      high,
      medium,
      low,
      byCategory,
    },
    timestamp: new Date().toISOString(),
    model,
  };
}
