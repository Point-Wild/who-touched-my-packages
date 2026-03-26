import type { Dependency } from '../scanner/types.js';
import { buildAnalysisGraph } from './graph.js';
import { createChatModel } from './llm/client.js';
import type { SupplyChainOptions, SupplyChainReport } from './types.js';
import { resolveApiKey } from './utils.js';

export type { SupplyChainFinding, SupplyChainOptions, SupplyChainReport, ThreatCategory } from './types.js';

const DEFAULT_MODEL = 'claude-sonnet-4-5-20241022';
const DEFAULT_CONCURRENCY = 3;

/**
 * Analyze dependencies for supply chain poisoning threats.
 *
 * @param dependencies - Parsed dependencies from the scanner
 * @param options - Configuration options (API key, model, concurrency)
 * @param onProgress - Optional progress callback
 * @returns Supply chain analysis results with findings and summary
 */
export async function analyzeSupplyChain(
  dependencies: Dependency[],
  options: SupplyChainOptions = {},
  onProgress?: (stage: string, done: number, total: number) => void
): Promise<SupplyChainReport> {
  // Return empty report if dry-run mode
  if (options.dryRun) {
    return {
      findings: [],
      summary: {
        packagesAnalyzed: dependencies.length,
        packagesWithFindings: 0,
        totalFindings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        byCategory: {},
      },
      timestamp: new Date().toISOString(),
      model: options.model ?? DEFAULT_MODEL,
    };
  }

  const apiKey = resolveApiKey(options.apiKey, options.provider);
  const model = options.model ?? DEFAULT_MODEL;
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;

  const chatModel = createChatModel({ apiKey, model, provider: options.provider });

  const graph = buildAnalysisGraph({
    chatModel,
    modelName: model,
    concurrency,
    maxPackages: options.maxPackages ?? 0,
    onProgress,
  });

  const finalState = await graph.invoke({
    dependencies,
    metadata: new Map(),
    sources: new Map(),
    primaryFindings: [],
    allFindings: [],
    result: null,
  });

  return finalState.result ?? {
    findings: [],
    summary: {
      packagesAnalyzed: 0,
      packagesWithFindings: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      byCategory: {},
    },
    timestamp: new Date().toISOString(),
    model,
  };
}
