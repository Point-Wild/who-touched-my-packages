import type { Dependency } from '../scanner/types.js';
import { buildAnalysisGraph } from './graph.js';
import { createChatModel } from './llm/client.js';
import { DEFAULT_MODEL, DEFAULT_CONCURRENCY, resolveModel } from './llm/models.js';
import type { SupplyChainOptions, SupplyChainReport } from './types.js';
import { resolveApiKey } from './utils.js';
import { createEmptyLLMUsage } from './usage.js';

export type { SupplyChainFinding, SupplyChainOptions, SupplyChainReport, ThreatCategory } from './types.js';
export { DEFAULT_MODEL, DEFAULT_CONCURRENCY } from './llm/models.js';

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
      fetchErrors: [],
      llmUsage: createEmptyLLMUsage(),
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
      model: resolveModel(options.model, options.provider),
    };
  }

  const model = resolveModel(options.model, options.provider);
  const apiKey = resolveApiKey(options.apiKey, options.provider, model);
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;

  const chatModel = createChatModel({ apiKey, model, provider: options.provider });

  const graph = buildAnalysisGraph({
    chatModel,
    modelName: model,
    concurrency,
    verbose: options.verbose ?? false,
    maxPackages: options.maxPackages ?? 0,
    onProgress,
  });

  const finalState = await graph.invoke({
    dependencies,
    metadata: new Map(),
    sources: new Map(),
    fetchErrors: [],
    primaryFindings: [],
    allFindings: [],
    llmUsage: createEmptyLLMUsage(),
    result: null,
  });

  return finalState.result ?? {
    findings: [],
    fetchErrors: [],
    llmUsage: createEmptyLLMUsage(),
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
