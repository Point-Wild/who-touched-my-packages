import { StateGraph, Annotation, START, END } from '@langchain/langgraph';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { Dependency } from '../scanner/types.js';
import type { PackageFetchError, PackageMetadata, PackageSource, SupplyChainFinding, SupplyChainReport } from './types.js';
import { fetchMetadataNode } from './nodes/fetch-metadata.js';
import { primaryAnalysisNode } from './nodes/primary-analysis.js';
import { deepInvestigationNode } from './nodes/deep-investigation.js';
import { aggregateNode } from './nodes/aggregate.js';
import { createEmptyLLMUsage, createSingleNodeUsage, mergeLLMUsage } from './usage.js';

// LangGraph state definition
const AnalysisAnnotation = Annotation.Root({
  dependencies: Annotation<Dependency[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  metadata: Annotation<Map<string, PackageMetadata>>({
    reducer: (_prev, next) => next,
    default: () => new Map(),
  }),
  sources: Annotation<Map<string, PackageSource>>({
    reducer: (_prev, next) => next,
    default: () => new Map(),
  }),
  fetchErrors: Annotation<PackageFetchError[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  primaryFindings: Annotation<SupplyChainFinding[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  allFindings: Annotation<SupplyChainFinding[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  llmUsage: Annotation<ReturnType<typeof createEmptyLLMUsage>>({
    reducer: (prev, next) => mergeLLMUsage(prev, next),
    default: () => createEmptyLLMUsage(),
  }),
  result: Annotation<SupplyChainReport | null>({
    reducer: (_prev, next) => next,
    default: () => null,
  }),
});

type AnalysisState = typeof AnalysisAnnotation.State;

export interface GraphOptions {
  chatModel: BaseChatModel;
  modelName: string;
  concurrency: number;
  verbose?: boolean;
  maxPackages?: number;
  onProgress?: (stage: string, done: number, total: number) => void;
}

/**
 * Build and compile the LangGraph supply chain analysis workflow.
 */
export function buildAnalysisGraph(options: GraphOptions) {
  const { chatModel, modelName, concurrency, verbose = false, maxPackages = 0, onProgress } = options;

  const graph = new StateGraph(AnalysisAnnotation)
    .addNode('fetch_metadata', async (state: AnalysisState) => {
      const { metadata, sources, fetchErrors } = await fetchMetadataNode(
        state.dependencies,
        concurrency,
        maxPackages,
        (done, total) => onProgress?.('Fetching package metadata & source', done, total)
      );
      return { metadata, sources, fetchErrors };
    })
    .addNode('primary_analysis', async (state: AnalysisState) => {
      const { findings, usage } = await primaryAnalysisNode(
        state.metadata,
        state.sources,
        chatModel,
        concurrency,
        verbose,
        (done, total) => onProgress?.('Investigating packages', done, total)
      );
      return { primaryFindings: findings, llmUsage: createSingleNodeUsage('primary_analysis', usage) };
    })
    .addNode('deep_investigation', async (state: AnalysisState) => {
      const { findings: allFindings, usage } = await deepInvestigationNode(
        state.primaryFindings,
        state.sources,
        chatModel,
        concurrency,
        verbose
      );
      return { allFindings, llmUsage: createSingleNodeUsage('deep_investigation', usage) };
    })
    .addNode('skip_deep', async (state: AnalysisState) => {
      return { allFindings: state.primaryFindings };
    })
    .addNode('aggregate', async (state: AnalysisState) => {
      const result = aggregateNode(
        state.allFindings,
        state.metadata.size,
        state.fetchErrors,
        modelName,
        state.llmUsage
      );
      return { result };
    })
    .addEdge(START, 'fetch_metadata')
    .addEdge('fetch_metadata', 'primary_analysis')
    .addConditionalEdges(
      'primary_analysis',
      (state: AnalysisState) => {
        const hasHighSeverity = state.primaryFindings.some(
          f => f.severity === 'CRITICAL' || f.severity === 'HIGH'
        );
        return hasHighSeverity ? 'deep_investigation' : 'skip_deep';
      },
      ['deep_investigation', 'skip_deep']
    )
    .addEdge('deep_investigation', 'aggregate')
    .addEdge('skip_deep', 'aggregate')
    .addEdge('aggregate', END);

  return graph.compile();
}
