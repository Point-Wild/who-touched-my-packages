import type { LLMNodeName, LLMUsageMetrics, SupplyChainLLMUsage } from './types.js';
import { addUsageMetrics, emptyUsageMetrics } from './llm/usage.js';

const LLM_NODES: LLMNodeName[] = ['primary_analysis', 'deep_investigation'];

export function createEmptyLLMUsage(): SupplyChainLLMUsage {
  const byNode = {
    primary_analysis: emptyUsageMetrics('primary_analysis'),
    deep_investigation: emptyUsageMetrics('deep_investigation'),
  };

  let total = emptyUsageMetrics('primary_analysis');
  for (const node of LLM_NODES) {
    total = addUsageMetrics(total, byNode[node]);
  }

  return { byNode, total };
}

export function mergeLLMUsage(
  current: SupplyChainLLMUsage,
  next: SupplyChainLLMUsage
): SupplyChainLLMUsage {
  const byNode = {
    primary_analysis: current.byNode.primary_analysis,
    deep_investigation: current.byNode.deep_investigation,
  };

  for (const node of LLM_NODES) {
    byNode[node] = addUsageMetrics(byNode[node], next.byNode[node]);
  }

  let total = emptyUsageMetrics('primary_analysis');
  for (const node of LLM_NODES) {
    total = addUsageMetrics(total, byNode[node]);
  }

  return { byNode, total };
}

export function createSingleNodeUsage(node: LLMNodeName, metrics: LLMUsageMetrics): SupplyChainLLMUsage {
  const usage = createEmptyLLMUsage();
  usage.byNode[node] = metrics;

  let total = emptyUsageMetrics('primary_analysis');
  for (const entry of LLM_NODES) {
    total = addUsageMetrics(total, usage.byNode[entry]);
  }
  usage.total = total;

  return usage;
}
