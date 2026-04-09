import type { AIMessage } from '@langchain/core/messages';
import type { LLMNodeName, LLMUsageMetrics } from '../types.js';

interface PriceConfig {
  match: RegExp;
  inputPerMillion: number;
  outputPerMillion: number;
}

const PRICE_TABLE: PriceConfig[] = [
  { match: /^claude-sonnet-4-(5|6)/, inputPerMillion: 3, outputPerMillion: 15 },
  { match: /^claude-haiku-4-5/, inputPerMillion: 0.8, outputPerMillion: 4 },
  { match: /^claude-opus-4-6/, inputPerMillion: 15, outputPerMillion: 75 },
  { match: /^gpt-4\.1$/, inputPerMillion: 2, outputPerMillion: 8 },
  { match: /^gpt-4\.1-mini$/, inputPerMillion: 0.4, outputPerMillion: 1.6 },
  { match: /^gemini-2\.5-pro$/, inputPerMillion: 1.25, outputPerMillion: 10 },
  { match: /^gemini-2\.5-flash$/, inputPerMillion: 0.3, outputPerMillion: 2.5 },
  { match: /^gemini-2\.5-flash-lite$/, inputPerMillion: 0.1, outputPerMillion: 0.4 },
];

function toNumber(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function normalizeModelName(model: string): string {
  return model.includes('/') ? model.split('/').at(-1) ?? model : model;
}

function resolveUsagePayload(message: AIMessage): Record<string, unknown> | undefined {
  if (message.usage_metadata && typeof message.usage_metadata === 'object') {
    return message.usage_metadata as Record<string, unknown>;
  }

  if (!message.response_metadata || typeof message.response_metadata !== 'object') {
    return undefined;
  }

  const candidates = [
    message.response_metadata.usage_metadata,
    message.response_metadata.usage,
    message.response_metadata.tokenUsage,
    message.response_metadata.token_usage,
  ];

  for (const candidate of candidates) {
    if (candidate && typeof candidate === 'object') {
      return candidate as Record<string, unknown>;
    }
  }

  return message.response_metadata as Record<string, unknown>;
}

function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number | null {
  const normalizedModel = normalizeModelName(model);
  const price = PRICE_TABLE.find(entry => entry.match.test(normalizedModel));
  if (!price) return null;

  return (
    (inputTokens / 1_000_000) * price.inputPerMillion +
    (outputTokens / 1_000_000) * price.outputPerMillion
  );
}

export function emptyUsageMetrics(node: LLMNodeName): LLMUsageMetrics {
  return {
    node,
    calls: 0,
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
    estimatedCostUsd: 0,
    costEstimateAvailable: true,
  };
}

export function addUsageMetrics(left: LLMUsageMetrics, right: LLMUsageMetrics): LLMUsageMetrics {
  return {
    node: left.node,
    calls: left.calls + right.calls,
    inputTokens: left.inputTokens + right.inputTokens,
    outputTokens: left.outputTokens + right.outputTokens,
    totalTokens: left.totalTokens + right.totalTokens,
    estimatedCostUsd: left.estimatedCostUsd + right.estimatedCostUsd,
    costEstimateAvailable: left.costEstimateAvailable && right.costEstimateAvailable,
  };
}

export function usageFromMessage(message: AIMessage, model: string, node: LLMNodeName): LLMUsageMetrics {
  const usage = resolveUsagePayload(message);
  const inputTokens = toNumber(
    usage?.input_tokens ??
    usage?.inputTokens ??
    usage?.prompt_tokens ??
    usage?.promptTokens
  );
  const outputTokens = toNumber(
    usage?.output_tokens ??
    usage?.outputTokens ??
    usage?.completion_tokens ??
    usage?.completionTokens ??
    usage?.candidatesTokenCount
  );
  const totalTokens = toNumber(usage?.total_tokens ?? usage?.totalTokens) || (inputTokens + outputTokens);
  const estimatedCostUsd = estimateCostUsd(model, inputTokens, outputTokens);

  return {
    node,
    calls: 1,
    inputTokens,
    outputTokens,
    totalTokens,
    estimatedCostUsd: estimatedCostUsd ?? 0,
    costEstimateAvailable: estimatedCostUsd !== null,
  };
}
