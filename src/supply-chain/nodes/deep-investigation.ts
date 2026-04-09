import { HumanMessage } from '@langchain/core/messages';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { LLMUsageMetrics, PackageSource, SupplyChainFinding } from '../types.js';
import { buildDeepInvestigationPrompt } from '../llm/prompts.js';
import { extractJSON, depKey, pMap } from '../utils.js';
import { addUsageMetrics, emptyUsageMetrics, usageFromMessage } from '../llm/usage.js';

function formatUsageSummary(usage: LLMUsageMetrics): string {
  const costText = usage.costEstimateAvailable
    ? `$${usage.estimatedCostUsd.toFixed(4)}`
    : 'unavailable';
  return `${usage.calls} call(s), ${usage.inputTokens} input, ${usage.outputTokens} output, ${usage.totalTokens} total, estimated cost ${costText}`;
}

function responseToText(response: any): string {
  const content = response?.content;
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map(block => {
      if (typeof block === 'string') return block;
      if (block && typeof block === 'object' && 'text' in block) return String(block.text ?? '');
      return JSON.stringify(block);
    }).join('\n');
  }
  return content == null ? '' : JSON.stringify(content);
}

/**
 * Deep investigation node: re-analyzes HIGH/CRITICAL findings with a targeted prompt.
 * Can confirm, downgrade, or dismiss findings.
 */
export async function deepInvestigationNode(
  findings: SupplyChainFinding[],
  sources: Map<string, PackageSource>,
  chatModel: BaseChatModel,
  concurrency: number = 3,
  verbose: boolean = false
): Promise<{ findings: SupplyChainFinding[]; usage: LLMUsageMetrics }> {
  const toInvestigate = findings.filter(
    f => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.confidence >= 0.3
  );
  const passThrough = findings.filter(
    f => !((f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.confidence >= 0.3)
  );

  if (toInvestigate.length === 0) {
    return { findings, usage: emptyUsageMetrics('deep_investigation') };
  }

  const investigated = await pMap(
    toInvestigate,
    async (finding, idx) => {
      const key = depKey(finding.ecosystem, finding.packageName);
      const source = sources.get(key);
      if (!source) {
        return { finding, usage: emptyUsageMetrics('deep_investigation') };
      }

      try {
        const prompt = buildDeepInvestigationPrompt(finding, source);
        if (verbose) {
          console.log(`  [deep:${finding.packageName}] finding ${idx + 1}/${toInvestigate.length}: ${finding.filePath} (${finding.severity}, confidence ${finding.confidence})`);
          console.log(`  [deep:${finding.packageName}]   input file ${finding.filePath}:`);
          console.log(prompt);
        }
        const response = await chatModel.invoke([new HumanMessage(prompt)]);
        const usage = usageFromMessage(response, getModelName(chatModel), 'deep_investigation');
        const text = typeof response.content === 'string'
          ? response.content
          : (response.content as any[]).map((b: any) => b.text ?? '').join('');
        if (verbose) {
          console.log(`  [deep:${finding.packageName}]   output file ${finding.filePath}:`);
          console.log(responseToText(response));
          console.log(`  [deep:${finding.packageName}]   usage file ${finding.filePath}: ${formatUsageSummary(usage)}`);
        }
        const parsed = extractJSON(text) as any;

        if (!parsed || typeof parsed !== 'object') {
          return { finding, usage };
        }

        const verdict = String(parsed.verdict ?? '')
          .trim()
          .replace(/^['"]|['"]$/g, '')
          .toUpperCase();
        if (verbose) {
          console.log(`  [deep:${finding.packageName}]   parsed verdict file ${finding.filePath}: raw=${JSON.stringify(parsed.verdict)} normalized=${verdict}`);
        }

        if (verdict === 'FALSE_POSITIVE') {
          return { finding: null, usage };
        }

        return {
          finding: {
            ...finding,
            severity: normalizeSeverity(parsed.adjustedSeverity) ?? finding.severity,
            confidence: typeof parsed.adjustedConfidence === 'number'
              ? Math.max(0, Math.min(1, parsed.adjustedConfidence))
              : finding.confidence,
            description: parsed.attackChain
              ? `${finding.description}\n\nAttack chain: ${parsed.attackChain}\nData at risk: ${parsed.dataAtRisk ?? 'Unknown'}`
              : finding.description,
            remediation: parsed.remediation ?? finding.remediation,
            deepInvestigated: true,
          },
          usage,
        };
      } catch {
        return { finding, usage: emptyUsageMetrics('deep_investigation') };
      }
    },
    concurrency
  );

  const usage = investigated.reduce(
    (acc, entry) => addUsageMetrics(acc, entry.usage),
    emptyUsageMetrics('deep_investigation')
  );
  const confirmed = investigated
    .map(entry => entry.finding)
    .filter((f): f is SupplyChainFinding => f !== null);
  if (confirmed.length === 0 && toInvestigate.length > 0) {
    if (verbose) {
      console.log(`  [deep] ZERO confirmed -- node usage total: ${formatUsageSummary(usage)}`);
    }
    return { findings, usage };
  }

  if (verbose) {
    console.log(`  [deep] node usage total: ${formatUsageSummary(usage)}`);
  }

  return { findings: [...confirmed, ...passThrough], usage };
}

function normalizeSeverity(s: unknown): SupplyChainFinding['severity'] | undefined {
  const str = String(s).toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(str)) {
    return str as SupplyChainFinding['severity'];
  }
  return undefined;
}

function getModelName(chatModel: BaseChatModel): string {
  return (
    (chatModel as any).model ??
    (chatModel as any).modelName ??
    (chatModel as any).model_name ??
    'unknown'
  );
}
