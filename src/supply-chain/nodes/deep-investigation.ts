import { HumanMessage } from '@langchain/core/messages';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { PackageSource, SupplyChainFinding } from '../types.js';
import { buildDeepInvestigationPrompt } from '../llm/prompts.js';
import { extractJSON, depKey, pMap } from '../utils.js';

/**
 * Deep investigation node: re-analyzes HIGH/CRITICAL findings with a targeted prompt.
 * Can confirm, downgrade, or dismiss findings.
 */
export async function deepInvestigationNode(
  findings: SupplyChainFinding[],
  sources: Map<string, PackageSource>,
  chatModel: BaseChatModel,
  concurrency: number = 3
): Promise<SupplyChainFinding[]> {
  const toInvestigate = findings.filter(
    f => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.confidence >= 0.3
  );
  const passThrough = findings.filter(
    f => !((f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.confidence >= 0.3)
  );

  if (toInvestigate.length === 0) {
    return findings;
  }

  const investigated = await pMap(
    toInvestigate,
    async (finding) => {
      const key = depKey(finding.ecosystem, finding.packageName);
      const source = sources.get(key);
      if (!source) return finding;

      try {
        const prompt = buildDeepInvestigationPrompt(finding, source);
        const response = await chatModel.invoke([new HumanMessage(prompt)]);
        const text = typeof response.content === 'string'
          ? response.content
          : (response.content as any[]).map((b: any) => b.text ?? '').join('');
        const parsed = extractJSON(text) as any;

        if (!parsed || typeof parsed !== 'object') return finding;

        const verdict = String(parsed.verdict ?? '').toUpperCase();

        if (verdict === 'FALSE_POSITIVE') {
          return null;
        }

        return {
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
        };
      } catch {
        return finding;
      }
    },
    concurrency
  );

  const confirmed = investigated.filter((f): f is SupplyChainFinding => f !== null);
  return [...confirmed, ...passThrough];
}

function normalizeSeverity(s: unknown): SupplyChainFinding['severity'] | undefined {
  const str = String(s).toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(str)) {
    return str as SupplyChainFinding['severity'];
  }
  return undefined;
}
