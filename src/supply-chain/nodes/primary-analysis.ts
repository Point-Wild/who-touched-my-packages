import { HumanMessage, SystemMessage, AIMessage, ToolMessage } from '@langchain/core/messages';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { PackageMetadata, PackageSource, SupplyChainFinding } from '../types.js';
import { createPackageTools, buildContentMap, runTriage, formatTriageResults } from '../llm/tools.js';
import { buildAgentSystemPrompt, buildFileAnalysisPrompt } from '../llm/prompts.js';
import { pMap } from '../utils.js';

/** Max LLM rounds per file for the agentic loop (grep, read_file, etc.) */
const MAX_ROUNDS_PER_FILE = 10;

/** Minimum triage score for a file to be investigated */
const MIN_TRIAGE_SCORE = 8;

/**
 * Run the tool-calling agent analysis on all packages.
 * For each package, the LLM gets tools to explore the source code interactively.
 */
export async function primaryAnalysisNode(
  metadata: Map<string, PackageMetadata>,
  sources: Map<string, PackageSource>,
  chatModel: BaseChatModel,
  concurrency: number = 3,
  onProgress?: (done: number, total: number) => void
): Promise<SupplyChainFinding[]> {
  const findings: SupplyChainFinding[] = [];

  const tasks: Array<{ meta: PackageMetadata; source: PackageSource }> = [];
  for (const [key, meta] of metadata) {
    const source = sources.get(key);
    if (source) tasks.push({ meta, source });
  }

  let done = 0;

  const results = await pMap(
    tasks,
    async ({ meta, source }) => {
      try {
        const result = await investigatePackage(meta, source, chatModel);
        done++;
        onProgress?.(done, tasks.length);
        return result;
      } catch (err) {
        console.error(`  [ERROR] ${meta.name}: ${err}`);
        done++;
        onProgress?.(done, tasks.length);
        return [];
      }
    },
    concurrency
  );

  for (const r of results) {
    findings.push(...r);
  }

  return findings;
}

/**
 * Investigate a single package using a two-phase approach:
 * 1. Programmatic triage — score all files against threat indicators
 * 2. Per-file LLM analysis — feed each suspicious file to the LLM for judgment
 */
async function investigatePackage(
  meta: PackageMetadata,
  source: PackageSource,
  chatModel: BaseChatModel
): Promise<SupplyChainFinding[]> {
  const verbose = process.env.SC_VERBOSE === '1';

  // Phase 1: Programmatic triage
  const allContent = buildContentMap(source);
  const triageResults = runTriage(allContent);

  if (verbose) {
    console.log(`  [triage:${meta.name}] ${allContent.size} files scanned, ${triageResults.length} with indicators`);
    console.log(formatTriageResults(triageResults, allContent.size).split('\n').map(l => `  [triage:${meta.name}] ${l}`).join('\n'));
  }

  // Filter to files worth investigating
  const filesToInvestigate = triageResults.filter(r => r.score >= MIN_TRIAGE_SCORE);
  if (verbose) {
    console.log(`  [triage:${meta.name}] ${filesToInvestigate.length} files above score threshold (${MIN_TRIAGE_SCORE})`);
  }

  if (filesToInvestigate.length === 0) {
    return [];
  }

  // Phase 2: Per-file LLM analysis
  const { listFiles, readFile, grepPackage, reportFindings } = createPackageTools(source, allContent);
  const tools = [listFiles, readFile, grepPackage, reportFindings];
  const modelWithTools = chatModel.bindTools!(tools);

  const allFindings: SupplyChainFinding[] = [];
  const systemPrompt = buildAgentSystemPrompt();

  for (let fileIdx = 0; fileIdx < filesToInvestigate.length; fileIdx++) {
    const triageEntry = filesToInvestigate[fileIdx];
    const fileContent = allContent.get(triageEntry.filePath);

    if (!fileContent) continue;

    if (verbose) {
      console.log(`  [analyze:${meta.name}] file ${fileIdx + 1}/${filesToInvestigate.length}: ${triageEntry.filePath} (score: ${triageEntry.score}, categories: ${[...triageEntry.categories].join('+')})`);
    }

    const filePrompt = buildFileAnalysisPrompt(meta, triageEntry, fileContent);

    const messages: any[] = [
      new SystemMessage(systemPrompt),
      new HumanMessage(filePrompt),
    ];

    // Agentic loop for this file — LLM can use grep/read_file for additional context
    for (let round = 0; round < MAX_ROUNDS_PER_FILE; round++) {
      const response = await modelWithTools.invoke(messages);
      messages.push(response);

      const toolCalls = (response as AIMessage).tool_calls;
      if (!toolCalls || toolCalls.length === 0) break;

      for (const tc of toolCalls) {
        if (verbose) {
          const argsPreview = JSON.stringify(tc.args).slice(0, 150);
          console.log(`  [analyze:${meta.name}]   tool: ${tc.name}(${argsPreview})`);
        }

        const toolMap: Record<string, any> = {
          list_files: listFiles,
          read_file: readFile,
          grep_package: grepPackage,
          report_findings: reportFindings,
        };

        const selectedTool = toolMap[tc.name];
        if (!selectedTool) {
          messages.push(new ToolMessage({
            tool_call_id: tc.id!,
            content: `Unknown tool: ${tc.name}`,
          }));
          continue;
        }

        const result = await selectedTool.invoke(tc.args);
        if (verbose && tc.name !== 'report_findings') {
          const preview = (typeof result === 'string' ? result : JSON.stringify(result)).slice(0, 150);
          console.log(`  [analyze:${meta.name}]     → ${preview}`);
        }
        messages.push(new ToolMessage({
          tool_call_id: tc.id!,
          content: typeof result === 'string' ? result : JSON.stringify(result),
        }));

        // Accumulate findings
        if (tc.name === 'report_findings' && tc.args?.findings) {
          const newFindings = (tc.args.findings as any[]).map((f): SupplyChainFinding => ({
            packageName: meta.name,
            packageVersion: source.version,
            ecosystem: meta.ecosystem,
            category: f.category ?? 'code-obfuscation',
            severity: normalizeSeverity(f.severity),
            confidence: typeof f.confidence === 'number' ? Math.max(0, Math.min(1, f.confidence)) : 0.5,
            title: f.title ?? 'Unknown finding',
            description: f.description ?? '',
            evidence: f.evidence ?? '',
            remediation: f.remediation ?? 'Review the package source code manually.',
            deepInvestigated: false,
          }));
          allFindings.push(...newFindings);
          if (verbose) {
            console.log(`  [analyze:${meta.name}]   reported ${newFindings.length} finding(s) (total: ${allFindings.length})`);
          }
        }
      }
    }
  }

  if (verbose) {
    console.log(`  [analyze:${meta.name}] complete — ${allFindings.length} findings from ${filesToInvestigate.length} files`);
  }

  return allFindings;
}

function normalizeSeverity(s: unknown): SupplyChainFinding['severity'] {
  const str = String(s).toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(str)) {
    return str as SupplyChainFinding['severity'];
  }
  return 'MEDIUM';
}
