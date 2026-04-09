import { HumanMessage, SystemMessage, AIMessage, ToolMessage } from '@langchain/core/messages';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { Runnable } from '@langchain/core/runnables';
import type { LLMUsageMetrics, PackageMetadata, PackageSource, SupplyChainFinding } from '../types.js';
import { createPackageTools, buildContentMap, runTriage, formatTriageResults } from '../llm/tools.js';
import { buildAgentSystemPrompt, buildFileAnalysisPrompt } from '../llm/prompts.js';
import { pMap } from '../utils.js';
import { addUsageMetrics, emptyUsageMetrics, usageFromMessage } from '../llm/usage.js';

/** Max LLM rounds per file for the agentic loop (grep, read_file, etc.) */
const MAX_ROUNDS_PER_FILE = 10;
const MAX_INVOKE_RETRIES = 3;
const INVOKE_RETRY_DELAY_MS = 750;

/** Minimum triage score for a file to be investigated */
const MIN_TRIAGE_SCORE = 8;

/**
 * Max files to send to the LLM per package. For large packages this prevents
 * hundreds of API calls. Override with SC_MAX_LLM_FILES env var.
 *
 * Files matching INSTALL_TRIGGER_RE are always elevated above the cap —
 * these file types (pth, shell scripts) should never contain executable
 * code in a legitimate package, so any indicators are high priority.
 */
const MAX_LLM_FILES = parseInt(process.env.SC_MAX_LLM_FILES ?? '10');
const INSTALL_TRIGGER_RE = /\.(pth|sh|bat|ps1)$|\/(?:post-?install|pre-?install|install)\.[jt]s$/i;

export interface PackageInvestigationPlan {
  allContent: Map<string, string>;
  triageResults: ReturnType<typeof runTriage>;
  filesToInvestigate: ReturnType<typeof runTriage>;
}

type ToolBoundChatModel = Runnable<any, AIMessage>;

async function sleep(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms));
}

async function invokeWithRetry(
  modelWithTools: ToolBoundChatModel,
  messages: any[],
  context: string,
  verbose: boolean,
  modelName: string
): Promise<{ response: AIMessage; usage: LLMUsageMetrics }> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= MAX_INVOKE_RETRIES; attempt++) {
    try {
      const response = await modelWithTools.invoke(messages);
      return {
        response,
        usage: usageFromMessage(response, modelName, 'primary_analysis'),
      };
    } catch (error: any) {
      lastError = error;
      const detail = error?.message ?? String(error);
      const isLastAttempt = attempt === MAX_INVOKE_RETRIES;

      if (verbose) {
        console.error(`  ⚠ ${context} attempt ${attempt}/${MAX_INVOKE_RETRIES} failed: ${detail}`);
      }

      if (isLastAttempt) {
        break;
      }

      await sleep(INVOKE_RETRY_DELAY_MS * attempt);
    }
  }

  const detail = lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(`${context}: ${detail}`);
}

function formatUsageSummary(usage: LLMUsageMetrics): string {
  const costText = usage.costEstimateAvailable
    ? `$${usage.estimatedCostUsd.toFixed(4)}`
    : 'unavailable';
  return `${usage.calls} call(s), ${usage.inputTokens} input, ${usage.outputTokens} output, ${usage.totalTokens} total, estimated cost ${costText}`;
}

function formatElapsedTime(startTime: number): string {
  const elapsedMs = Date.now() - startTime;
  return elapsedMs < 1000
    ? `${elapsedMs}ms`
    : `${(elapsedMs / 1000).toFixed(2)}s`;
}

function messageToText(message: any): string {
  const content = message?.content;
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

function logConversationInput(packageName: string, filePath: string, round: number, messages: any[]): void {
  console.log(`  [analyze:${packageName}]   input file ${filePath} round ${round}:`);
  for (const message of messages) {
    const type = message?.getType?.() ?? message?.constructor?.name ?? 'message';
    console.log(`  [analyze:${packageName}]     [${type}]`);
    console.log(messageToText(message));
  }
}

function logConversationOutput(packageName: string, filePath: string, round: number, response: AIMessage): void {
  console.log(`  [analyze:${packageName}]   output file ${filePath} round ${round}:`);
  console.log(messageToText(response));
}

function logPackageFileScores(
  packageName: string,
  allContent: Map<string, string>,
  triageResults: ReturnType<typeof runTriage>,
  filesToInvestigate: ReturnType<typeof runTriage>
): void {
  const triageByPath = new Map(triageResults.map(result => [result.filePath, result]));
  console.log(`  [triage:${packageName}] package files with risk scores:`);
  for (const filePath of [...allContent.keys()].sort()) {
    const triage = triageByPath.get(filePath);
    const categories = triage ? [...triage.categories].join('+') : 'none';
    console.log(`  [triage:${packageName}]   [score: ${triage?.score ?? 0}] ${filePath} (categories: ${categories})`);
  }
  console.log(`  [triage:${packageName}] files selected for LLM scan:`);
  for (const triage of filesToInvestigate) {
    console.log(`  [triage:${packageName}]   [score: ${triage.score}] ${triage.filePath} (categories: ${[...triage.categories].join('+')})`);
  }
}

/**
 * Run the tool-calling agent analysis on all packages.
 * For each package, the LLM gets tools to explore the source code interactively.
 */
export async function primaryAnalysisNode(
  metadata: Map<string, PackageMetadata>,
  sources: Map<string, PackageSource>,
  chatModel: BaseChatModel,
  concurrency: number = 3,
  verbose: boolean = false,
  onProgress?: (done: number, total: number) => void
): Promise<{ findings: SupplyChainFinding[]; usage: LLMUsageMetrics }> {
  const nodeStartTime = Date.now();
  const findings: SupplyChainFinding[] = [];

  const tasks: Array<{ meta: PackageMetadata; source: PackageSource }> = [];
  for (const [key, meta] of metadata) {
    const source = sources.get(key);
    if (source) tasks.push({ meta, source });
  }

  let done = 0;
  const errors: Array<{ pkg: string; error: string }> = [];
  let packagesNeedingLlm = 0;

  const results = await pMap(
    tasks,
    async ({ meta, source }) => {
      try {
        const result = await analyzePackageWithModel(meta, source, chatModel, verbose);
        if (result.needsLlm) packagesNeedingLlm++;
        done++;
        onProgress?.(done, tasks.length);
        return result;
      } catch (err: any) {
        const msg = err?.message ?? String(err);
        errors.push({ pkg: meta.name, error: msg });
        packagesNeedingLlm++;
        done++;
        onProgress?.(done, tasks.length);
        return { findings: [], needsLlm: true, usage: emptyUsageMetrics('primary_analysis') };
      }
    },
    concurrency
  );

  for (const r of results) {
    findings.push(...r.findings);
  }
  const usage = results.reduce(
    (acc, result) => addUsageMetrics(acc, result.usage),
    emptyUsageMetrics('primary_analysis')
  );

  // If every package that needed LLM analysis failed, throw so the caller knows
  if (errors.length > 0 && errors.length >= packagesNeedingLlm) {
    throw new Error(
      `All ${errors.length} LLM analysis calls failed. First error: ${errors[0].error}`
    );
  }

  // If some failed, log warnings
  if (errors.length > 0) {
    console.error(`  ⚠ ${errors.length}/${packagesNeedingLlm} package analyses failed:`);
    for (const { pkg, error } of errors) {
      console.error(`    - ${pkg}: ${error}`);
    }
  }

  console.log(`  [primary] node usage total: ${formatUsageSummary(usage)} | elapsed ${formatElapsedTime(nodeStartTime)}`);

  return { findings, usage };
}

export function planPackageInvestigation(source: PackageSource): PackageInvestigationPlan {
  const allContent = buildContentMap(source);
  const triageResults = runTriage(allContent);
  const aboveThreshold = triageResults.filter(r => r.score >= MIN_TRIAGE_SCORE);

  let filesToInvestigate = aboveThreshold;
  if (aboveThreshold.length > MAX_LLM_FILES) {
    const priority = aboveThreshold.filter(r => INSTALL_TRIGGER_RE.test(r.filePath));
    const rest = aboveThreshold
      .filter(r => !INSTALL_TRIGGER_RE.test(r.filePath))
      .slice(0, Math.max(0, MAX_LLM_FILES - priority.length));
    filesToInvestigate = [...priority, ...rest];
  }

  return {
    allContent,
    triageResults,
    filesToInvestigate,
  };
}

/**
 * Investigate a single package using a two-phase approach:
 * 1. Programmatic triage — score all files against threat indicators
 * 2. Per-file LLM analysis — feed each suspicious file to the LLM for judgment
 */
export async function analyzePackageWithModel(
  meta: PackageMetadata,
  source: PackageSource,
  chatModel: BaseChatModel,
  verbose: boolean
): Promise<{ findings: SupplyChainFinding[]; needsLlm: boolean; usage: LLMUsageMetrics }> {
  const packageStartTime = Date.now();
  const { allContent, triageResults, filesToInvestigate } = planPackageInvestigation(source);

  if (verbose) {
    console.log(`  [triage:${meta.name}] ${allContent.size} files scanned, ${triageResults.length} with indicators`);
    console.log(formatTriageResults(triageResults, allContent.size).split('\n').map(l => `  [triage:${meta.name}] ${l}`).join('\n'));
  }

  if (verbose) {
    const aboveThreshold = triageResults.filter(r => r.score >= MIN_TRIAGE_SCORE);
    console.log(`  [triage:${meta.name}] ${aboveThreshold.length} files above score threshold (${MIN_TRIAGE_SCORE}), sending ${filesToInvestigate.length} to LLM (cap: ${MAX_LLM_FILES})`);
    logPackageFileScores(meta.name, allContent, triageResults, filesToInvestigate);
  }

  if (filesToInvestigate.length === 0) {
    return { findings: [], needsLlm: false, usage: emptyUsageMetrics('primary_analysis') };
  }

  // Phase 2: Per-file LLM analysis
  const { listFiles, readFile, grepPackage, reportFindings } = createPackageTools(source, allContent);
  const tools = [listFiles, readFile, grepPackage, reportFindings];
  const systemPrompt = buildAgentSystemPrompt();
  const toolMap: Record<string, any> = {
    list_files: listFiles,
    read_file: readFile,
    grep_package: grepPackage,
    report_findings: reportFindings,
  };

  const findingsByFile = await Promise.all(
    filesToInvestigate.map(async (triageEntry, fileIdx) => {
      try {
        const fileStartTime = Date.now();
        const fileContent = allContent.get(triageEntry.filePath);
        if (!fileContent) {
          return { findings: [] as SupplyChainFinding[], usage: emptyUsageMetrics('primary_analysis') };
        }

        if (verbose) {
          console.log(`  [analyze:${meta.name}] file ${fileIdx + 1}/${filesToInvestigate.length}: ${triageEntry.filePath} (score: ${triageEntry.score}, categories: ${[...triageEntry.categories].join('+')})`);
        }

        const modelWithTools = chatModel.bindTools!(tools) as ToolBoundChatModel;
        const filePrompt = buildFileAnalysisPrompt(meta, triageEntry, fileContent, source);
        const messages: any[] = [
          new SystemMessage(systemPrompt),
          new HumanMessage(filePrompt),
        ];
        const fileFindings: SupplyChainFinding[] = [];
        let fileUsage = emptyUsageMetrics('primary_analysis');

        // Agentic loop for this file — LLM can use grep/read_file for additional context
        for (let round = 0; round < MAX_ROUNDS_PER_FILE; round++) {
          const roundStartTime = Date.now();
          if (verbose) {
            logConversationInput(meta.name, triageEntry.filePath, round + 1, messages);
          }
          const { response, usage: roundUsage } = await invokeWithRetry(
            modelWithTools,
            messages,
            `LLM analysis failed for ${meta.name}@${source.version} file ${triageEntry.filePath} during round ${round + 1}`,
            verbose,
            getModelName(chatModel)
          );
          if (verbose) {
            logConversationOutput(meta.name, triageEntry.filePath, round + 1, response);
            const roundCostText = roundUsage.costEstimateAvailable
              ? `$${roundUsage.estimatedCostUsd.toFixed(4)}`
              : 'unavailable';
            console.log(
              `  [analyze:${meta.name}]   usage file ${triageEntry.filePath} round ${round + 1}: ${roundUsage.inputTokens} input, ${roundUsage.outputTokens} output, ${roundUsage.totalTokens} total, estimated cost ${roundCostText}, elapsed ${formatElapsedTime(roundStartTime)}`
            );
          }
          fileUsage = addUsageMetrics(fileUsage, roundUsage);
          messages.push(response);

          const toolCalls = response.tool_calls;
          if (!toolCalls || toolCalls.length === 0) break;

          for (const tc of toolCalls) {
            if (verbose) {
              const argsPreview = JSON.stringify(tc.args).slice(0, 150);
              console.log(`  [analyze:${meta.name}]   tool: ${tc.name}(${argsPreview})`);
            }

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

            if (tc.name === 'report_findings' && tc.args?.findings) {
              const newFindings = (tc.args.findings as any[]).map((f): SupplyChainFinding => ({
                packageName: meta.name,
                packageVersion: source.version,
                ecosystem: meta.ecosystem,
                filePath: triageEntry.filePath,
                category: f.category ?? 'code-obfuscation',
                severity: normalizeSeverity(f.severity),
                confidence: typeof f.confidence === 'number' ? Math.max(0, Math.min(1, f.confidence)) : 0.5,
                title: f.title ?? 'Unknown finding',
                description: f.description ?? '',
                evidence: f.evidence ?? '',
                remediation: f.remediation ?? 'Review the package source code manually.',
                deepInvestigated: false,
              }));
              fileFindings.push(...newFindings);
              if (verbose) {
                console.log(`  [analyze:${meta.name}]   reported ${newFindings.length} finding(s) for ${triageEntry.filePath} (file total: ${fileFindings.length})`);
              }
            }
          }
        }

        if (verbose) {
          console.log(`  [analyze:${meta.name}] file usage ${triageEntry.filePath}: ${formatUsageSummary(fileUsage)} | elapsed ${formatElapsedTime(fileStartTime)}`);
        }

        return { findings: fileFindings, usage: fileUsage };
      } catch (error: any) {
        const detail = error?.message ?? String(error);
        console.error(`  ⚠ ${detail}`);
        return { findings: [] as SupplyChainFinding[], usage: emptyUsageMetrics('primary_analysis') };
      }
    })
  );

  const allFindings = findingsByFile.flatMap(entry => entry.findings);
  const usage = findingsByFile.reduce(
    (acc, entry) => addUsageMetrics(acc, entry.usage),
    emptyUsageMetrics('primary_analysis')
  );

  if (verbose) {
    console.log(`  [analyze:${meta.name}] complete — ${allFindings.length} findings from ${filesToInvestigate.length} files in ${formatElapsedTime(packageStartTime)}`);
    console.log(`  [analyze:${meta.name}] node usage total: ${formatUsageSummary(usage)} | elapsed ${formatElapsedTime(packageStartTime)}`);
  }

  return { findings: allFindings, needsLlm: true, usage };
}

function normalizeSeverity(s: unknown): SupplyChainFinding['severity'] {
  const str = String(s).toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(str)) {
    return str as SupplyChainFinding['severity'];
  }
  return 'MEDIUM';
}

function getModelName(chatModel: BaseChatModel): string {
  return (
    (chatModel as any).model ??
    (chatModel as any).modelName ??
    (chatModel as any).model_name ??
    'unknown'
  );
}
