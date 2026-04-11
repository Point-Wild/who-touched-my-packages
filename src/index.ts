import * as clack from '@clack/prompts';
import { spawnSync } from 'node:child_process';
import { Command } from 'commander';
import { resolve } from 'node:path';
import { cwd } from 'node:process';
import open from 'open';
import ora from 'ora';

import * as Package from "../package.json" assert { type: "json" };
import { OSVDataSource } from './auditor/datasources/index.js';
import { applyVerificationResults, verifyPackages } from './auditor/package-verifier.js';
import { VulnerabilityChecker } from './auditor/vulnerability-checker.js';
import type { Dependency } from './scanner/types.js';
import { scanWorkflow, type ScanWorkflowOptions } from './scan-workflow.js';
import { analyzeSupplyChain, DEFAULT_CONCURRENCY, DEFAULT_MODEL, type SupplyChainReport } from './supply-chain/index.js';
import { buildFinalReport, displayAggregatedReport } from './ui/aggregated-report.js';
import { Reporter } from './ui/reporter.js';
import { icons, recreateTheme, setColorEnabled, theme } from './ui/theme.js';
import { shouldFailOnSeverity } from './utils/config.js';
import { cloneRepository } from './utils/git-clone.js';
import { Logger } from './utils/logger.js';

const program = new Command();

interface CLIOptions extends ScanWorkflowOptions {
  path: string;
  branch?: string;
  severity?: string;
  failOn?: string;
  output?: string;
  open: boolean;
  color: boolean;
  timeout: string;
  gitCloneDepth: string;
  supplyChainModel?: string;
  llmProvider?: 'anthropic' | 'openai' | 'gemini' | 'openrouter';
  supplyChainConcurrency: string;
  supplyChainMaxPackages: string;
  supplyChainDryRun: boolean;
}

program
  .name('who-touched-my-packages')
  .description('A beautiful CLI tool for auditing dependencies and finding vulnerabilities')
  .version(Package.version)
  .option('-p, --path <directory>', 'Path to scan (default: current directory)', '.')
  .option('-r, --repo <url>', 'Git repository URL to clone and scan')
  .option('-b, --branch <name>', 'Branch to checkout when cloning repository')
  .option('-e, --exclude <patterns...>', 'Patterns to exclude from scanning', [])
  .option('-s, --severity <level>', 'Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)')
  .option('-f, --fail-on <level>', 'Exit with error code if vulnerabilities at or above this severity are found')
  .option('-j, --json', 'Output results as JSON', false)
  .option('-o, --output <file>', 'Save report to file instead of stdout/browser')
  .option('--html', 'Generate HTML report and open in browser (default)', true)
  .option('--no-html', 'Disable HTML report generation')
  .option('--no-open', 'Generate HTML report but do not open in browser')
  .option('-v, --verbose', 'Verbose output', false)
  .option('-q, --quiet', 'Suppress non-error output', false)
  .option('--no-color', 'Disable colored terminal output')
  .option('--timeout <seconds>', 'Operation timeout in seconds', '300')
  .option('--git-clone-depth <number>', 'Git clone depth (shallow clones)', '0')
  .option('--max-depth <number>', 'Maximum directory recursion depth', '0')
  .option('--supply-chain', 'Enable supply chain security analysis', false)
  .option('--supply-chain-model <model>', `LLM model for supply chain analysis (default: per-provider, e.g. ${DEFAULT_MODEL})`)
  .option('--llm-provider <provider>', 'LLM provider — auto-detected from model name when omitted (anthropic, openai, gemini, openrouter)')
  .option('--supply-chain-concurrency <number>', 'Number of concurrent LLM requests', String(DEFAULT_CONCURRENCY))
  .option('--package-depth <number>', 'Maximum dependency package depth to include in graph/supply-chain input (1 = direct only)', '1')
  .option('--supply-chain-max-packages <number>', 'Maximum packages to analyse in supply chain scan (0 = unlimited)', '0')
  .option('--supply-chain-dry-run', 'Skip actual LLM calls (for testing)', false)
  .parse();

const options = program.opts() as CLIOptions;

// Handle --no-color option early (before any output)
if (options.color === false) {
  setColorEnabled(false);
  recreateTheme();
}

// Auto-disable HTML generation in CI environments
const isCI = process.env.CI ||
  process.env.GITHUB_ACTIONS ||
  process.env.GITLAB_CI ||
  process.env.CIRCLECI ||
  process.env.TRAVIS ||
  process.env.DRONE ||
  process.env.BUILDKITE ||
  process.env.JENKINS ||
  process.env.TEAMCITY_VERSION;

if (isCI) {
  options.html = false;
}

function createSpinner(text: string): ReturnType<typeof ora> {
  return ora({
    text,
    color: 'cyan',
    discardStdin: false,
  });
}

function restoreTerminalInput(): void {
  if (!process.stdin.isTTY) {
    return;
  }

  try {
    process.stdin.setRawMode?.(false);
  } catch {
    // Ignore terminal state restoration errors
  }

  try {
    process.stdin.pause();
  } catch {
    // Ignore terminal state restoration errors
  }

  try {
    spawnSync('stty', ['sane'], { stdio: 'inherit' });
  } catch {
    // Ignore terminal state restoration errors
  }
}

async function main() {
  const logger = new Logger(options.verbose);
  
  let scanPath: string;
  let cleanup: (() => Promise<void>) | null = null;
  
  if (options.repo) {
    if (!options.json && !options.quiet) {
      const spinner = createSpinner(`Cloning repository${options.branch ? ` (branch: ${options.branch})` : ''}...`).start();
      
      try {
        const cloneResult = await cloneRepository({
          repoUrl: options.repo,
          branch: options.branch,
          depth: parseInt(options.gitCloneDepth, 10) || undefined,
        });
        scanPath = cloneResult.path;
        cleanup = cloneResult.cleanup;
        spinner.succeed(` Repository cloned to ${scanPath}`);
      } catch (error) {
        spinner.fail('Failed to clone repository');
        throw error;
      }
    } else {
      const cloneResult = await cloneRepository({
        repoUrl: options.repo,
        branch: options.branch,
        depth: parseInt(options.gitCloneDepth, 10) || undefined,
      });
      scanPath = cloneResult.path;
      cleanup = cloneResult.cleanup;
    }
  } else {
    scanPath = resolve(cwd(), options.path);
  }
  
  if (!options.json && !options.quiet) {
    clack.intro(theme.bold(`${icons.shield} Who Touched My Packages?`));
    console.log(theme.dim('  ⚠️  This program is a work in progress. Accuracy is not guaranteed.\n'));
  }
  
  const reporter = new Reporter({
    json: options.json,
    severityFilter: options.severity,
    verbose: options.verbose,
    html: options.html,
    supplyChain: options.supplyChain,
    output: options.output,
  });
  let spinner: ReturnType<typeof ora> | null = null;
  if (!options.json && !options.quiet) {
    spinner = createSpinner('Scanning for dependency files...').start();
  }
  const reportData = await scanWorkflow(scanPath, options, spinner);
  let finalReport = buildFinalReport(reportData);
  
  // Run supply chain analysis if enabled
  let supplyChainReport: SupplyChainReport | undefined;
  if (options.supplyChain) {
    const blockingVulnerablePackages = new Set(
      reportData.auditResult.vulnerabilities
        .filter(v => v.severity !== 'LOW')
        .map(v => `${v.ecosystem}:${v.packageName}@${v.packageVersion}`)
    );
    const skippedSupplyChainDependencies = reportData.dependencies.filter(
      dep => blockingVulnerablePackages.has(`${dep.ecosystem}:${dep.name}@${dep.version}`)
    );
    const supplyChainDependencies = reportData.dependencies.filter(
      dep => !blockingVulnerablePackages.has(`${dep.ecosystem}:${dep.name}@${dep.version}`)
    );

    if (skippedSupplyChainDependencies.length > 0 && !options.json && !options.quiet) {
      console.log(theme.dim('\nSkipping supply chain analysis for packages with known vulnerabilities:'));
      for (const dep of skippedSupplyChainDependencies) {
        console.log(theme.dim(`  • [${dep.ecosystem}] ${dep.name}@${dep.version}`));
      }
    }

    if (supplyChainDependencies.length === 0) {
      if (!options.json && !options.quiet) {
        console.log(theme.dim('No packages remain for supply chain analysis after excluding known vulnerable packages.'));
      }
    } else {
      if (spinner) {
        spinner.text = 'Running supply chain security analysis...';
      }

      try {
        supplyChainReport = await analyzeSupplyChain(supplyChainDependencies, {
          model: options.supplyChainModel,
          provider: options.llmProvider,
          concurrency: parseInt(options.supplyChainConcurrency, 10),
          verbose: options.verbose,
          maxPackages: parseInt(options.supplyChainMaxPackages ?? '0', 10),
          dryRun: options.supplyChainDryRun,
        }, (stage, done, total) => {
          if (spinner) {
            spinner.text = `Supply chain analysis: ${stage} (${done}/${total})...`;
          }
        });

        if (spinner) {
          spinner.succeed('Supply chain analysis complete');
        }

        if (supplyChainReport.fetchErrors.length > 0 && !options.json && !options.quiet) {
          console.log(theme.high(`\n${icons.warning} ${supplyChainReport.fetchErrors.length} package fetch error(s) during supply chain analysis:`));
          for (const error of supplyChainReport.fetchErrors.slice(0, 5)) {
            const target = error.packageVersion
              ? `${error.packageName}@${error.packageVersion}`
              : error.packageName;
            console.log(theme.dim(`  • [${error.ecosystem}/${error.stage}] ${target}: ${error.message}`));
          }
          if (supplyChainReport.fetchErrors.length > 5) {
            console.log(theme.dim(`  ... and ${supplyChainReport.fetchErrors.length - 5} more`));
          }
        }

        if (options.verbose && !options.json && !options.quiet) {
          const { llmUsage } = supplyChainReport;
          console.log(theme.bold('\nLLM Usage:'));
          for (const [nodeName, usage] of Object.entries(llmUsage.byNode)) {
            const costText = usage.costEstimateAvailable
              ? `$${usage.estimatedCostUsd.toFixed(4)}`
              : 'unavailable';
            console.log(theme.dim(
              `  • ${nodeName}: ${usage.calls} call(s), ${usage.inputTokens} input, ${usage.outputTokens} output, ${usage.totalTokens} total, estimated cost ${costText}`
            ));
          }

          const totalCostText = llmUsage.total.costEstimateAvailable
            ? `$${llmUsage.total.estimatedCostUsd.toFixed(4)}`
            : 'unavailable';
          console.log(theme.dim(
            `  Total: ${llmUsage.total.calls} call(s), ${llmUsage.total.inputTokens} input, ${llmUsage.total.outputTokens} output, ${llmUsage.total.totalTokens} total, estimated cost ${totalCostText}`
          ));
        }
      } catch (error: any) {
        if (spinner) {
          spinner.fail(`Supply chain analysis failed: ${error.message}`);
        } else if (options.verbose) {
          console.error(`Supply chain analysis error: ${error.message}`);
        }
      }
    }
  }
  
  if (spinner) {
    spinner.succeed('Scan complete');
  }
  finalReport = buildFinalReport(reportData, supplyChainReport);
  if (!options.json && !options.quiet) {
    displayAggregatedReport(finalReport);
  }
  
  if (options.html) {
    if (!options.json && !options.quiet) {
      spinner = createSpinner('Generating HTML report...').start();
    }
    
    const server = await reporter.generateHtmlReport(finalReport);
    
    if (spinner) {
      spinner.succeed('HTML report generated');
    }
    
    if (!options.open) {
      // --no-open flag was used
      if (!options.json && !options.quiet) {
        console.log(theme.info(`\n📄 HTML report available at: ${server.url}`));
        console.log(theme.dim('Server running. Press Ctrl+C to stop.\n'));
      }
    } else {
      if (!options.json && !options.quiet) {
        console.log(theme.info(`\n📄 Opening report in browser...`));
      }
      
      await open(server.url);
      restoreTerminalInput();
      
      if (!options.json && !options.quiet) {
        console.log(theme.success(`${icons.success} Report opened in browser!`));
        console.log(theme.dim(`Server running at ${server.url}`));
        console.log(theme.dim('Press Ctrl+C to stop the server\n'));
      }
    }

    restoreTerminalInput();
    
    const shutdown = async () => {
      restoreTerminalInput();
      if (!options.json && !options.quiet) {
        console.log(theme.dim('\n\nShutting down server...'));
      }
      server.close();
      if (cleanup) {
        await cleanup();
      }
      process.exit(0);
    };

    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    
    // Don't exit - keep server running
    return;
  } else {
    reporter.reportResults(finalReport, options.repo);
  }
  
  if (cleanup) {
    await cleanup();
  }
  
  if (options.failOn && shouldFailOnSeverity(reportData.auditResult.summary, options.failOn)) {
    process.exit(1);
  }
  
  // Also fail on supply chain findings if fail-on is set and there are critical/high findings
  if (options.failOn && supplyChainReport && shouldFailOnSeverity(supplyChainReport.summary, options.failOn)) {
    process.exit(1);
  }
  
  process.exit(0);
}

main().catch(async (error) => {
  if (!options.json && !options.quiet) {
    clack.outro(theme.critical(`Error: ${error.message}`));
  } else {
    console.error(JSON.stringify({ error: error.message }));
  }
  process.exit(2);
});
