import * as clack from '@clack/prompts';
import { Command } from 'commander';
import { resolve } from 'node:path';
import { cwd } from 'node:process';
import open from 'open';
import ora from 'ora';

import * as Package from "../package.json" assert { type: "json" };
import { OSVDataSource } from './auditor/datasources/index.js';
import { applyVerificationResults, verifyPackages } from './auditor/package-verifier.js';
import { VulnerabilityChecker } from './auditor/vulnerability-checker.js';
import { parseDependencies } from './scanner/dependency-parser.js';
import { buildDependencyTree, flattenDependencyTree } from './scanner/dependency-tree-resolver.js';
import { findDependencyFiles } from './scanner/file-finder.js';
import { detectLanguages } from './scanner/language-detector.js';
import type { Dependency, DependencyEdge, UnresolvedDependency } from './scanner/types.js';
import { analyzeSupplyChain, DEFAULT_CONCURRENCY, DEFAULT_MODEL, type SupplyChainReport } from './supply-chain/index.js';
import { buildFinalReport, displayAggregatedReport } from './ui/aggregated-report.js';
import type { ReportData } from './ui/html-report/types.js';
import { Reporter } from './ui/reporter.js';
import { icons, recreateTheme, setColorEnabled, theme } from './ui/theme.js';
import { shouldFailOnSeverity } from './utils/config.js';
import { cloneRepository } from './utils/git-clone.js';
import { Logger } from './utils/logger.js';

const program = new Command();

interface CLIOptions {
  path: string;
  repo?: string;
  branch?: string;
  exclude: string[];
  severity?: string;
  failOn?: string;
  json: boolean;
  output?: string;
  html: boolean;
  open: boolean;
  verbose: boolean;
  quiet: boolean;
  color: boolean;
  timeout: string;
  gitCloneDepth: string;
  maxDepth: string;
  supplyChain: boolean;
  supplyChainModel?: string;
  llmProvider?: 'anthropic' | 'openai' | 'gemini' | 'openrouter';
  supplyChainConcurrency: string;
  packageDepth: string;
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

async function main() {
  const logger = new Logger(options.verbose);
  
  let scanPath: string;
  let cleanup: (() => Promise<void>) | null = null;
  
  if (options.repo) {
    if (!options.json && !options.quiet) {
      const spinner = ora({
        text: `Cloning repository${options.branch ? ` (branch: ${options.branch})` : ''}...`,
        color: 'cyan',
      }).start();
      
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
    spinner = ora({
      text: 'Scanning for dependency files...',
      color: 'cyan',
    }).start();
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
        supplyChainReport = await analyzeSupplyChain(reportData.dependencies, {
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
      spinner = ora({
        text: 'Generating HTML report...',
        color: 'cyan',
      }).start();
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
      
      if (!options.json && !options.quiet) {
        console.log(theme.success(`${icons.success} Report opened in browser!`));
        console.log(theme.dim(`Server running at ${server.url}`));
        console.log(theme.dim('Press Ctrl+C to stop the server\n'));
      }
    }
    
    // Keep the process running
    process.on('SIGINT', async () => {
      if (!options.json && !options.quiet) {
        console.log(theme.dim('\n\nShutting down server...'));
      }
      server.close();
      if (cleanup) {
        await cleanup();
      }
      process.exit(0);
    });
    
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

async function scanWorkflow(
  scanPath: string,
  scanOptions: CLIOptions,
  spinner: ReturnType<typeof ora> | null
): Promise<ReportData> {
  const packageDepth = parseInt(scanOptions.packageDepth ?? '1', 10);
  const files = await findDependencyFiles(scanPath, scanOptions.exclude, parseInt(scanOptions.maxDepth, 10) || 0);

  if (spinner) {
    spinner.text = 'Parsing dependencies...';
  }

  if (files.length === 0) {
    if (!scanOptions.json && !scanOptions.quiet) {
      clack.outro(theme.dim('No dependency files found.'));
    }
    process.exit(0);
  }

  const scannedDependencies = await parseDependencies(files);

  if (spinner) {
    spinner.text = 'Checking for vulnerabilities...';
  }

  let allDependencies: Dependency[] = scannedDependencies;
  let dependencyEdges: DependencyEdge[] = [];
  let unresolvedDependencies: UnresolvedDependency[] = [];

  const needsTree = scanOptions.html || (scanOptions.supplyChain && packageDepth > 1);

  if (needsTree) {
    if (spinner) {
      spinner.text = 'Building dependency trees...';
    }

    const npmFiles = files.filter(f => f.type === 'package.json');
    const pythonFiles = files.filter(f => f.type === 'requirements.txt');
    const rustFiles = files.filter(f => f.type === 'Cargo.toml');
    const goFiles = files.filter(f => f.type === 'go.mod');
    const rubyFiles = files.filter(f => f.type === 'Gemfile.lock');
    const allTreeNodes = new Map<string, Dependency>();

    for (const file of npmFiles) {
      try {
        const tree = await buildDependencyTree(file.path, 'npm');
        const flatDeps = flattenDependencyTree(tree);

        flatDeps.forEach(dep => {
          const key = `${dep.name}@${dep.version}`;
          if (!allTreeNodes.has(key)) {
            allTreeNodes.set(key, dep);
          } else {
            const existing = allTreeNodes.get(key)!;
            if (dep.paths) {
              existing.paths = existing.paths || [];
              existing.paths.push(...dep.paths);
            }
          }
        });

        dependencyEdges.push(...tree.edges);
        unresolvedDependencies.push(...tree.unresolved);
      } catch (error) {
        // Skip files that fail to parse
      }
    }

    for (const file of pythonFiles) {
      const pythonDeps = scannedDependencies.filter(d => d.file === file.path && d.ecosystem === 'pypi');
      for (const dep of pythonDeps) {
        const key = `${dep.name}@${dep.version}`;
        if (!allTreeNodes.has(key)) {
          allTreeNodes.set(key, dep);
        }
      }
    }

    for (const file of rustFiles) {
      try {
        const tree = await buildDependencyTree(file.path, 'cargo');
        const flatDeps = flattenDependencyTree(tree);

        flatDeps.forEach(dep => {
          const key = `${dep.name}@${dep.version}`;
          if (!allTreeNodes.has(key)) {
            allTreeNodes.set(key, dep);
          } else {
            const existing = allTreeNodes.get(key)!;
            if (dep.paths) {
              existing.paths = existing.paths || [];
              existing.paths.push(...dep.paths);
            }
          }
        });

        dependencyEdges.push(...tree.edges);
        unresolvedDependencies.push(...tree.unresolved);
      } catch (error) {
        // Skip files that fail to parse
      }
    }

    for (const file of goFiles) {
      try {
        const tree = await buildDependencyTree(file.path, 'go');
        const flatDeps = flattenDependencyTree(tree);

        flatDeps.forEach(dep => {
          const key = `${dep.name}@${dep.version}`;
          if (!allTreeNodes.has(key)) {
            allTreeNodes.set(key, dep);
          } else {
            const existing = allTreeNodes.get(key)!;
            if (dep.paths) {
              existing.paths = existing.paths || [];
              existing.paths.push(...dep.paths);
            }
          }
        });

        dependencyEdges.push(...tree.edges);
        unresolvedDependencies.push(...tree.unresolved);
      } catch (error) {
        // Skip files that fail to parse
      }
    }

    for (const file of rubyFiles) {
      try {
        const tree = await buildDependencyTree(file.path, 'ruby');
        const flatDeps = flattenDependencyTree(tree);

        flatDeps.forEach(dep => {
          const key = `${dep.name}@${dep.version}`;
          if (!allTreeNodes.has(key)) {
            allTreeNodes.set(key, dep);
          } else {
            const existing = allTreeNodes.get(key)!;
            if (dep.paths) {
              existing.paths = existing.paths || [];
              existing.paths.push(...dep.paths);
            }
          }
        });

        dependencyEdges.push(...tree.edges);
        unresolvedDependencies.push(...tree.unresolved);
      } catch (error) {
        // Skip files that fail to parse
      }
    }

    allDependencies = Array.from(allTreeNodes.values());

    if (scanOptions.supplyChain && packageDepth > 1) {
      allDependencies = allDependencies.filter(d => (d.depth ?? 0) < packageDepth);
    }
  }

  if (spinner) {
    spinner.text = 'Verifying package provenance...';
  }

  try {
    const verificationResults = await verifyPackages(allDependencies);
    applyVerificationResults(allDependencies, verificationResults);
    if (allDependencies !== scannedDependencies) {
      applyVerificationResults(scannedDependencies, verificationResults);
    }
  } catch (error) {
    if (scanOptions.verbose) {
      console.log(theme.dim('Warning: Package provenance verification failed'));
    }
  }

  if (scannedDependencies.length === 0) {
    if (!scanOptions.json && !scanOptions.html && !scanOptions.quiet) {
      clack.outro(theme.dim('No dependencies found.'));
    }
    process.exit(0);
  }

  const checker = new VulnerabilityChecker([
    new OSVDataSource(),
  ]);

  const auditResult = await checker.checkDependencies(scannedDependencies);
  const languageStats = scanOptions.html
    ? await detectLanguages(scanPath, scanOptions.exclude)
    : undefined;

  return {
    auditResult,
    dependencies: allDependencies,
    scannedDependencies,
    files,
    scanPath,
    repositoryUrl: scanOptions.repo,
    languageStats,
    dependencyEdges,
    unresolvedDependencies,
  };
}

main().catch(async (error) => {
  if (!options.json && !options.quiet) {
    clack.outro(theme.critical(`Error: ${error.message}`));
  } else {
    console.error(JSON.stringify({ error: error.message }));
  }
  process.exit(2);
});
