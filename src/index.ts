import * as clack from '@clack/prompts';
import { Command } from 'commander';
import { resolve } from 'node:path';
import { cwd } from 'node:process';
import open from 'open';
import ora from 'ora';

import { GitHubDataSource, OSVDataSource } from './auditor/datasources/index.js';
import { VulnerabilityChecker } from './auditor/vulnerability-checker.js';
import { parseDependencies } from './scanner/dependency-parser.js';
import { buildDependencyTree, flattenDependencyTree } from './scanner/dependency-tree-resolver.js';
import { findDependencyFiles } from './scanner/file-finder.js';
import { detectLanguages } from './scanner/language-detector.js';
import type { Dependency, DependencyEdge } from './scanner/types.js';
import { analyzeSupplyChain, type SupplyChainReport } from './supply-chain/index.js';
import { Reporter } from './ui/reporter.js';
import { icons, theme } from './ui/theme.js';
import { shouldFailOnSeverity } from './utils/config.js';
import { cloneRepository } from './utils/git-clone.js';
import { Logger } from './utils/logger.js';

const program = new Command();

program
  .name('who-touched-my-packages')
  .description('A beautiful CLI tool for auditing dependencies and finding vulnerabilities')
  .version('0.1.0')
  .option('-p, --path <directory>', 'Path to scan (default: current directory)', '.')
  .option('-r, --repo <url>', 'Git repository URL to clone and scan')
  .option('-b, --branch <name>', 'Branch to checkout when cloning repository')
  .option('-e, --exclude <patterns...>', 'Patterns to exclude from scanning', [])
  .option('-s, --severity <level>', 'Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)')
  .option('-f, --fail-on <level>', 'Exit with error code if vulnerabilities at or above this severity are found')
  .option('-j, --json', 'Output results as JSON', false)
  .option('--html', 'Generate HTML report and open in browser (default)', true)
  .option('--no-html', 'Disable HTML report generation')
  .option('-v, --verbose', 'Verbose output', false)
  .option('--supply-chain', 'Enable supply chain security analysis', false)
  .option('--supply-chain-api-key <key>', 'API key for LLM analysis (or set ANTHROPIC_API_KEY env var)')
  .option('--supply-chain-model <model>', 'LLM model to use for supply chain analysis', 'claude-sonnet-4-5-20241022')
  .option('--supply-chain-provider <provider>', 'LLM provider (anthropic, openrouter, openai)', 'anthropic')
  .option('--supply-chain-concurrency <number>', 'Number of concurrent LLM requests', '3')
  .option('--supply-chain-dry-run', 'Skip actual LLM calls (for testing)', false)
  .parse();

const options = program.opts();

async function main() {
  const logger = new Logger(options.verbose);
  
  let scanPath: string;
  let cleanup: (() => Promise<void>) | null = null;
  
  if (options.repo) {
    if (!options.json) {
      const spinner = ora({
        text: `Cloning repository${options.branch ? ` (branch: ${options.branch})` : ''}...`,
        color: 'cyan',
      }).start();
      
      try {
        const cloneResult = await cloneRepository({
          repoUrl: options.repo,
          branch: options.branch,
        });
        scanPath = cloneResult.path;
        cleanup = cloneResult.cleanup;
        spinner.succeed(`Repository cloned to ${scanPath}`);
      } catch (error) {
        spinner.fail('Failed to clone repository');
        throw error;
      }
    } else {
      const cloneResult = await cloneRepository({
        repoUrl: options.repo,
        branch: options.branch,
      });
      scanPath = cloneResult.path;
      cleanup = cloneResult.cleanup;
    }
  } else {
    scanPath = resolve(cwd(), options.path);
  }
  
  if (!options.json) {
    clack.intro(theme.bold(`${icons.shield} Who Touched My Packages?`));
    console.log(theme.dim('  ⚠️  This program is a work in progress. Accuracy is not guaranteed.\n'));
  }
  
  let spinner: ReturnType<typeof ora> | null = null;
  
  if (!options.json) {
    spinner = ora({
      text: 'Scanning for dependency files...',
      color: 'cyan',
    }).start();
  }
  
  const files = await findDependencyFiles(scanPath, options.exclude);
  
  if (spinner) {
    spinner.text = 'Parsing dependencies...';
  }
  
  if (files.length === 0) {
    if (!options.json) {
      clack.outro(theme.dim('No dependency files found.'));
    }
    process.exit(0);
  }
  
  const dependencies = await parseDependencies(files);
  
  if (spinner) {
    spinner.text = 'Checking for vulnerabilities...';
  }
  
  const reporter = new Reporter({
    json: options.json,
    severityFilter: options.severity,
    verbose: options.verbose,
    html: options.html,
    supplyChain: options.supplyChain,
  });
  
  // Build dependency trees for graph visualization
  let allDependencies: Dependency[] = dependencies;
  let dependencyEdges: DependencyEdge[] = [];
  
  if (options.html) {
    if (spinner) {
      spinner.text = 'Building dependency trees...';
    }
    
    const npmFiles = files.filter(f => f.type === 'package.json');
    const pythonFiles = files.filter(f => f.type === 'requirements.txt');
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
      } catch (error) {
        // Skip files that fail to parse
      }
    }
    
    // Include Python dependencies in the graph (flat list, no deep tree resolution yet)
    for (const file of pythonFiles) {
      const pythonDeps = dependencies.filter(d => d.file === file.path && d.ecosystem === 'pypi');
      for (const dep of pythonDeps) {
        const key = `${dep.name}@${dep.version}`;
        if (!allTreeNodes.has(key)) {
          allTreeNodes.set(key, dep);
        }
      }
    }
    
    allDependencies = Array.from(allTreeNodes.values());
  }
  
  if (dependencies.length === 0) {
    if (!options.json && !options.html) {
      clack.outro(theme.dim('No dependencies found.'));
    }
    process.exit(0);
  }
  
  const dataSources = [
    new OSVDataSource(),
    new GitHubDataSource(),
  ];
  
  const checker = new VulnerabilityChecker(dataSources);
  const result = await checker.checkDependencies(dependencies);
  
  // Run supply chain analysis if enabled
  let supplyChainReport: SupplyChainReport | undefined;
  if (options.supplyChain) {
    if (spinner) {
      spinner.text = 'Running supply chain security analysis...';
    }
    
    try {
      supplyChainReport = await analyzeSupplyChain(allDependencies, {
        apiKey: options.supplyChainApiKey,
        model: options.supplyChainModel,
        provider: options.supplyChainProvider,
        concurrency: parseInt(options.supplyChainConcurrency, 10),
        dryRun: options.supplyChainDryRun,
      }, (stage, done, total) => {
        if (spinner) {
          spinner.text = `Supply chain analysis: ${stage} (${done}/${total})...`;
        }
      });
      
      if (spinner) {
        spinner.succeed('Supply chain analysis complete');
      }
    } catch (error: any) {
      if (spinner) {
        spinner.fail(`Supply chain analysis failed: ${error.message}`);
      } else if (options.verbose) {
        console.error(`Supply chain analysis error: ${error.message}`);
      }
    }
  }
  
  if (spinner) {
    spinner.succeed('Scan complete');
  }
  
  if (options.html) {
    if (!options.json) {
      spinner = ora({
        text: 'Generating HTML report...',
        color: 'cyan',
      }).start();
    }
    
    const languageStats = await detectLanguages(scanPath, options.exclude);
    const server = await reporter.generateHtmlReport(result, allDependencies, scanPath, options.repo, languageStats, dependencyEdges, supplyChainReport);
    
    if (spinner) {
      spinner.succeed('HTML report generated');
    }
    
    if (!options.json) {
      console.log(theme.info(`\n📄 Opening report in browser...`));
    }
    
    await open(server.url);
    
    if (!options.json) {
      console.log(theme.success(`${icons.success} Report opened in browser!`));
      console.log(theme.dim(`Server running at ${server.url}`));
      console.log(theme.dim('Press Ctrl+C to stop the server\n'));
    }
    
    // Keep the process running
    process.on('SIGINT', async () => {
      if (!options.json) {
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
    reporter.reportResults(result, files, dependencies, supplyChainReport);
  }
  
  if (cleanup) {
    await cleanup();
  }
  
  if (options.failOn && shouldFailOnSeverity(result.summary, options.failOn)) {
    process.exit(1);
  }
  
  // Also fail on supply chain findings if fail-on is set and there are critical/high findings
  if (options.failOn && supplyChainReport && shouldFailOnSeverity(supplyChainReport.summary, options.failOn)) {
    process.exit(1);
  }
  
  process.exit(0);
}

main().catch(async (error) => {
  if (!options.json) {
    clack.outro(theme.critical(`Error: ${error.message}`));
  } else {
    console.error(JSON.stringify({ error: error.message }));
  }
  process.exit(2);
});
