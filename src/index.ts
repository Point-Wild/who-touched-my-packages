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
import { Reporter } from './ui/reporter.js';
import { icons, theme } from './ui/theme.js';
import { shouldFailOnSeverity } from './utils/config.js';
import { cloneRepository } from './utils/git-clone.js';
import { Logger } from './utils/logger.js';

const program = new Command();

program
  .name('who-touched-my-deps')
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
    clack.intro(theme.bold(`${icons.shield} Who Touched My Deps?`));
    console.log(theme.dim('  ⚠️  This program is a work in progress. Accuracy is not guaranteed.\n'));
    console.log(theme.dim('  Scanning dependencies for vulnerabilities...\n'));
  }
  
  let spinner: ReturnType<typeof ora> | null = null;
  
  if (!options.json) {
    spinner = ora({
      text: 'Finding dependency files...',
      color: 'cyan',
    }).start();
  }
  
  const files = await findDependencyFiles(scanPath, options.exclude);
  
  if (spinner) {
    spinner.succeed(`Found ${files.length} dependency file(s)`);
  }
  
  if (files.length === 0) {
    if (!options.json) {
      clack.outro(theme.dim('No dependency files found.'));
    }
    process.exit(0);
  }
  
  const reporter = new Reporter({
    json: options.json,
    severityFilter: options.severity,
    verbose: options.verbose,
    html: options.html,
  });
  
  if (!options.json && !options.html) {
    reporter.reportFiles(files);
  }
  
  if (!options.json && !options.html) {
    spinner = ora({
      text: 'Parsing dependencies...',
      color: 'cyan',
    }).start();
  }
  
  const dependencies = await parseDependencies(files);
  
  if (spinner) {
    spinner.succeed(`Parsed ${dependencies.length} package(s)`);
  }
  
  // Build dependency trees for graph visualization
  let allDependencies: Dependency[] = dependencies;
  let dependencyEdges: DependencyEdge[] = [];
  
  if (options.html) {
    if (!options.json) {
      spinner = ora({
        text: 'Building dependency trees...',
        color: 'cyan',
      }).start();
    }
    
    const npmFiles = files.filter(f => f.type === 'package.json');
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
    
    allDependencies = Array.from(allTreeNodes.values());
    
    if (spinner) {
      spinner.succeed(`Built dependency trees (${allDependencies.length} total packages, ${dependencyEdges.length} edges)`);
    }
  }
  
  if (dependencies.length === 0) {
    if (!options.json && !options.html) {
      clack.outro(theme.dim('No dependencies found.'));
    }
    process.exit(0);
  }
  
  if (!options.json && !options.html) {
    spinner = ora({
      text: 'Checking for vulnerabilities (OSV + GitHub)...',
      color: 'cyan',
    }).start();
  }
  
  const dataSources = [
    new OSVDataSource(),
    new GitHubDataSource(),
  ];
  
  const checker = new VulnerabilityChecker(dataSources);
  const result = await checker.checkDependencies(dependencies);
  
  if (spinner) {
    spinner.stop();
  }
  
  if (options.html) {
    if (!options.json) {
      spinner = ora({
        text: 'Detecting languages...',
        color: 'cyan',
      }).start();
    }
    
    const languageStats = await detectLanguages(scanPath, options.exclude);
    
    if (spinner) {
      spinner.succeed(`Detected ${languageStats.length} language(s)`);
      spinner = ora({
        text: 'Starting report server...',
        color: 'cyan',
      }).start();
    }
    
    const server = await reporter.generateHtmlReport(result, allDependencies, scanPath, options.repo, languageStats, dependencyEdges);
    
    if (spinner) {
      spinner.succeed(`Report server started at ${server.url}`);
    }
    
    if (!options.json) {
      console.log(theme.info(`\n📄 Opening report in browser...\n`));
    }
    
    await open(server.url);
    
    if (!options.json) {
      console.log(theme.success(`${icons.success} Report opened in browser!`));
      console.log(theme.dim(`\nServer running at ${server.url}`));
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
    reporter.reportResults(result);
    
    if (!options.json) {
      if (result.summary.total === 0) {
        clack.outro(theme.success(`${icons.success} All clear! No vulnerabilities found.`));
      } else {
        clack.outro(theme.dim('Scan complete.'));
      }
    }
  }
  
  if (cleanup) {
    await cleanup();
  }
  
  if (options.failOn && shouldFailOnSeverity(result.summary, options.failOn)) {
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
