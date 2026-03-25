import * as clack from '@clack/prompts';
import { Command } from 'commander';
import { resolve } from 'node:path';
import { cwd } from 'node:process';
import ora from 'ora';

import { GitHubDataSource, OSVDataSource } from './auditor/datasources/index.js';
import { VulnerabilityChecker } from './auditor/vulnerability-checker.js';
import { parseDependencies } from './scanner/dependency-parser.js';
import { findDependencyFiles } from './scanner/file-finder.js';
import { Reporter } from './ui/reporter.js';
import { icons, theme } from './ui/theme.js';
import { shouldFailOnSeverity } from './utils/config.js';
import { Logger } from './utils/logger.js';

const program = new Command();

program
  .name('who-touched-my-deps')
  .description('A beautiful CLI tool for auditing dependencies and finding vulnerabilities')
  .version('0.1.0')
  .option('-p, --path <directory>', 'Path to scan (default: current directory)', '.')
  .option('-e, --exclude <patterns...>', 'Patterns to exclude from scanning', [])
  .option('-s, --severity <level>', 'Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW)')
  .option('-f, --fail-on <level>', 'Exit with error code if vulnerabilities at or above this severity are found')
  .option('-j, --json', 'Output results as JSON', false)
  .option('-v, --verbose', 'Verbose output', false)
  .parse();

const options = program.opts();

async function main() {
  const logger = new Logger(options.verbose);
  const scanPath = resolve(cwd(), options.path);
  
  if (!options.json) {
    clack.intro(theme.bold(`${icons.shield} Who Touched My Deps?`));
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
  });
  
  if (!options.json) {
    reporter.reportFiles(files);
  }
  
  if (!options.json) {
    spinner = ora({
      text: 'Parsing dependencies...',
      color: 'cyan',
    }).start();
  }
  
  const dependencies = await parseDependencies(files);
  
  if (spinner) {
    spinner.succeed(`Parsed ${dependencies.length} package(s)`);
  }
  
  if (dependencies.length === 0) {
    if (!options.json) {
      clack.outro(theme.dim('No dependencies found.'));
    }
    process.exit(0);
  }
  
  if (!options.json) {
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
  
  reporter.reportResults(result);
  
  if (!options.json) {
    if (result.summary.total === 0) {
      clack.outro(theme.success(`${icons.success} All clear! No vulnerabilities found.`));
    } else {
      clack.outro(theme.dim('Scan complete.'));
    }
  }
  
  if (options.failOn && shouldFailOnSeverity(result.summary, options.failOn)) {
    process.exit(1);
  }
  
  process.exit(0);
}

main().catch((error) => {
  if (!options.json) {
    clack.outro(theme.critical(`Error: ${error.message}`));
  } else {
    console.error(JSON.stringify({ error: error.message }));
  }
  process.exit(2);
});
