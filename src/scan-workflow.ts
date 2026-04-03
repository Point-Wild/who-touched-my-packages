import { applyVerificationResults, verifyPackages } from './auditor/package-verifier.js';
import { OSVDataSource } from './auditor/datasources/index.js';
import { VulnerabilityChecker } from './auditor/vulnerability-checker.js';
import { parseDependencies } from './scanner/dependency-parser.js';
import { buildDependencyTree, flattenDependencyTree } from './scanner/dependency-tree-resolver.js';
import { findDependencyFiles } from './scanner/file-finder.js';
import { detectLanguages } from './scanner/language-detector.js';
import type { Dependency, DependencyEdge, UnresolvedDependency } from './scanner/types.js';
import type { ReportData } from './ui/html-report/types.js';
import { theme } from './ui/theme.js';

export interface ScanWorkflowOptions {
  exclude: string[];
  maxDepth: string;
  supplyChain: boolean;
  packageDepth: string;
  html: boolean;
  json: boolean;
  quiet: boolean;
  verbose: boolean;
  repo?: string;
}

export async function scanWorkflow(
  scanPath: string,
  scanOptions: ScanWorkflowOptions,
  spinner: { text: string } | null
): Promise<ReportData> {
  const logVerbose = (message: string): void => {
    if (scanOptions.verbose) {
      console.log(`[scanWorkflow] ${message}`);
    }
  };

  const logVerboseJson = (label: string, value: unknown): void => {
    if (scanOptions.verbose) {
      console.log(`[scanWorkflow] ${label}:`);
      console.log(JSON.stringify(value, null, 2).split('\n').map(line => `  ${line}`).join('\n'));
    }
  };

  logVerbose(`Starting scan for path: ${scanPath}`);
  logVerboseJson('Options', scanOptions);
  const packageDepth = parseInt(scanOptions.packageDepth ?? '1', 10);
  logVerbose(`Resolved package depth: ${packageDepth}`);
  const files = await findDependencyFiles(scanPath, scanOptions.exclude, parseInt(scanOptions.maxDepth, 10) || 0);
  logVerbose(`Dependency files found: ${files.length}`);
  if (files.length > 0) {
    logVerboseJson('Dependency files', files);
  }

  if (spinner) {
    spinner.text = 'Parsing dependencies...';
  }

  if (files.length === 0) {
    throw new Error('No dependency files found.');
  }

  const scannedDependencies = await parseDependencies(files);
  logVerbose(`Direct dependencies parsed: ${scannedDependencies.length}`);
  if (scannedDependencies.length > 0) {
    logVerboseJson(
      'Scanned dependencies',
      scannedDependencies.map(dep => ({
        ecosystem: dep.ecosystem,
        name: dep.name,
        version: dep.version,
        file: dep.file,
        depth: dep.depth,
      }))
    );
  }

  if (spinner) {
    spinner.text = 'Checking for vulnerabilities...';
  }

  let allDependencies: Dependency[] = scannedDependencies;
  let dependencyEdges: DependencyEdge[] = [];
  let unresolvedDependencies: UnresolvedDependency[] = [];

  const needsTree = scanOptions.html || (scanOptions.supplyChain && packageDepth > 1);
  logVerbose(`Dependency tree expansion needed: ${needsTree}`);

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
        logVerbose(`Resolved npm tree for ${file.path}: ${flatDeps.length} dependencies, ${tree.edges.length} edges, ${tree.unresolved.length} unresolved`);

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
        logVerbose(`Failed to build npm tree for ${file.path}: ${error instanceof Error ? error.message : String(error)}`);
        // Skip files that fail to parse
      }
    }

    for (const file of pythonFiles) {
      const pythonDeps = scannedDependencies.filter(d => d.file === file.path && d.ecosystem === 'pypi');
      logVerbose(`Using direct Python dependencies for ${file.path}: ${pythonDeps.length}`);
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
        logVerbose(`Resolved cargo tree for ${file.path}: ${flatDeps.length} dependencies, ${tree.edges.length} edges, ${tree.unresolved.length} unresolved`);

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
        logVerbose(`Failed to build cargo tree for ${file.path}: ${error instanceof Error ? error.message : String(error)}`);
        // Skip files that fail to parse
      }
    }

    for (const file of goFiles) {
      try {
        const tree = await buildDependencyTree(file.path, 'go');
        const flatDeps = flattenDependencyTree(tree);
        logVerbose(`Resolved go tree for ${file.path}: ${flatDeps.length} dependencies, ${tree.edges.length} edges, ${tree.unresolved.length} unresolved`);

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
        logVerbose(`Failed to build go tree for ${file.path}: ${error instanceof Error ? error.message : String(error)}`);
        // Skip files that fail to parse
      }
    }

    for (const file of rubyFiles) {
      try {
        const tree = await buildDependencyTree(file.path, 'ruby');
        const flatDeps = flattenDependencyTree(tree);
        logVerbose(`Resolved ruby tree for ${file.path}: ${flatDeps.length} dependencies, ${tree.edges.length} edges, ${tree.unresolved.length} unresolved`);

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
        logVerbose(`Failed to build ruby tree for ${file.path}: ${error instanceof Error ? error.message : String(error)}`);
        // Skip files that fail to parse
      }
    }

    allDependencies = Array.from(allTreeNodes.values());
    logVerbose(`Expanded dependency set size before package-depth filter: ${allDependencies.length}`);

    if (scanOptions.supplyChain && packageDepth > 1) {
      allDependencies = allDependencies.filter(d => (d.depth ?? 0) < packageDepth);
      logVerbose(`Expanded dependency set size after package-depth filter: ${allDependencies.length}`);
    }

    logVerbose(`Dependency edges collected: ${dependencyEdges.length}`);
    logVerbose(`Unresolved dependencies collected: ${unresolvedDependencies.length}`);
  }

  if (spinner) {
    spinner.text = 'Verifying package provenance...';
  }

  try {
    const verificationResults = await verifyPackages(allDependencies);
    logVerbose(`Package provenance results received: ${verificationResults.length}`);
    applyVerificationResults(allDependencies, verificationResults);
    if (allDependencies !== scannedDependencies) {
      applyVerificationResults(scannedDependencies, verificationResults);
    }
  } catch {
    if (scanOptions.verbose) {
      console.log(theme.dim('Warning: Package provenance verification failed'));
    }
  }

  if (allDependencies.length === 0) {
    throw new Error('No dependencies found.');
  }

  const checker = new VulnerabilityChecker([
    new OSVDataSource(),
  ]);

  const auditResult = await checker.checkDependencies(allDependencies);
  logVerbose(`Vulnerability results: ${auditResult.vulnerabilities.length} findings across ${auditResult.scannedPackages} scanned packages`);
  if (auditResult.vulnerabilities.length > 0) {
    logVerboseJson(
      'Vulnerabilities',
      auditResult.vulnerabilities.map(v => ({
        ecosystem: v.ecosystem,
        packageName: v.packageName,
        packageVersion: v.packageVersion,
        severity: v.severity,
        id: v.id,
        source: v.source,
      }))
    );
  }
  const languageStats = scanOptions.html
    ? await detectLanguages(scanPath, scanOptions.exclude)
    : undefined;
  if (languageStats) {
    logVerboseJson('Language stats', languageStats);
  }

  logVerbose(
    `Completed scanWorkflow with ${allDependencies.length} total dependencies and ${scannedDependencies.length} directly scanned dependencies`
  );

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
