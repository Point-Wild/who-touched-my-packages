/**
 * Benchmark: cache enabled vs disabled, concurrency 1 vs 8.
 *
 * Runs each ecosystem's test repo through a full scan under four configurations
 * and prints a comparison table at the end. JSON reports are saved to tests/benchmarks/
 * for inspection.
 *
 * Usage:
 *   bun tests/benchmark-cache.test.ts            # all ecosystems
 *   bun tests/benchmark-cache.test.ts npm         # single ecosystem
 *   bun tests/benchmark-cache.test.ts npm python   # multiple ecosystems
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const BENCHMARKS_DIR = join(import.meta.dir, 'benchmarks');
mkdirSync(BENCHMARKS_DIR, { recursive: true });

const ECOSYSTEMS: Record<string, string> = {
  npm: 'https://github.com/appsecco/dvna',
  python: 'https://github.com/anxolerd/dvpwa',
  rust: 'https://github.com/snyk/rust-vulnerable-apps',
  go: 'https://github.com/sonatype-nexus-community/intentionally-vulnerable-golang-project',
  ruby: 'https://github.com/OWASP/railsgoat',
};

interface ScanStats {
  totalDependencies: number;
  totalVulnerabilities: number;
  scannedPackages: number;
  filesScanned: number;
}

interface BenchmarkResult {
  ecosystem: string;
  cache: boolean;
  concurrency: number;
  durationMs: number;
  peakMemoryMb: number;
  exitCode: number | null;
  stats: ScanStats;
  reportFile: string;
}

/**
 * Parse peak resident memory from `/usr/bin/time -l` stderr output (macOS).
 * The line looks like: "  12345678  maximum resident set size" (bytes on macOS).
 * On Linux (`/usr/bin/time -v`) it's: "Maximum resident set size (kbytes): 12345".
 */
function parsePeakMemoryMb(stderr: string): number {
  // macOS: value in bytes
  const macMatch = stderr.match(/(\d+)\s+maximum resident set size/);
  if (macMatch) return Math.round(parseInt(macMatch[1], 10) / 1024 / 1024);

  // Linux: value in kbytes
  const linuxMatch = stderr.match(/Maximum resident set size \(kbytes\):\s*(\d+)/);
  if (linuxMatch) return Math.round(parseInt(linuxMatch[1], 10) / 1024);

  return 0;
}

function readStatsFromReport(reportPath: string): ScanStats {
  const stats: ScanStats = {
    totalDependencies: 0,
    totalVulnerabilities: 0,
    scannedPackages: 0,
    filesScanned: 0,
  };

  try {
    if (!existsSync(reportPath)) return stats;
    const report = JSON.parse(readFileSync(reportPath, 'utf-8'));

    stats.totalDependencies = report?.reportData?.dependencies?.length ?? 0;
    stats.totalVulnerabilities = report?.vulnerabilities?.length ?? 0;
    stats.scannedPackages = report?.reportData?.auditResult?.scannedPackages ?? 0;
    stats.filesScanned = report?.reportData?.scannedFiles?.length ?? 0;
  } catch {
    // parse failed — return zeroes
  }

  return stats;
}

function runScan(ecosystem: string, repo: string, cache: boolean, concurrency: number): {
  durationMs: number;
  peakMemoryMb: number;
  exitCode: number | null;
  stats: ScanStats;
  reportFile: string;
} {
  const reportFile = join(
    BENCHMARKS_DIR,
    `benchmark_${ecosystem}_cache-${cache ? 'on' : 'off'}_conc-${concurrency}.json`,
  );

  const bunArgs = [
    'src/index.ts',
    '--repo', repo,
    '--no-html',
    '--json',
    '--output', reportFile,
    '--concurrency', String(concurrency),
  ];
  if (!cache) {
    bunArgs.push('--no-cache');
  }

  // Wrap with /usr/bin/time to capture peak memory of the child process.
  // macOS: /usr/bin/time -l  (reports bytes)
  // Linux: /usr/bin/time -v  (reports kbytes)
  const isMac = process.platform === 'darwin';
  const timeFlag = isMac ? '-l' : '-v';
  const command = '/usr/bin/time';
  const args = [timeFlag, 'bun', ...bunArgs];

  const start = performance.now();

  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 60 * 60 * 1000, // 1 hour timeout per run
    env: { ...process.env },
  });

  const durationMs = Math.round(performance.now() - start);
  const stderr = result.stderr?.toString() ?? '';
  const peakMemoryMb = parsePeakMemoryMb(stderr);
  const stats = readStatsFromReport(reportFile);

  return { durationMs, peakMemoryMb, exitCode: result.status, stats, reportFile };
}

// Parse CLI args to filter ecosystems
const requestedEcosystems = process.argv.slice(2).filter(a => !a.startsWith('-'));
const ecosystemsToRun = requestedEcosystems.length > 0
  ? Object.fromEntries(
      Object.entries(ECOSYSTEMS).filter(([key]) => requestedEcosystems.includes(key))
    )
  : ECOSYSTEMS;

if (Object.keys(ecosystemsToRun).length === 0) {
  console.error(`No matching ecosystems. Available: ${Object.keys(ECOSYSTEMS).join(', ')}`);
  process.exit(1);
}

const configurations = [
  { cache: true,  concurrency: 1, label: 'cache=ON  concurrency=1' },
  { cache: false, concurrency: 1, label: 'cache=OFF concurrency=1' },
];

const results: BenchmarkResult[] = [];

console.log('='.repeat(70));
console.log('  Registry Cache Benchmark');
console.log('='.repeat(70));
console.log(`  Ecosystems: ${Object.keys(ecosystemsToRun).join(', ')}`);
console.log(`  Configurations: ${configurations.length} per ecosystem`);
console.log(`  Total runs: ${Object.keys(ecosystemsToRun).length * configurations.length}`);
console.log(`  Reports: ${BENCHMARKS_DIR}`);
console.log('='.repeat(70));
console.log();

for (const [ecosystem, repo] of Object.entries(ecosystemsToRun)) {
  console.log(`\n--- ${ecosystem.toUpperCase()} (${repo}) ---\n`);

  for (const config of configurations) {
    process.stdout.write(`  ${config.label} ... `);
    const { durationMs, peakMemoryMb, exitCode, stats, reportFile } = runScan(ecosystem, repo, config.cache, config.concurrency);
    const status = exitCode === 0 || exitCode === 1 ? '✓' : `✗ (exit ${exitCode})`;
    const memStr = peakMemoryMb > 0 ? `${peakMemoryMb}MB` : 'n/a';
    console.log(`${(durationMs / 1000).toFixed(1)}s  ${memStr}  ${stats.totalDependencies} deps  ${stats.totalVulnerabilities} vulns  ${status}`);

    results.push({
      ecosystem,
      cache: config.cache,
      concurrency: config.concurrency,
      durationMs,
      peakMemoryMb,
      exitCode,
      stats,
      reportFile,
    });
  }
}

// Print summary table
console.log('\n');
console.log('='.repeat(90));
console.log('  RESULTS SUMMARY');
console.log('='.repeat(90));

const header = [
  'Ecosystem'.padEnd(10),
  'Cache'.padEnd(6),
  'Conc'.padEnd(5),
  'Time'.padStart(8),
  'Memory'.padStart(8),
  'Deps'.padStart(6),
  'Vulns'.padStart(6),
].join(' | ');

console.log(header);
console.log('-'.repeat(header.length));

for (const ecosystem of Object.keys(ecosystemsToRun)) {
  const ecosystemResults = results.filter(r => r.ecosystem === ecosystem);

  for (const r of ecosystemResults) {
    const memStr = r.peakMemoryMb > 0 ? `${r.peakMemoryMb}MB` : 'n/a';
    console.log([
      r.ecosystem.padEnd(10),
      (r.cache ? 'ON' : 'OFF').padEnd(6),
      String(r.concurrency).padEnd(5),
      `${(r.durationMs / 1000).toFixed(1)}s`.padStart(8),
      memStr.padStart(8),
      String(r.stats.totalDependencies).padStart(6),
      String(r.stats.totalVulnerabilities).padStart(6),
    ].join(' | '));
  }
  console.log('-'.repeat(header.length));
}

console.log(`\n  JSON reports saved to: ${BENCHMARKS_DIR}`);
console.log('\nDone.');
