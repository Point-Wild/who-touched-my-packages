import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import open from 'open';
import { parseTestLLMOptions } from './test-llm-options.js';
import { scanWorkflow, type ScanWorkflowOptions } from './src/scan-workflow.js';
import { buildFinalReport, displayAggregatedReport } from './src/ui/aggregated-report.js';
import { analyzeSupplyChain } from './src/supply-chain/index.js';
import { Reporter } from './src/ui/reporter.js';
import type { Dependency } from './src/scanner/types.js';

const llmOptions = parseTestLLMOptions('test-python-final-report.ts');

const TARGET = {
  label: 'litellm 1.82.8 final merged report',
  version: '1.82.8',
  url: 'https://files.pythonhosted.org/packages/f6/2c/731b614e6cee0bca1e010a36fd381fba69ee836fe3cb6753ba23ef2b9601/litellm-1.82.8.tar.gz',
};

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function logSection(title: string): void {
  console.log('\n' + '═'.repeat(80));
  console.log(title);
  console.log('═'.repeat(80));
}

function logStep(message: string): void {
  console.log(`  • ${message}`);
}

function logKeyValue(label: string, value: unknown): void {
  console.log(`  ${label}: ${String(value)}`);
}

function logJson(label: string, value: unknown): void {
  console.log(`  ${label}:`);
  console.log(JSON.stringify(value, null, 2).split('\n').map(line => `    ${line}`).join('\n'));
}

function buildDependency(): Dependency {
  return {
    name: 'litellm',
    version: TARGET.version,
    versionSpec: `==${TARGET.version}`,
    ecosystem: 'pypi',
    file: '/virtual/requirements.txt',
    depth: 0,
    paths: [['litellm']],
  };
}

function installPypiFetchMock() {
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;

    if (url === 'https://pypi.org/pypi/litellm/json') {
      return jsonResponse({
        info: {
          version: TARGET.version,
          author: 'BerriAI',
          maintainer: 'BerriAI',
          summary: 'Call all LLM APIs using the OpenAI format',
          home_page: 'https://github.com/BerriAI/litellm',
          project_urls: {
            Source: 'https://github.com/BerriAI/litellm',
          },
          license: 'MIT',
        },
        releases: {
          [TARGET.version]: [
            {
              upload_time_iso_8601: '2026-03-24T00:00:00Z',
              provenance_url: null,
              metadata_version: '2.1',
              filename: `litellm-${TARGET.version}.tar.gz`,
            },
          ],
        },
      });
    }

    if (url === 'https://pypi.org/pypi/litellm/1.82.8/json') {
      return jsonResponse({
        urls: [
          {
            packagetype: 'sdist',
            filename: `litellm-${TARGET.version}.tar.gz`,
            url: TARGET.url,
          },
        ],
      });
    }

    if (url === 'https://pypistats.org/api/packages/litellm/recent') {
      return jsonResponse({
        data: {
          last_week: 2_000_000,
        },
      });
    }

    return originalFetch(input as any, init);
  };

  return () => {
    globalThis.fetch = originalFetch;
  };
}

async function buildSupplyChainReportFromTarball() {
  logSection(`Supply Chain Analysis: ${TARGET.label}`);
  logStep('Preparing mocked PyPI endpoints for analyzeSupplyChain.');
  logKeyValue('Target version', TARGET.version);
  logKeyValue('Tarball URL', TARGET.url);
  logKeyValue('LLM provider', llmOptions.provider);
  logKeyValue('LLM model', llmOptions.model);

  const restoreFetch = installPypiFetchMock();
  try {
    logStep('Calling analyzeSupplyChain with the same production entry point used by the CLI.');
    const report = await analyzeSupplyChain([buildDependency()], {
      apiKey: llmOptions.apiKey,
      model: llmOptions.model,
      provider: llmOptions.provider,
      verbose: true,
      maxPackages: 1,
    });

    logStep('Supply chain analysis completed.');
    logJson('Raw report', report);
    logKeyValue('Findings', report.findings.length);
    logJson('Summary', report.summary);
    logKeyValue('Fetch errors', report.fetchErrors.length);
    if (report.findings.length > 0) {
      console.log('\n  Supply chain findings:');
      for (const finding of report.findings) {
        console.log(
          `  - ${finding.packageName}@${finding.packageVersion} [${finding.ecosystem}] ${finding.severity} ${finding.category}: ${finding.title}`
        );
        console.log(`    confidence=${Math.round(finding.confidence * 100)}`);
      }
    }

    assert(report.findings.length > 0, 'Expected supply chain findings from analyzeSupplyChain');
    return report;
  } finally {
    logStep('Restoring original fetch implementation.');
    restoreFetch();
  }
}

async function buildStaticReportFromRequirements() {
  logSection('Static Scan Workflow');
  const scanDir = await mkdtemp(join(tmpdir(), 'wtmp-litellm-'));
  const requirementsPath = join(scanDir, 'requirements.txt');
  await writeFile(requirementsPath, 'litellm==1.82.8\n', 'utf8');
  logStep('Created temporary Python project fixture.');
  logKeyValue('Scan directory', scanDir);
  logKeyValue('Requirements file', requirementsPath);

  const scanOptions: ScanWorkflowOptions = {
    exclude: [],
    maxDepth: '0',
    supplyChain: true,
    packageDepth: '5',
    html: true,
    json: false,
    quiet: false,
    verbose: true,
  };

  logStep('Running scanWorkflow on requirements.txt.');
  logJson('scanOptions', scanOptions);
  logKeyValue('packageDepth', scanOptions.packageDepth);
  logKeyValue('maxDepth', scanOptions.maxDepth);
  const reportData = await scanWorkflow(scanDir, scanOptions, null);
  logStep('Static scan completed.');
  logJson('Raw report', reportData);
  logKeyValue('Dependencies discovered', reportData.dependencies.length);
  logKeyValue('Files scanned', reportData.files.length);
  logKeyValue('Vulnerabilities', reportData.auditResult.vulnerabilities.length);
  if (reportData.auditResult.vulnerabilities.length > 0) {
    console.log('\n  Static findings:');
    for (const vuln of reportData.auditResult.vulnerabilities) {
      console.log(
        `  - ${vuln.packageName}@${vuln.packageVersion} [${vuln.ecosystem}] ${vuln.severity} ${vuln.id} source=${vuln.source}`
      );
    }
  }
  assert(
    reportData.auditResult.vulnerabilities.some(v => v.packageName === 'litellm' && v.packageVersion === '1.82.8'),
    'Expected static scan workflow to report litellm@1.82.8'
  );

  return reportData;
}

logSection('Final Report E2E Test');
logStep('Starting end-to-end flow for merged static and supply chain reporting.');
const reportData = await buildStaticReportFromRequirements();
const supplyChainReport = await buildSupplyChainReportFromTarball();

logSection('Build Final Report');
logStep('Merging static report data with supply chain report.');
const finalReport = buildFinalReport(reportData, supplyChainReport);
logKeyValue('Aggregated packages', finalReport.aggregatedReport.aggregatedSummary.totalPackages);
logKeyValue(
  'Packages with static findings',
  finalReport.aggregatedReport.aggregatedSummary.packagesWithStaticFindings
);
logKeyValue(
  'Packages with supply chain findings',
  finalReport.aggregatedReport.aggregatedSummary.packagesWithSupplyChainFindings
);
logKeyValue('Critical packages', finalReport.aggregatedReport.aggregatedSummary.critical);
logKeyValue('High packages', finalReport.aggregatedReport.aggregatedSummary.high);
logKeyValue('Medium packages', finalReport.aggregatedReport.aggregatedSummary.medium);
logKeyValue('Low packages', finalReport.aggregatedReport.aggregatedSummary.low);
logKeyValue('Unknown packages', finalReport.aggregatedReport.aggregatedSummary.unknown);

logStep('Running validation checks.');
assert(finalReport.reportData.auditResult.vulnerabilities.length > 0, 'Expected static findings in final report');
assert(finalReport.supplyChainReport?.findings.length, 'Expected supply chain findings in final report');

const litellmFinding = finalReport.aggregatedReport.aggregatedFindings.find(
  finding => finding.packageName === 'litellm' && finding.packageVersion === '1.82.8'
);
assert(litellmFinding, 'Expected aggregated report to contain litellm@1.82.8');
assert(litellmFinding.staticFindings.length > 0, 'Expected aggregated litellm finding to include static findings');
assert(litellmFinding.supplyChainFindings.length > 0, 'Expected aggregated litellm finding to include supply chain findings');
logStep('Validation checks passed.');

logSection('Aggregated Report');
displayAggregatedReport(finalReport);

logSection('HTML Report');
logStep('Generating HTML report server.');
const reporter = new Reporter({ html: true, verbose: true });
const server = await reporter.generateHtmlReport(finalReport);

logStep('Opening HTML report in browser.');
await open(server.url);

console.log(`\n📄 Report opened in browser: ${server.url}`);
console.log('Server running. Press Ctrl+C to stop.\n');

process.on('SIGINT', () => {
  server.close();
  process.exit(0);
});

await new Promise(() => {});
