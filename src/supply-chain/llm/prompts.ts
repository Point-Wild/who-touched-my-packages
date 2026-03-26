import type { PackageMetadata, PackageSource, SupplyChainFinding } from '../types.js';
import type { TriageResult } from './tools.js';

/**
 * System prompt for the tool-calling agent that investigates a package.
 * The agent has tools: triage_scan, list_files, read_file, grep_package, report_findings.
 */
export function buildAgentSystemPrompt(): string {
  return `You are an expert supply chain security analyst. You are investigating a package for signs of supply chain poisoning.

You have tools to explore the package source code:
- list_files: List all files in the package, optionally filtered by pattern
- read_file: Read a specific file's contents
- grep_package: Search for regex patterns across files (with context lines)
- report_findings: Submit findings incrementally as you discover them

You are given a specific file that was flagged by an automated triage scan. The triage score, threat categories, and indicators are provided in the prompt.

## Investigation Procedure

1. **Analyze the flagged file** — it has already been scored against threat indicator patterns. The file content, triage score, and matched categories are provided to you.
2. **Determine if the flagged behavior is malicious or legitimate.**
3. **If you need more context**, use read_file or grep_package to examine related files.
4. **If malicious**, call report_findings with the finding(s).
5. **When done**, call report_findings with an empty array to signal completion.

## Efficiency Rules
- Do NOT waste rounds reading files that are obviously benign (test specs, type definitions, documentation)
- Report all findings from the file in one call
- You have limited investigation rounds — stay focused on the flagged file and closely related code
- If a file has indicators from multiple categories (e.g., network+creds+exec), it is MUCH more likely to be malicious

## What to Look For

### PRIMARY THREATS (CRITICAL/HIGH)

**Network Exfiltration**
- HTTP/HTTPS requests sending data to non-registry domains
- curl/wget/nc subprocesses sending data externally
- DNS-based exfiltration (dns.resolve with hex-encoded subdomains)
- Raw socket connections (net.createConnection, socket.connect) to external servers
- Known C2 domains, suspicious telemetry/metrics endpoints

**Credential Harvesting**
- File reads: ~/.ssh/id_rsa, ~/.aws/credentials, ~/.kube/config, ~/.docker/config.json, ~/.npmrc, /etc/shadow
- Cloud metadata endpoints: 169.254.169.254, metadata.google.internal
- Reading credential files and sending them externally

**Crypto Wallet Theft**
- Access to ~/.bitcoin/, ~/.ethereum/, ~/.solana/, wallet.dat, keystore files
- Browser extension wallet directories (MetaMask, Phantom, etc.)
- Seed phrase / mnemonic detection and exfiltration

**Remote Code Execution**
- new Function(data)() on remote data, eval() on received payloads
- Reverse shells (net.createConnection piped to child_process)
- Code received from external server and executed

### SECONDARY THREATS (MEDIUM/HIGH)

**Environment Scanning & Exfiltration**
- Bulk process.env / os.environ dumps sent externally
- Filtering env vars by pattern (TOKEN, KEY, SECRET, PASS, CRED) then exfiltrating
- Targeted reads of 30+ sensitive env var names

**CI/CD Poisoning**
- Writing to .github/workflows/, injecting malicious build steps
- Terraform state exfiltration, kubectl manipulation
- Jenkins credential theft from withCredentials blocks
- Docker build-time exfiltration of env vars or .npmrc

**Code Injection via Build Tools**
- Webpack BannerPlugin injecting runtime code that phones home
- Monkey-patching module.require to intercept imports (Module.prototype)
- Prepending/appending malicious code to built output files (main.js)
- String array .join('') to hide executable code in build configs

**Code Obfuscation**
- exec(base64.b64decode(...)), eval(atob(...)), eval(Buffer.from(...,'base64'))
- marshal.loads, pickle.loads with untrusted data
- Large base64/hex blobs (>200 chars) that decode to executable code
- Dynamic __import__ or require() with computed strings

**Persistence**
- Writing to ~/.bashrc/~/.zshrc/~/.profile, crontab modifications
- Creating systemd services, launchctl load, .pth injection

**Data Packaging**
- tar/zip archives + AES/RSA encryption or openssl enc before exfiltration
- Known campaign artifact names (tpcp.tar.gz, payload.enc)

**Dormancy / Time-bombs**
- Code that only activates after a specific date: \`new Date().getFullYear() > 2025\`, \`Date.now() > 1800000000000\`
- Large \`setTimeout\` or \`setInterval\` delays (>100 seconds) triggering malicious code
- OS-conditional execution: code that runs \`exec()\` only on Linux or only on Windows
- These are used to evade detection during initial review

**Trojan Source (CVE-2021-42574) / Unicode Tricks**
- Unicode bidirectional override characters (U+202A–U+202E, U+2066–U+2069) that make code appear different to human reviewers than to the compiler
- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+2060) used to hide content in strings or identifiers
- These are EXTREMELY suspicious in package source code — there is almost no legitimate reason for them

**Multi-stage Loaders**
- \`eval(response)\`, \`eval(data)\`, \`eval(body)\` — executing remotely fetched content
- Writing content received from a network call to disk, then immediately \`exec()\`-ing or \`require()\`-ing it
- This pattern fetches the actual malicious payload at runtime to evade static analysis

## Important Rules
- Be precise. Only flag patterns you find in the actual code.
- Quote EXACT code as evidence — include the file path and the specific malicious lines.
- Distinguish LEGITIMATE uses from MALICIOUS intent. Context matters:
  - A test helper reading env vars for test configuration = LEGITIMATE
  - A build tool sending ALL env vars to an external server = MALICIOUS
  - A crypto module decrypting data for business logic = LEGITIMATE
  - A crypto module sending decrypted plaintext to an external endpoint = MALICIOUS
- Do NOT hallucinate findings.
- **Be thorough**: examine the full file content and any related code before concluding.`;
}

/**
 * Build the initial user message with package metadata to kick off investigation.
 */
export function buildInvestigationKickoff(
  meta: PackageMetadata,
  source: PackageSource
): string {
  const signals = meta.registrySignals;
  const signalsBlock = signals
    ? `\n**Registry Risk Score:** ${signals.riskScore}/10${signals.riskScore >= 5 ? ' \u26a0\ufe0f HIGH' : ''}
**Maintainer change in latest release:** ${signals.maintainerChangedInLatestRelease ? `YES \u2014 replaced: ${signals.previousMaintainers.join(', ')} \u2192 ${signals.newMaintainers.join(', ')}` : 'no'}
**Package age:** ${signals.packageAgeDays} days
**Published days ago:** ${signals.publishedDaysAgo}
**Typosquat candidate:** ${signals.typosquatCandidate ?? 'none'}${signals.typosquatCandidate ? ' \u26a0\ufe0f' : ''}
**Dependency confusion risk:** ${signals.isDependencyConfusion ? 'YES \u26a0\ufe0f' : 'no'}
**Has sigstore/Trusted Publisher provenance:** ${signals.hasProvenance ? 'yes' : 'NO'}` : '';

  return `Investigate this ${meta.ecosystem} package for supply chain threats:

**Package:** ${meta.name}@${source.version}
**Description:** ${meta.description ?? '(none)'}
**License:** ${meta.license ?? '(none)'}
**Weekly downloads:** ${meta.weeklyDownloads.toLocaleString()}
**Created:** ${meta.createdAt}
**Updated:** ${meta.updatedAt}
**Maintainers:** ${meta.maintainers.join(', ') || '(unknown)'}
**Repository:** ${meta.repositoryUrl ?? '(none)'}
**Has install scripts:** ${meta.hasInstallScripts}
**Total files:** ${source.fileList.length}${signalsBlock}

Analyze the flagged file provided below. Use read_file or grep_package if you need additional context from the package.`;
}

/**
 * Build a prompt for analyzing a single file that was flagged by triage.
 * The LLM receives the file content + triage indicators and must determine if it's malicious.
 */
export function buildFileAnalysisPrompt(
  meta: PackageMetadata,
  triage: TriageResult,
  fileContent: string,
  source?: PackageSource
): string {
  const indicatorList = [...triage.indicators.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => `${name} (${count} matches)`)
    .join(', ');
  const catList = [...triage.categories].join(', ');

  // Warn if this file is new in the current version vs. the previous one
  const normalizedPath = triage.filePath.replace(/^package\//, '');
  const isNewFile = source?.newFilesInVersion?.includes(normalizedPath);
  const newFileWarning = isNewFile && source?.previousVersion
    ? `\n\u26a0\ufe0f  NEW FILE: This file did NOT exist in the previous version (${source.previousVersion}). Newly added files are prime injection vectors \u2014 weight your analysis accordingly.\n`
    : '';

  return `Analyze this file from package "${meta.name}" for supply chain threats.${newFileWarning}

**File:** ${triage.filePath}
**Triage score:** ${triage.score}
**Threat categories detected:** ${catList}
**Indicators:** ${indicatorList}

## File Content
\`\`\`
${truncate(fileContent, 12000)}
\`\`\`

Analyze this file carefully. Determine if the flagged indicators represent MALICIOUS behavior or LEGITIMATE code.

If you find malicious behavior, call report_findings immediately with your findings.
If you need more context, use grep_package or read_file to examine related files.
If the file is clean/legitimate, call report_findings with an empty array.

You MUST call report_findings exactly once for this file.`;
}

/**
 * Build a targeted follow-up prompt for deep investigation of a specific finding.
 */
export function buildDeepInvestigationPrompt(
  finding: SupplyChainFinding,
  source: PackageSource
): string {
  const allCode = [
    ...Object.entries(source.installScripts).map(([h, c]) => `=== Install script: ${h} ===\n${c}`),
    ...Object.entries(source.suspiciousFiles).map(([p, c]) => `=== ${p} ===\n${truncate(c, 4000)}`),
    source.entryPoint ? `=== Entry point ===\n${truncate(source.entryPoint, 6000)}` : '',
  ].filter(Boolean).join('\n\n');

  return `You are a senior supply chain security researcher performing a deep investigation.

A primary analysis flagged this finding for package "${finding.packageName}@${finding.packageVersion}" (${finding.ecosystem}):

## Original Finding
- Category: ${finding.category}
- Severity: ${finding.severity}
- Confidence: ${finding.confidence}
- Title: ${finding.title}
- Description: ${finding.description}
- Evidence: ${finding.evidence}

## Full Package Source Code
${allCode}

## File Listing
${source.fileList.slice(0, 200).join('\n')}

---

Your task:
1. CONFIRM or DOWNGRADE this finding based on the full source code context
2. Determine if the flagged behavior is MALICIOUS, SUSPICIOUS, or BENIGN
3. If confirmed, provide the exact attack chain and data at risk
4. Calibrate your confidence score carefully

Respond in JSON:
{
  "verdict": "CONFIRMED" | "DOWNGRADED" | "FALSE_POSITIVE",
  "adjustedSeverity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "adjustedConfidence": 0.0-1.0,
  "attackChain": "step by step description if confirmed",
  "dataAtRisk": "what is at risk if confirmed",
  "remediation": "specific steps to remediate",
  "reasoning": "detailed explanation of your conclusion"
}`;
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '\n... [truncated]';
}
