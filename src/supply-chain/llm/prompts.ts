import type { PackageMetadata, PackageSource, SupplyChainFinding } from '../types.js';
import type { TriageResult } from './tools.js';

/**
 * System prompt for the tool-calling agent that investigates a package.
 * The agent has tools: triage_scan, list_files, read_file, grep_package, report_findings.
 */
export function buildAgentSystemPrompt(): string {
  return `You are an expert supply chain security analyst. You are investigating a package for signs of supply chain poisoning.

You have tools to explore the package source code:
- triage_scan: Automated scan of ALL files against threat indicator patterns — returns prioritized list of suspicious files
- list_files: List all files in the package, optionally filtered by pattern
- read_file: Read a specific file's contents
- grep_package: Search for regex patterns across files (with context lines)
- report_findings: Submit findings incrementally as you discover them

## Investigation Procedure

1. **ALWAYS start with triage_scan** — this scans ALL files and returns a ranked list. Files are scored by threat indicators with compound scoring (files matching MULTIPLE threat categories score much higher).
2. **Work through the triage results systematically from highest score to lowest.** For each high-scoring file:
   a. Read the FULL file with read_file
   b. Determine if the flagged behavior is malicious or legitimate
   c. If malicious, immediately call report_findings with the finding(s)
   d. Move to the next file — do NOT stop early
3. **SKIP low-value files** — test files (.spec.ts, .test.js, __tests__/), type definitions (.d.ts), mocks, and fixtures almost never contain real threats. The triage already de-prioritizes these. Focus your rounds on configs, scripts, build tools, and entry points.
4. **After processing all triage results**, use grep_package for any threat patterns you want to double-check across the full codebase.
5. **When done**, call report_findings with an empty array to signal completion.

## Efficiency Rules
- Do NOT waste rounds reading files that are obviously benign (test specs, type definitions, documentation)
- Report findings in BATCHES — after reading each suspicious file, report all findings from that file in one call
- You have limited investigation rounds — prioritize high-scoring triage files
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

## Important Rules
- Be precise. Only flag patterns you find in the actual code.
- Quote EXACT code as evidence — include the file path and the specific malicious lines.
- Distinguish LEGITIMATE uses from MALICIOUS intent. Context matters:
  - A test helper reading env vars for test configuration = LEGITIMATE
  - A build tool sending ALL env vars to an external server = MALICIOUS
  - A crypto module decrypting data for business logic = LEGITIMATE
  - A crypto module sending decrypted plaintext to an external endpoint = MALICIOUS
- Do NOT hallucinate findings.
- **Be thorough**: investigate ALL high-scoring files from the triage scan. Each file may contain a DIFFERENT attack vector. Do not assume that once you've found a few threats, you've found them all.
- **NEVER stop early**: Do not write a summary or conclude until you have read and analyzed EVERY file with a triage score above 10. Sophisticated attacks plant 10+ backdoors — finding 5 does not mean you are done.`;
}

/**
 * Build the initial user message with package metadata to kick off investigation.
 */
export function buildInvestigationKickoff(
  meta: PackageMetadata,
  source: PackageSource
): string {
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
**Total files:** ${source.fileList.length}

Start by running triage_scan to identify the most suspicious files, then investigate each one.

CRITICAL: You MUST work through ALL files in the triage results that have a score above 10. Do NOT stop after finding a few issues — real supply chain attacks plant MANY backdoors across different files. Each file may contain a completely different attack vector. Keep reading and reporting until you have investigated every significant triage result.`;
}

/**
 * Build a prompt for analyzing a single file that was flagged by triage.
 * The LLM receives the file content + triage indicators and must determine if it's malicious.
 */
export function buildFileAnalysisPrompt(
  meta: PackageMetadata,
  triage: TriageResult,
  fileContent: string
): string {
  const indicatorList = [...triage.indicators.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => `${name} (${count} matches)`)
    .join(', ');
  const catList = [...triage.categories].join(', ');

  return `Analyze this file from package "${meta.name}" for supply chain threats.

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
