import { tool } from '@langchain/core/tools';
import { z } from 'zod';
import type { PackageSource } from '../types.js';

/**
 * Threat indicator patterns used by the triage_scan tool.
 * Each pattern is tested against every file; hits are accumulated per-file.
 *
 * Weights reflect how suspicious a match is in isolation:
 *   1 = common in legitimate code, needs context
 *   2 = moderately suspicious
 *   3 = highly suspicious on its own
 *   4 = almost always malicious
 */
const THREAT_INDICATORS: Array<{ name: string; pattern: RegExp; weight: number; category: string }> = [
  // ── Network Exfiltration ──────────────────────────────────
  { name: 'http-request-api', category: 'network', pattern: /https?\.request\s*\(\s*\{|https?\.get\s*\(|urllib\.request|requests\.(get|post|put)\s*\(/gi, weight: 2 },
  { name: 'http-post-data', category: 'network', pattern: /method:\s*['"]POST['"]|\.write\s*\(\s*(JSON\.stringify|payload|data|encoded|body)/gi, weight: 3 },
  { name: 'curl-wget-nc', category: 'network', pattern: /\bcurl\s|wget\s|netcat\s|\bnc\s+-[elzw]/gi, weight: 3 },
  { name: 'fetch-xhr', category: 'network', pattern: /\bfetch\s*\(|XMLHttpRequest|axios\.(get|post)\(/gi, weight: 1 },
  { name: 'socket-connect', category: 'network', pattern: /net\.createConnection|net\.connect\(|socket\.connect\(|new\s+WebSocket\(/gi, weight: 3 },
  { name: 'socket-import', category: 'network', pattern: /import\s+socket|require\s*\(\s*['"]net['"]\)|from\s+['"]net['"]/gi, weight: 2 },
  { name: 'dns-exfil', category: 'network', pattern: /dns\.resolve|dns\.lookup|\.resolveAny|\.resolveTxt/gi, weight: 3 },
  { name: 'external-url', category: 'network', pattern: /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|registry\.npmjs\.org|github\.com|gitlab\.com|npmjs\.com|pypi\.org|jfrog\.io|amazonaws\.com|docker\.io|docker\.com|googleapis\.com|cloudflare\.com|w3\.org|schema\.org|spdx\.org|creativecommons\.org|opensource\.org|example\.com|json-schema\.org|xml\.org|ietf\.org|swagger\.io|openapis\.org|microsoft\.com|apple\.com|google\.com|mozilla\.org)[a-z0-9][-a-z0-9.]*\.[a-z]{2,}/gi, weight: 0 },
  { name: 'known-c2', category: 'network', pattern: /models\.litellm\.cloud|checkmarx\.zone|pastebin\.com\/raw|transfer\.sh|ngrok\.io|requestbin|pipedream/gi, weight: 4 },
  { name: 'metadata-endpoint', category: 'network', pattern: /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/gi, weight: 4 },

  // ── Credential Harvesting ─────────────────────────────────
  { name: 'credential-files', category: 'creds', pattern: /\.ssh\/id_rsa|\.ssh\/id_ed25519|\.aws\/credentials|\.kube\/config|\.docker\/config\.json|\.npmrc|\.netrc|\.gnupg|\.pgpass/gi, weight: 4 },
  { name: 'system-files', category: 'creds', pattern: /\/etc\/shadow|\/etc\/passwd|\/etc\/hosts/gi, weight: 4 },
  { name: 'homedir-read', category: 'creds', pattern: /homedir\(\).*readFile|os\.homedir\(\).*readFile|expanduser.*open|Path\.home\(\)/gi, weight: 3 },

  // ── Crypto Wallet Theft ───────────────────────────────────
  { name: 'crypto-wallets', category: 'crypto', pattern: /\.bitcoin\/|\.ethereum\/|\.solana\/|wallet\.dat|keystore\/|\.electrum\/|\.monero\/|\.exodus\//gi, weight: 4 },
  { name: 'seed-mnemonic', category: 'crypto', pattern: /mnemonic|seed.?phrase|bip39|bip44|recovery.?phrase|secret.?recovery/gi, weight: 3 },
  { name: 'browser-wallets', category: 'crypto', pattern: /metamask|phantom|solflare|nkbihfbeogaeao|chrome.*extensions.*wallet/gi, weight: 4 },

  // ── Environment Scanning ──────────────────────────────────
  // Pattern-based: detect the BEHAVIOR of collecting/exfiltrating env vars
  { name: 'env-bulk-dump', category: 'env', pattern: /JSON\.stringify\([^)]*process\.env|JSON\.stringify\([^)]*os\.environ|JSON\.stringify\(\{[^}]*env:\s*process\.env/gi, weight: 4 },
  { name: 'env-iterate-all', category: 'env', pattern: /Object\.(keys|entries|values)\(\s*process\.env\s*\)|Object\.fromEntries\([^)]*process\.env|for\s*\(\s*\w+\s+in\s+process\.env\)|os\.environ\.items\(\)|os\.environ\.copy\(\)/gi, weight: 3 },
  { name: 'env-filter-pattern', category: 'env', pattern: /process\.env\)\.filter\(|Object\.\w+\(process\.env\)\.filter/gi, weight: 4 },
  { name: 'env-regex-secrets', category: 'env', pattern: /\/(TOKEN|KEY|SECRET|PASS|CRED).*\/[gimsuy]*\.test\s*\(/gi, weight: 4 },
  { name: 'env-spread-into-payload', category: 'env', pattern: /\.\.\.\s*process\.env|env:\s*process\.env|env:\s*\{[^}]*\.\.\.process\.env|"env"\s*:\s*process\.env/gi, weight: 4 },
  { name: 'env-reduce-collect', category: 'env', pattern: /\.reduce\([^)]*process\.env|Object\.assign\([^)]*process\.env/gi, weight: 3 },
  { name: 'env-printenv', category: 'env', pattern: /printenv|set\s*\|\s*grep|env\s*\|\s*grep|export\s+-p/gi, weight: 3 },
  // Specific high-value env var names (supplementary — catches targeted reads)
  { name: 'env-secrets-named', category: 'env', pattern: /AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|NPM_TOKEN|ARTIFACTORY_CREDS|OPENAI_API_KEY|STRIPE_SECRET_KEY|SLACK_TOKEN|DATABASE_URL|VAULT_TOKEN/gi, weight: 1 },

  // ── Code Obfuscation / Dynamic Execution ──────────────────
  { name: 'dynamic-exec', category: 'exec', pattern: /new\s+Function\s*\(|eval\s*\((?!uate)|exec\s*\([^)]*\.toString/gi, weight: 3 },
  { name: 'base64-decode-exec', category: 'exec', pattern: /Buffer\.from\([^)]+,\s*['"]base64['"]\)\s*\.toString|atob\s*\(|base64\.b64decode|base64\.decode/gi, weight: 3 },
  { name: 'marshal-pickle', category: 'exec', pattern: /marshal\.loads|pickle\.loads|yaml\.load\([^)]*Loader/gi, weight: 3 },
  { name: 'dynamic-import', category: 'exec', pattern: /__import__\s*\(|importlib\.import_module|require\s*\(\s*[^'"]/gi, weight: 2 },
  { name: 'string-concat-hide', category: 'exec', pattern: /\.join\s*\(\s*['"]['"]?\s*\).*require|\.join\s*\(\s*['"]['"]?\s*\).*https?/gi, weight: 3 },
  { name: 'hex-base64-blob', category: 'exec', pattern: /[A-Za-z0-9+/=]{200,}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/gi, weight: 3 },
  { name: 'child-process', category: 'exec', pattern: /require\s*\(\s*['"]child_process['"]\)|child_process\.exec|execSync\s*\(|spawnSync\s*\(/gi, weight: 2 },

  // ── Build / Install Hooks ─────────────────────────────────
  { name: 'install-script', category: 'install', pattern: /["']?preinstall["']?\s*:|["']?postinstall["']?\s*:|["']?preuninstall["']?\s*:/gi, weight: 3 },
  { name: 'build-injection', category: 'install', pattern: /BannerPlugin|DefinePlugin.*process\.env|webpack.*plugin.*raw|prepend.*main\.js|\.to\s*\(.*main\.js/gi, weight: 3 },

  // ── CI/CD Poisoning ───────────────────────────────────────
  { name: 'ci-workflow-write', category: 'cicd', pattern: /writeFile.*\.github\/workflows|writeFile.*\.gitlab-ci|fs\.write.*workflow/gi, weight: 4 },
  { name: 'ci-tool-exec', category: 'cicd', pattern: /terraform\s+(show|apply|plan)|kubectl\s+(apply|exec|create)|helm\s+(install|upgrade)/gi, weight: 2 },
  { name: 'proc-docker-access', category: 'cicd', pattern: /\/proc\/\d+\/mem|\/var\/run\/docker\.sock|docker\.sock/gi, weight: 4 },

  // ── Persistence ───────────────────────────────────────────
  { name: 'shell-profile', category: 'persist', pattern: /\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile/gi, weight: 4 },
  { name: 'system-persist', category: 'persist', pattern: /crontab|launchctl\s+load|systemctl\s+enable|systemd.*service|\.pth/gi, weight: 4 },

  // ── Data Packaging ────────────────────────────────────────
  { name: 'archive-encrypt', category: 'data-pkg', pattern: /tar\s+[a-z]*c[a-z]*f|openssl\s+enc|gpg\s+--encrypt|zip\s+-[er]/gi, weight: 3 },
  { name: 'known-artifacts', category: 'data-pkg', pattern: /tpcp\.tar\.gz|payload\.enc|\.tar\.gz.*\/tmp|\/tmp.*\.tar\.gz/gi, weight: 4 },

  // ── Monkey-patching / Hooking ─────────────────────────────
  { name: 'monkey-patch', category: 'hook', pattern: /module\.constructor\.prototype|Module\._resolveFilename|Module\._load|__proto__.*require/gi, weight: 4 },
  { name: 'prototype-pollute', category: 'hook', pattern: /Object\.prototype\[|__proto__\s*=/gi, weight: 3 },
];

/**
 * File path patterns that are LOW-VALUE for security analysis.
 * Matches reduce a file's score to suppress noise from tests, docs, etc.
 */
const LOW_VALUE_PATH_PATTERNS = [
  /\/__tests__\//i,
  /\.spec\.(ts|js|tsx|jsx)$/i,
  /\.test\.(ts|js|tsx|jsx)$/i,
  /\/test\//i,
  /\.stories\.(ts|js|tsx|jsx)$/i,
  /\.d\.ts$/i,
  /\/types?\.(ts|js)$/i,
  /\/interfaces?\//i,
  /\/mocks?\//i,
  /\/fixtures?\//i,
  /\/docs?\//i,
  /README/i,
  /CHANGELOG/i,
  /LICENSE/i,
  /\.ya?ml$/i,
  /\.json$/i,  // standalone JSON files (not package.json — that's boosted separately)
  /api\.spec/i,
  /swagger/i,
  /openapi/i,
];

/**
 * File path patterns that are HIGH-VALUE — common injection points.
 */
const HIGH_VALUE_PATH_PATTERNS = [
  /package\.json$/i,
  /Dockerfile/i,
  /Jenkinsfile/i,
  /\.sh$/i,
  /webpack.*config/i,
  /rollup.*config/i,
  /vite.*config/i,
  /jest.*config|jest.*preset|jest.*setup/i,
  /babel.*config/i,
  /\.github\/workflows/i,
  /\.gitlab-ci/i,
  /Makefile/i,
  /setup\.(py|cfg)$/i,
  /pyproject\.toml$/i,
  /main\.(ts|js)$/i,
  /index\.(ts|js)$/i,
  /^tools\//i,
  /builders?\//i,
  /scripts?\//i,
  /codegen/i,
  /generate/i,
  /deploy/i,
  /install-script/i,
  /locust/i,
  /\.py$/i,
];

/**
 * Build the content map for a package source (used by both triage and tools).
 */
export function buildContentMap(source: PackageSource): Map<string, string> {
  const allContent = new Map<string, string>();

  // Include all extracted file contents for triage scanning
  for (const [path, content] of Object.entries(source.fileContents)) {
    allContent.set(path, content);
  }

  // Add install script hooks with a distinguishing prefix
  for (const [hook, content] of Object.entries(source.installScripts)) {
    allContent.set(`package.json:${hook}`, content);
  }

  return allContent;
}

export interface TriageResult {
  filePath: string;
  score: number;
  indicators: Map<string, number>;
  categories: Set<string>;
}

/**
 * Run triage scan programmatically — scores all files against threat indicators.
 * Returns sorted results (highest score first).
 */
export function runTriage(allContent: Map<string, string>): TriageResult[] {
  const fileScores = new Map<string, {
    score: number;
    indicators: Map<string, number>;
    categories: Set<string>;
  }>();

  for (const [filePath, content] of allContent) {
    for (const indicator of THREAT_INDICATORS) {
      indicator.pattern.lastIndex = 0;
      const matches = content.match(indicator.pattern);
      if (matches && matches.length > 0) {
        if (!fileScores.has(filePath)) {
          fileScores.set(filePath, { score: 0, indicators: new Map(), categories: new Set() });
        }
        const entry = fileScores.get(filePath)!;
        entry.score += matches.length * indicator.weight;
        entry.indicators.set(indicator.name, (entry.indicators.get(indicator.name) ?? 0) + matches.length);
        entry.categories.add(indicator.category);
      }
    }
  }

  // Compound scoring: multiple categories = more suspicious
  for (const [, entry] of fileScores) {
    const catCount = entry.categories.size;
    if (catCount >= 3) {
      entry.score = Math.round(entry.score * 2.5);
    } else if (catCount >= 2) {
      entry.score = Math.round(entry.score * 1.8);
    }
  }

  // Path-based adjustments
  for (const [filePath, entry] of fileScores) {
    if (LOW_VALUE_PATH_PATTERNS.some(p => p.test(filePath))) {
      entry.score = Math.round(entry.score * 0.3);
    }
    if (HIGH_VALUE_PATH_PATTERNS.some(p => p.test(filePath))) {
      entry.score = Math.round(entry.score * 1.5);
    }
    if (filePath.startsWith('package.json:')) {
      entry.score = Math.round(entry.score * 3);
    }
  }

  return [...fileScores.entries()]
    .map(([filePath, data]) => ({ filePath, ...data }))
    .sort((a, b) => b.score - a.score);
}

/**
 * Format triage results for display/logging.
 */
export function formatTriageResults(results: TriageResult[], totalFiles: number): string {
  if (results.length === 0) return 'No threat indicators found in any file.';

  const lines: string[] = [];
  lines.push(`Scanned ${totalFiles} files. Found indicators in ${results.length} files.\n`);

  const topCount = Math.min(results.length, 50);
  for (let i = 0; i < topCount; i++) {
    const { filePath, score, indicators, categories } = results[i];
    const indicatorList = [...indicators.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${name}(${count})`)
      .join(', ');
    const catList = [...categories].join('+');
    lines.push(`${i + 1}. [score: ${score}] ${filePath}`);
    lines.push(`   categories: ${catList} | indicators: ${indicatorList}`);
  }

  return lines.join('\n');
}

/**
 * Create package inspection tools bound to a specific package's in-memory source.
 * These tools let the LLM interactively explore the package code.
 */
export function createPackageTools(source: PackageSource, allContent?: Map<string, string>) {
  const content = allContent ?? buildContentMap(source);

  // ── list_files ─────────────────────────────────────────────
  const listFiles = tool(
    async ({ pattern }) => {
      let files = source.fileList;
      if (pattern) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\?/g, '.'), 'i');
        files = files.filter(f => regex.test(f));
      }
      if (files.length === 0) return 'No files matching pattern.';

      // For large file lists, group by top-level directory
      if (files.length > 200 && !pattern) {
        const dirCounts = new Map<string, number>();
        for (const f of files) {
          const dir = f.includes('/') ? f.split('/')[0] : '(root)';
          dirCounts.set(dir, (dirCounts.get(dir) ?? 0) + 1);
        }
        const summary = [...dirCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([dir, count]) => `  ${dir}/ (${count} files)`)
          .join('\n');
        const rootFiles = files.filter(f => !f.includes('/'));
        return `${files.length} total files.\n\nDirectory summary:\n${summary}\n\nRoot files:\n${rootFiles.join('\n')}\n\nUse list_files with a pattern to explore specific directories (e.g., "tools/*", "apps/*", "libs/*").`;
      }

      if (files.length > 200) {
        return `${files.length} files found. Showing first 200:\n${files.slice(0, 200).join('\n')}`;
      }
      return files.join('\n');
    },
    {
      name: 'list_files',
      description: 'List files in the package. Optionally filter by glob-like pattern (e.g., "*.js", "*install*", "*.sh", "tools/*"). For large packages, returns a directory summary when no pattern is specified.',
      schema: z.object({
        pattern: z.string().optional().describe('Glob-like pattern to filter files. Use * as wildcard.'),
      }),
    }
  );

  // ── read_file ──────────────────────────────────────────────
  const readFile = tool(
    async ({ path }) => {
      // Try exact match first
      if (content.has(path)) {
        return content.get(path)!;
      }
      // Try matching by suffix
      for (const [key, val] of content) {
        if (key.endsWith(path) || key.endsWith(`/${path}`)) {
          return val;
        }
      }
      // Check if file exists in fileList but we didn't extract content
      if (source.fileList.some(f => f === path || f.endsWith(`/${path}`))) {
        return '(file exists but content was not extracted — only text files under 500KB are available)';
      }
      return `File not found: ${path}`;
    },
    {
      name: 'read_file',
      description: 'Read the contents of a specific file in the package. Use the path from list_files or triage_scan output.',
      schema: z.object({
        path: z.string().describe('File path to read (from list_files output)'),
      }),
    }
  );

  // ── grep_package ───────────────────────────────────────────
  const grepPackage = tool(
    async ({ pattern, filePattern, context }) => {
      const regex = new RegExp(pattern, 'gi');
      const contextLines = context ?? 2;
      const results: string[] = [];
      const filesMatched = new Set<string>();

      for (const [filePath, fileContent] of content) {
        if (filePattern) {
          const fp = new RegExp(filePattern.replace(/\*/g, '.*'), 'i');
          if (!fp.test(filePath)) continue;
        }

        const lines = fileContent.split('\n');
        const fileMatches: string[] = [];

        for (let i = 0; i < lines.length; i++) {
          regex.lastIndex = 0;
          if (regex.test(lines[i])) {
            // Include context lines
            const start = Math.max(0, i - contextLines);
            const end = Math.min(lines.length - 1, i + contextLines);
            const snippet: string[] = [];
            for (let j = start; j <= end; j++) {
              const marker = j === i ? '>' : ' ';
              snippet.push(`${marker} ${j + 1}: ${lines[j]}`);
            }
            fileMatches.push(snippet.join('\n'));

            if (fileMatches.length >= 5) break; // Cap per file
          }
        }

        if (fileMatches.length > 0) {
          filesMatched.add(filePath);
          results.push(`── ${filePath} (${fileMatches.length} matches) ──`);
          results.push(fileMatches.join('\n---\n'));
          results.push('');
        }

        if (filesMatched.size >= 25) break; // Cap total files
      }

      if (results.length === 0) return 'No matches found.';
      return `Matched in ${filesMatched.size} files:\n\n${results.join('\n')}`;
    },
    {
      name: 'grep_package',
      description: 'Search for a regex pattern across all extracted package files. Returns matching lines grouped by file with surrounding context. Limited to 5 matches per file, 25 files max.',
      schema: z.object({
        pattern: z.string().describe('Regex pattern to search for'),
        filePattern: z.string().optional().describe('Optional file glob to limit search (e.g., "*.js", "*.py")'),
        context: z.number().optional().describe('Number of context lines before/after each match (default: 2)'),
      }),
    }
  );

  // ── report_findings ────────────────────────────────────────
  const reportFindings = tool(
    async ({ findings }) => {
      return `Recorded ${findings.length} finding(s).`;
    },
    {
      name: 'report_findings',
      description: 'Submit findings for this package. Call this incrementally as you discover threats — results accumulate across calls. Call with an empty array when done investigating.',
      schema: z.object({
        findings: z.array(z.object({
          category: z.enum([
            'network-exfiltration',
            'credential-harvesting',
            'crypto-wallet-theft',
            'environment-scanning',
            'code-obfuscation',
            'persistence',
            'data-packaging',
            'cicd-poisoning',
          ]),
          severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
          confidence: z.number().min(0).max(1),
          title: z.string(),
          description: z.string(),
          evidence: z.string(),
          remediation: z.string(),
        })).describe('Array of findings. Empty array [] if the package is clean.'),
      }),
    }
  );

  return { listFiles, readFile, grepPackage, reportFindings };
}
