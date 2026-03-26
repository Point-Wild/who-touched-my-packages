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
  { name: 'known-c2', category: 'network', pattern: /models\.litellm\.cloud|checkmarx\.zone|pastebin\.com\/raw|transfer\.sh|ngrok\.io|requestbin|pipedream|oastify\.com|oast\.fun|oast\.pro|oast\.me|oast\.site|interactsh\.com|burpcollaborator|canarytokens|resolver-io\.net/gi, weight: 6 },
  { name: 'telegram-exfil', category: 'network', pattern: /api\.telegram\.org|t\.me\/|sendMessage.*chat_id|bot.*token.*telegram/gi, weight: 4 },
  { name: 'discord-webhook', category: 'network', pattern: /discord\.com\/api\/webhooks|discordapp\.com\/api\/webhooks/gi, weight: 4 },
  { name: 'suspicious-tld', category: 'network', pattern: /https?:\/\/[^\s'"]+\.(xyz|top|tk|ml|ga|cf|gq|pw|ru|su)[\/'"\\s]/gi, weight: 2 },
  { name: 'metadata-endpoint', category: 'network', pattern: /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/gi, weight: 4 },

  // ── Credential Harvesting ─────────────────────────────────
  { name: 'credential-files', category: 'creds', pattern: /\.ssh\/id_rsa|\.ssh\/id_ed25519|\.aws\/credentials|\.kube\/config|\.docker\/config\.json|\.npmrc|\.netrc|\.gnupg|\.pgpass|bash_history|zsh_history|\.config\/gcloud|\.azure\/credentials/gi, weight: 4 },
  { name: 'system-files', category: 'creds', pattern: /\/etc\/shadow|\/etc\/passwd|\/etc\/hosts/gi, weight: 4 },
  { name: 'homedir-read', category: 'creds', pattern: /homedir\(\).*readFile|os\.homedir\(\).*readFile|expanduser.*open|Path\.home\(\)/gi, weight: 3 },

  // ── Crypto Wallet Theft ───────────────────────────────────
  { name: 'crypto-wallets', category: 'crypto', pattern: /\.bitcoin\/|\.ethereum\/|\.solana\/|wallet\.dat|keystore\/|\.electrum\/|\.monero\/|\.exodus\//gi, weight: 4 },
  { name: 'seed-mnemonic', category: 'crypto', pattern: /mnemonic|seed.?phrase|bip39|bip44|recovery.?phrase|secret.?recovery/gi, weight: 3 },
  { name: 'browser-wallets', category: 'crypto', pattern: /metamask|phantom|solflare|nkbihfbeogaeao|chrome.*extensions.*wallet/gi, weight: 4 },

  // ── Environment Scanning ──────────────────────────────────
  // Pattern-based: detect the BEHAVIOR of collecting/exfiltrating env vars
  { name: 'env-bulk-dump', category: 'env', pattern: /JSON\.stringify\([^)]*process\.env|JSON\.stringify\([^)]*os\.environ|JSON\.stringify\(\{[^}]*env:\s*process\.env/gi, weight: 4 },
  { name: 'env-iterate-all', category: 'env', pattern: /Object\.(keys|entries|values)\(\s*process\.env\s*\)|Object\.fromEntries\([^)]*process\.env|for\s*\(\s*\w+\s+in\s+process\.env\)|os\.environ\.items\(\)|os\.environ\.copy\(\)|for\s+\w+\s+in\s+os\.environ/gi, weight: 3 },
  { name: 'env-filter-pattern', category: 'env', pattern: /process\.env\)\.filter\(|Object\.\w+\(process\.env\)\.filter/gi, weight: 4 },
  { name: 'env-regex-secrets', category: 'env', pattern: /\/(TOKEN|KEY|SECRET|PASS|CRED).*\/[gimsuy]*\.test\s*\(/gi, weight: 4 },
  { name: 'env-spread-into-payload', category: 'env', pattern: /\.\.\.\s*process\.env|env:\s*process\.env|env:\s*\{[^}]*\.\.\.process\.env|"env"\s*:\s*process\.env/gi, weight: 4 },
  { name: 'env-reduce-collect', category: 'env', pattern: /\.reduce\([^)]*process\.env|Object\.assign\([^)]*process\.env/gi, weight: 3 },
  { name: 'env-printenv', category: 'env', pattern: /printenv|set\s*\|\s*grep|env\s*\|\s*grep|export\s+-p/gi, weight: 3 },
  // Specific high-value env var names (supplementary — catches targeted reads)
  { name: 'env-secrets-named', category: 'env', pattern: /AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|NPM_TOKEN|ARTIFACTORY_CREDS|OPENAI_API_KEY|STRIPE_SECRET_KEY|SLACK_TOKEN|DATABASE_URL|VAULT_TOKEN/gi, weight: 1 },

  // ── Code Obfuscation / Dynamic Execution ──────────────────
  { name: 'dynamic-exec', category: 'exec', pattern: /new\s+Function\s*\(|eval\s*\((?!uate)|exec\s*\([^)]*(?:\.toString|base64|decode|atob|compile)/gi, weight: 3 },
  { name: 'subprocess-launch', category: 'exec', pattern: /subprocess\.(?:Popen|run|call|check_output|check_call)\s*\(|os\.(?:system|popen)\s*\(/gi, weight: 2 },
  { name: 'base64-decode-exec', category: 'exec', pattern: /Buffer\.from\([^)]+,\s*['"]base64['"]\)\s*\.toString|atob\s*\(|base64\.b64decode|base64\.decode|b64decode\s*\(/gi, weight: 3 },
  { name: 'marshal-pickle', category: 'exec', pattern: /marshal\.loads|pickle\.loads|dill\.loads|cPickle\.loads|yaml\.load\([^)]*Loader/gi, weight: 3 },
  { name: 'dynamic-import', category: 'exec', pattern: /__import__\s*\(|importlib\.import_module|require\s*\(\s*[^'"]/gi, weight: 2 },
  { name: 'python-pip-install', category: 'exec', pattern: /\bpip\s+install\b|\bpip3\s+install\b|subprocess.*pip.*install/gi, weight: 4 },
  { name: 'python-codecs-decode', category: 'exec', pattern: /codecs\.decode\s*\([^)]*['"]rot.?13['"]|codecs\.decode\s*\([^)]*['"]hex/gi, weight: 4 },
  { name: 'python-compile-exec', category: 'exec', pattern: /compile\s*\([^)]+\)\s*\n?\s*exec\s*\(|exec\s*\(\s*compile\s*\(/gi, weight: 4 },
  { name: 'python-setup-override', category: 'install', pattern: /setuptools\.command\.install|cmdclass\s*=\s*\{[^}]*['"]install['"]|setuptools\.command\.develop/gi, weight: 3 },
  { name: 'python-pty-spawn', category: 'exec', pattern: /pty\.spawn\s*\(/gi, weight: 5 },
  { name: 'python-os-system', category: 'exec', pattern: /os\.system\s*\(|os\.popen\s*\(/gi, weight: 2 },
  { name: 'python-socket-connect', category: 'network', pattern: /socket\.socket\s*\([^)]*\)[\s\S]{0,200}\.connect\s*\(|socket\.create_connection\s*\(/gis, weight: 3 },
  { name: 'python-urllib', category: 'network', pattern: /urllib\.urlopen|urllib2\.urlopen|urllib\.request\.urlopen|urlopen\s*\(/gi, weight: 2 },
  { name: 'python-http-client', category: 'network', pattern: /HTTPSConnection\s*\(|HTTPConnection\s*\(|http\.client/gi, weight: 2 },
  { name: 'string-concat-hide', category: 'exec', pattern: /\.join\s*\(\s*['"]['"]?\s*\).*require|\.join\s*\(\s*['"]['"]?\s*\).*https?/gi, weight: 3 },
  { name: 'hex-base64-blob', category: 'exec', pattern: /[A-Za-z0-9+/=]{200,}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/gi, weight: 3 },
  { name: 'chr-obfuscation', category: 'exec', pattern: /map\s*\(\s*chr\s*,|join\s*\(\s*map\s*\(\s*chr|""\s*\.join\s*\(\s*\[chr|String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){3,}/gi, weight: 4 },
  { name: 'exec-chr-combo', category: 'exec', pattern: /exec\s*\(\s*["']?\s*["']?\s*\.?\s*join\s*\(\s*map\s*\(\s*chr/gi, weight: 5 },
  { name: 'encoded-powershell', category: 'exec', pattern: /powershell.*-[Ee]ncoded[Cc]ommand|FromBase64String|System\.Convert/gi, weight: 4 },
  { name: 'child-process', category: 'exec', pattern: /require\s*\(\s*['"]child_process['"]\)|child_process\.exec|execSync\s*\(|spawnSync\s*\(/gi, weight: 2 },
  { name: 'discord-token-steal', category: 'creds', pattern: /Discord.*token|token.*Discord|isValidDiscordToken|extractAllTokens|discord.*leveldb/gi, weight: 5 },

  // ── Build / Install Hooks ─────────────────────────────────
  { name: 'install-script', category: 'install', pattern: /["']?preinstall["']?\s*:|["']?postinstall["']?\s*:|["']?preuninstall["']?\s*:/gi, weight: 3 },
  { name: 'build-injection', category: 'install', pattern: /BannerPlugin|DefinePlugin.*process\.env|webpack.*plugin.*raw|prepend.*main\.js|\.to\s*\(.*main\.js/gis, weight: 3 },

  // ── CI/CD Poisoning ───────────────────────────────────────
  { name: 'ci-workflow-write', category: 'cicd', pattern: /writeFile.*\.github\/workflows|writeFile.*\.gitlab-ci|writeFile.*\.circleci|writeFile.*\.travis\.yml|writeFile.*azure-pipelines|fs\.write.*workflow/gi, weight: 4 },
  { name: 'ci-tool-exec', category: 'cicd', pattern: /terraform\s+(show|apply|plan)|kubectl\s+(apply|exec|create)|helm\s+(install|upgrade)/gi, weight: 2 },
  { name: 'proc-docker-access', category: 'cicd', pattern: /\/proc\/\d+\/mem|\/var\/run\/docker\.sock|docker\.sock/gi, weight: 4 },

  // ── Persistence ───────────────────────────────────────────
  { name: 'shell-profile', category: 'persist', pattern: /\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile/gi, weight: 4 },
  { name: 'system-persist', category: 'persist', pattern: /crontab|launchctl\s+load|systemctl\s+enable|systemd.*service|\.pth|Library\/LaunchAgents|HKEY_(?:LOCAL_MACHINE|CURRENT_USER)|reg(?:\.exe)?\s+add/gi, weight: 4 },

  // ── Data Packaging ────────────────────────────────────────
  { name: 'archive-encrypt', category: 'data-pkg', pattern: /tar\s+[a-z]*c[a-z]*f|openssl\s+enc|gpg\s+--encrypt|zip\s+-[er]/gi, weight: 3 },
  { name: 'known-artifacts', category: 'data-pkg', pattern: /tpcp\.tar\.gz|payload\.enc|\.tar\.gz.*\/tmp|\/tmp.*\.tar\.gz/gi, weight: 4 },

  // ── Monkey-patching / Hooking ─────────────────────────────
  { name: 'monkey-patch', category: 'hook', pattern: /module\.constructor\.prototype|Module\._resolveFilename|Module\._load|__proto__.*require/gi, weight: 4 },
  { name: 'prototype-pollute', category: 'hook', pattern: /Object\.prototype\[|__proto__\s*=/gi, weight: 3 },
  // ── Dormancy / Time-bomb ──────────────────────────────────────
  { name: 'timebomb-date', category: 'timebomb',
    // Matches literal future timestamps AND named constants assigned a 13-digit value near a Date.now() comparison
    pattern: /new\s+Date\(\)\.getFullYear\(\)\s*[><=!]+\s*\d{4}|Date\.now\(\)\s*[><=!]+\s*(?:\d{13}|[A-Z_]{4,})|const\s+[A-Z_]{4,}\s*=\s*1[5-9]\d{11}/gi, weight: 3 },
  { name: 'timebomb-delay', category: 'timebomb',
    pattern: /setTimeout\s*\([^,]+,\s*\d{6,}\)|setInterval\s*\([^,]+,\s*\d{6,}\)/gi, weight: 3 },
  { name: 'conditional-os', category: 'timebomb',
    // Covers both process.platform and os.platform() (node-ipc style)
    pattern: /(?:process\.platform|os\.platform\(\))\s*===?\s*['"](win32|linux|darwin)['"][\s\S]{0,300}exec|os\.name\s*==\s*['"](nt|posix)['"][\s\S]{0,300}subprocess/gis, weight: 3 },

  // ── Trojan Source / Unicode Tricks (CVE-2021-42574) ──────────
  { name: 'unicode-bidi', category: 'trojan-source',
    pattern: /[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200f\u061c]/g, weight: 4 },
  { name: 'zero-width-chars', category: 'trojan-source',
    pattern: /[\u200b\u200c\u200d\ufeff\u2060]/g, weight: 4 },

  // ── Multi-stage Loader ────────────────────────────────────────
  { name: 'eval-on-response', category: 'loader',
    pattern: /eval\s*\(\s*(response|data|payload|result|body|text|res|chunk)\b/gi, weight: 4 },
  { name: 'write-then-exec', category: 'loader',
    pattern: /writeFile(?:Sync)?\s*\([^)]+\)[\s\S]{0,200}exec(?:Sync)?\s*\(|writeFile(?:Sync)?\s*\([^)]+\)[\s\S]{0,200}require\s*\(/gis, weight: 4 },
  { name: 'multi-stage-fetch-exec', category: 'loader',
    pattern: /(?:fetch|axios\.get|axios\.post|request)\s*\([^)]+\)[\s\S]{0,300}exec(?:Sync)?\s*\(/gis, weight: 4 },

  // ── Package.json metadata URL injection ──────────────────────
  { name: 'metadata-private-ip', category: 'network',
    pattern: /"(?:bugs|funding|homepage)"[^}]{0,100}(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.0\.0\.1|0\.0\.0\.0)/gi, weight: 4 },];

/**
 * File path patterns that are LOW-VALUE for security analysis.
 * Matches reduce a file's score to suppress noise from tests, docs, etc.
 * NOTE: .min.js is intentionally excluded here; it is handled separately in
 * runTriage() with score-sensitive logic (high-scoring minified files are
 * boosted, not suppressed).
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
  /\/examples?\//i,
  /\.md$/i,
  /\.map$/i,
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

  // Combo bonuses: known-malicious indicator combinations
  const NETWORK_NAMES = new Set([
    'http-request-api', 'http-post-data', 'curl-wget-nc', 'fetch-xhr', 'socket-connect',
    'dns-exfil', 'known-c2', 'metadata-endpoint', 'telegram-exfil', 'discord-webhook',
    'suspicious-tld', 'python-urllib', 'python-socket-connect', 'python-http-client',
  ]);
  const EXEC_NAMES = new Set([
    'dynamic-exec', 'subprocess-launch', 'child-process', 'dynamic-import',
    'python-compile-exec', 'python-os-system', 'python-pty-spawn', 'python-pip-install',
    'chr-obfuscation', 'exec-chr-combo',
  ]);
  for (const [, entry] of fileScores) {
    const names = entry.indicators;
    const hasNetwork = [...names.keys()].some(n => NETWORK_NAMES.has(n));
    const hasExec = [...names.keys()].some(n => EXEC_NAMES.has(n));

    // install-hook + any network or exec → +10
    if (names.has('install-script') && (hasNetwork || hasExec)) {
      entry.score += 10;
    }
    // setup.py install override + any exec or network → +10
    if (names.has('python-setup-override') && (hasNetwork || hasExec)) {
      entry.score += 10;
    }
    // env-bulk-dump or credential-files + any network → +8
    if ((names.has('env-bulk-dump') || names.has('credential-files')) && hasNetwork) {
      entry.score += 8;
    }
    // base64-decode + exec → +6
    if (names.has('base64-decode-exec') && hasExec) {
      entry.score += 6;
    }
    // pip-install + obfuscation blob → +6 (common setup.py backdoor)
    if (names.has('python-pip-install') && (names.has('hex-base64-blob') || names.has('encoded-powershell'))) {
      entry.score += 6;
    }
    // child-process + curl/wget → +6
    if (names.has('child-process') && names.has('curl-wget-nc')) {
      entry.score += 6;
    }
    // exec + chr obfuscation → always malicious
    if (names.has('exec-chr-combo') && entry.score < 8) {
      entry.score = 8;
    }
    // known-c2 should always cross threshold 8
    if (names.has('known-c2') && entry.score < 8) {
      entry.score = 8;
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
    // Minified files: suppress low-scoring matches (noise) but boost high-scoring
    // ones — legitimate minified files don't contain eval, base64 blobs, or socket
    // calls, so a high score in a .min.js is genuinely suspicious.
    if (/\.min\.js$/i.test(filePath)) {
      if (entry.score < 6) {
        entry.score = Math.round(entry.score * 0.3);
      } else {
        entry.score = Math.round(entry.score * 1.2);
      }
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
          // Accept any string the LLM produces; unknown categories are preserved
          // as-is so findings are never silently dropped due to schema mismatches.
          category: z.string().transform(v => {
            const known = [
              'network-exfiltration', 'credential-harvesting', 'crypto-wallet-theft',
              'environment-scanning', 'code-obfuscation', 'persistence',
              'data-packaging', 'cicd-poisoning', 'maintainer-takeover',
              'typosquatting', 'dependency-confusion',
            ];
            return known.includes(v) ? v : 'code-obfuscation';
          }),
          severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).catch('MEDIUM'),
          confidence: z.number().min(0).max(1).catch(0.5),
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
