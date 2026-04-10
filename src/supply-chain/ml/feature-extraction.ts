/**
 * Statistical and structural feature extraction for code chunks.
 * Mirrors the Python extract_features.py + extract_triage_features.py pipeline.
 *
 * Two feature groups:
 *   1. Statistical features (115-d): entropy, line stats, char ratios, char freqs
 *   2. Triage features (68-d): 64 pattern counts + total_score + n_categories + path_adjust + final_score
 *
 * Total: 183 features per chunk (no embedding needed).
 */

// ── Statistical Features (115) ──────────────────────────────────────────

const PRINTABLE_ASCII_START = 0x20;
const PRINTABLE_ASCII_END = 0x7e;

function shannonEntropy(text: string): number {
  if (!text) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  const len = text.length;
  let entropy = 0;
  for (const c of counts.values()) {
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function extractStatFeatures(code: string): number[] {
  if (!code || code.length < 2) return new Array(115).fill(0);

  const lines = code.split('\n');
  const lineLengths = lines.map(l => l.length);
  const total = code.length;

  // Entropy
  const entropyFull = shannonEntropy(code);
  const alnumOnly = code.replace(/[^a-zA-Z0-9]/g, '');
  const entropyAlnum = alnumOnly ? shannonEntropy(alnumOnly) : 0;

  // Line stats
  const maxLineLen = Math.max(...lineLengths, 0);
  const meanLineLen = lineLengths.length ? lineLengths.reduce((a, b) => a + b, 0) / lineLengths.length : 0;

  // Character ratios
  let nonAscii = 0, punctuation = 0, uppercase = 0, digits = 0, whitespace = 0;
  for (const ch of code) {
    const c = ch.charCodeAt(0);
    if (c > 127) nonAscii++;
    if (/[^\w\s]/.test(ch)) punctuation++;
    if (ch >= 'A' && ch <= 'Z') uppercase++;
    if (ch >= '0' && ch <= '9') digits++;
    if (/\s/.test(ch)) whitespace++;
  }

  // String literals
  const stringLits = code.match(/(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)/g) ?? [];
  const numStringLiterals = stringLits.length;
  const longestStringLiteral = Math.max(...stringLits.map(s => s.length), 0);

  // Base64-like sequences
  const b64Matches = code.match(/[A-Za-z0-9+/=]{20,}/g) ?? [];
  const longestBase64 = Math.max(...b64Matches.map(m => m.length), 0);

  // Hex sequences
  const hexMatches = code.match(/(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]+)/g) ?? [];
  const longestHex = Math.max(...hexMatches.map(m => m.length), 0);

  // Vocabulary richness
  const tokens = code.match(/\w+/g) ?? [];
  const vocabRichness = tokens.length ? new Set(tokens).size / tokens.length : 0;

  // Code density
  const nonWs = total - whitespace;
  const codeDensity = total ? nonWs / total : 0;

  // Nesting depth
  let maxDepth = 0, depth = 0;
  for (const ch of code) {
    if ('({['.includes(ch)) { depth++; maxDepth = Math.max(maxDepth, depth); }
    else if (')}]'.includes(ch)) { depth = Math.max(0, depth - 1); }
  }

  // Import count
  const importCount = (code.match(/\bimport\s|require\s*\(|from\s+\S+\s+import/g) ?? []).length;

  // Semicolon density
  const semicolons = (code.match(/;/g) ?? []).length;
  const semicolonDensity = lines.length ? semicolons / lines.length : 0;

  // Comment ratio
  const commentLines = lines.filter(l => {
    const t = l.trim();
    return t.startsWith('//') || t.startsWith('#') || t.startsWith('*');
  }).length;
  const commentRatio = lines.length ? commentLines / lines.length : 0;

  // Character frequency (95 printable ASCII chars)
  const charCounts = new Map<number, number>();
  for (const ch of code) {
    const c = ch.charCodeAt(0);
    charCounts.set(c, (charCounts.get(c) ?? 0) + 1);
  }
  const charFreq: number[] = [];
  for (let c = PRINTABLE_ASCII_START; c <= PRINTABLE_ASCII_END; c++) {
    charFreq.push((charCounts.get(c) ?? 0) / total);
  }

  return [
    entropyFull, entropyAlnum, maxLineLen, meanLineLen,
    nonAscii / total, punctuation / total, uppercase / total,
    digits / total, whitespace / total,
    longestStringLiteral, longestBase64, longestHex,
    numStringLiterals, vocabRichness,
    lines.length, codeDensity, maxDepth, importCount,
    semicolonDensity, commentRatio,
    ...charFreq,
  ];
}

// ── Triage Pattern Features (64) ────────────────────────────────────────

interface TriagePattern {
  name: string;
  category: string;
  weight: number;
  pattern: RegExp;
}

const TRIAGE_PATTERNS: TriagePattern[] = [
  // Network
  { name: 'http-request-api', category: 'network', weight: 2, pattern: /https?\.request\s*\(\s*\{|https?\.get\s*\(|urllib\.request|requests\.(get|post|put)\s*\(/gi },
  { name: 'http-post-data', category: 'network', weight: 3, pattern: /method:\s*['"]POST['"]|\.write\s*\(\s*(JSON\.stringify|payload|data|encoded|body)/gi },
  { name: 'curl-wget-nc', category: 'network', weight: 3, pattern: /\bcurl\s|wget\s|netcat\s|\bnc\s+-[elzw]/gi },
  { name: 'fetch-xhr', category: 'network', weight: 1, pattern: /\bfetch\s*\(|XMLHttpRequest|axios\.(get|post)\(/gi },
  { name: 'socket-connect', category: 'network', weight: 3, pattern: /net\.createConnection|net\.connect\(|socket\.connect\(|new\s+WebSocket\(/gi },
  { name: 'socket-import', category: 'network', weight: 2, pattern: /import\s+socket|require\s*\(\s*['"]net['"]\)|from\s+['"]net['"]/gi },
  { name: 'dns-exfil', category: 'network', weight: 3, pattern: /dns\.resolve|dns\.lookup|\.resolveAny|\.resolveTxt/gi },
  { name: 'external-url', category: 'network', weight: 0, pattern: /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|registry\.npmjs\.org|github\.com|gitlab\.com|npmjs\.com|pypi\.org|jfrog\.io|amazonaws\.com|docker\.io|docker\.com|googleapis\.com|cloudflare\.com|w3\.org|schema\.org|spdx\.org|creativecommons\.org|opensource\.org|example\.com|json-schema\.org|xml\.org|ietf\.org|swagger\.io|openapis\.org|microsoft\.com|apple\.com|google\.com|mozilla\.org)[a-z0-9][-a-z0-9.]*\.[a-z]{2,}/gi },
  { name: 'known-c2', category: 'network', weight: 6, pattern: /models\.litellm\.cloud|checkmarx\.zone|pastebin\.com\/raw|transfer\.sh|ngrok\.io|requestbin|pipedream|oastify\.com|oast\.fun|oast\.pro|oast\.me|oast\.site|interactsh\.com|burpcollaborator|canarytokens|resolver-io\.net/gi },
  { name: 'telegram-exfil', category: 'network', weight: 4, pattern: /api\.telegram\.org|t\.me\/|sendMessage.*chat_id|bot.*token.*telegram/gi },
  { name: 'discord-webhook', category: 'network', weight: 4, pattern: /discord\.com\/api\/webhooks|discordapp\.com\/api\/webhooks/gi },
  { name: 'suspicious-tld', category: 'network', weight: 2, pattern: /https?:\/\/[^\s'"]+\.(xyz|top|tk|ml|ga|cf|gq|pw|ru|su)[\/'"\\s]/gi },
  { name: 'metadata-endpoint', category: 'network', weight: 4, pattern: /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/gi },
  // Creds
  { name: 'credential-files', category: 'creds', weight: 4, pattern: /\.ssh\/id_rsa|\.ssh\/id_ed25519|\.aws\/credentials|\.kube\/config|\.docker\/config\.json|\.npmrc|\.netrc|\.gnupg|\.pgpass|bash_history|zsh_history|\.config\/gcloud|\.azure\/credentials/gi },
  { name: 'system-files', category: 'creds', weight: 4, pattern: /\/etc\/shadow|\/etc\/passwd|\/etc\/hosts/gi },
  { name: 'homedir-read', category: 'creds', weight: 3, pattern: /homedir\(\).*readFile|os\.homedir\(\).*readFile|expanduser.*open|Path\.home\(\)/gi },
  // Crypto
  { name: 'crypto-wallets', category: 'crypto', weight: 4, pattern: /\.bitcoin\/|\.ethereum\/|\.solana\/|wallet\.dat|keystore\/|\.electrum\/|\.monero\/|\.exodus\//gi },
  { name: 'seed-mnemonic', category: 'crypto', weight: 3, pattern: /mnemonic|seed.?phrase|bip39|bip44|recovery.?phrase|secret.?recovery/gi },
  { name: 'browser-wallets', category: 'crypto', weight: 4, pattern: /metamask|phantom|solflare|nkbihfbeogaeao|chrome.*extensions.*wallet/gi },
  // Env
  { name: 'env-bulk-dump', category: 'env', weight: 4, pattern: /JSON\.stringify\([^)]*process\.env|JSON\.stringify\([^)]*os\.environ|JSON\.stringify\(\{[^}]*env:\s*process\.env/gi },
  { name: 'env-iterate-all', category: 'env', weight: 3, pattern: /Object\.(keys|entries|values)\(\s*process\.env\s*\)|Object\.fromEntries\([^)]*process\.env|for\s*\(\s*\w+\s+in\s+process\.env\)|os\.environ\.items\(\)|os\.environ\.copy\(\)|for\s+\w+\s+in\s+os\.environ/gi },
  { name: 'env-filter-pattern', category: 'env', weight: 4, pattern: /process\.env\)\.filter\(|Object\.\w+\(process\.env\)\.filter/gi },
  { name: 'env-regex-secrets', category: 'env', weight: 4, pattern: /\/(TOKEN|KEY|SECRET|PASS|CRED).*\/[gimsuy]*\.test\s*\(/gi },
  { name: 'env-spread-into-payload', category: 'env', weight: 4, pattern: /\.\.\.\s*process\.env|env:\s*process\.env|env:\s*\{[^}]*\.\.\.process\.env|"env"\s*:\s*process\.env/gi },
  { name: 'env-reduce-collect', category: 'env', weight: 3, pattern: /\.reduce\([^)]*process\.env|Object\.assign\([^)]*process\.env/gi },
  { name: 'env-printenv', category: 'env', weight: 3, pattern: /printenv|set\s*\|\s*grep|env\s*\|\s*grep|export\s+-p/gi },
  { name: 'env-secrets-named', category: 'env', weight: 1, pattern: /AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|NPM_TOKEN|ARTIFACTORY_CREDS|OPENAI_API_KEY|STRIPE_SECRET_KEY|SLACK_TOKEN|DATABASE_URL|VAULT_TOKEN/gi },
  // Exec
  { name: 'dynamic-exec', category: 'exec', weight: 3, pattern: /new\s+Function\s*\(|eval\s*\((?!uate)|exec\s*\([^)]*(?:\.toString|base64|decode|atob|compile)/gi },
  { name: 'subprocess-launch', category: 'exec', weight: 2, pattern: /subprocess\.(?:Popen|run|call|check_output|check_call)\s*\(|os\.(?:system|popen)\s*\(/gi },
  { name: 'base64-decode-exec', category: 'exec', weight: 3, pattern: /Buffer\.from\([^)]+,\s*['"]base64['"]\)\s*\.toString|atob\s*\(|base64\.b64decode|base64\.decode|b64decode\s*\(/gi },
  { name: 'marshal-pickle', category: 'exec', weight: 3, pattern: /marshal\.loads|pickle\.loads|dill\.loads|cPickle\.loads|yaml\.load\([^)]*Loader/gi },
  { name: 'dynamic-import', category: 'exec', weight: 2, pattern: /import\s*\(|__import__\s*\(|importlib\.import_module/gi },
  { name: 'python-pip-install', category: 'exec', weight: 4, pattern: /\bpip\s+install\b|\bpip3\s+install\b|subprocess.*pip.*install/gi },
  { name: 'python-codecs-decode', category: 'exec', weight: 4, pattern: /codecs\.decode\s*\([^)]*['"]rot.?13['"]|codecs\.decode\s*\([^)]*['"]hex/gi },
  { name: 'python-compile-exec', category: 'exec', weight: 4, pattern: /compile\s*\([^)]+\)\s*\n?\s*exec\s*\(|exec\s*\(\s*compile\s*\(/gi },
  { name: 'python-setup-override', category: 'install', weight: 3, pattern: /setuptools\.command\.install|cmdclass\s*=\s*\{[^}]*['"]install['"]|setuptools\.command\.develop/gi },
  { name: 'python-pty-spawn', category: 'exec', weight: 5, pattern: /pty\.spawn\s*\(/gi },
  { name: 'python-os-system', category: 'exec', weight: 2, pattern: /os\.system\s*\(|os\.popen\s*\(/gi },
  { name: 'python-socket-connect', category: 'network', weight: 3, pattern: /socket\.socket\s*\([^)]*\)[\s\S]{0,200}\.connect\s*\(|socket\.create_connection\s*\(/gis },
  { name: 'python-urllib', category: 'network', weight: 2, pattern: /urllib\.urlopen|urllib2\.urlopen|urllib\.request\.urlopen|urlopen\s*\(/gi },
  { name: 'python-http-client', category: 'network', weight: 2, pattern: /HTTPSConnection\s*\(|HTTPConnection\s*\(|http\.client/gi },
  { name: 'string-concat-hide', category: 'exec', weight: 3, pattern: /\.join\s*\(\s*['"]['"]?\s*\).*require|\.join\s*\(\s*['"]['"]?\s*\).*https?/gi },
  { name: 'hex-base64-blob', category: 'exec', weight: 3, pattern: /[A-Za-z0-9+/=]{200,}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/gi },
  { name: 'chr-obfuscation', category: 'exec', weight: 4, pattern: /map\s*\(\s*chr\s*,|join\s*\(\s*map\s*\(\s*chr|""\s*\.join\s*\(\s*\[chr|String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){3,}/gi },
  { name: 'exec-chr-combo', category: 'exec', weight: 5, pattern: /exec\s*\(\s*["']?\s*["']?\s*\.?\s*join\s*\(\s*map\s*\(\s*chr/gi },
  { name: 'encoded-powershell', category: 'exec', weight: 4, pattern: /powershell.*-[Ee]ncoded[Cc]ommand|FromBase64String|System\.Convert/gi },
  { name: 'child-process', category: 'exec', weight: 2, pattern: /require\s*\(\s*['"]child_process['"]\)|child_process\.exec|execSync\s*\(|spawnSync\s*\(/gi },
  { name: 'discord-token-steal', category: 'creds', weight: 5, pattern: /Discord.*token|token.*Discord|isValidDiscordToken|extractAllTokens|discord.*leveldb/gi },
  // Install
  { name: 'install-script', category: 'install', weight: 3, pattern: /["']?preinstall["']?\s*:|["']?postinstall["']?\s*:|["']?preuninstall["']?\s*:/gi },
  { name: 'build-injection', category: 'install', weight: 3, pattern: /BannerPlugin|DefinePlugin.*process\.env|webpack.*plugin.*raw|prepend.*main\.js|\.to\s*\(.*main\.js/gis },
  // CI/CD
  { name: 'ci-workflow-write', category: 'cicd', weight: 4, pattern: /writeFile.*\.github\/workflows|writeFile.*\.gitlab-ci|writeFile.*\.circleci|writeFile.*\.travis\.yml|writeFile.*azure-pipelines|fs\.write.*workflow/gi },
  { name: 'ci-tool-exec', category: 'cicd', weight: 2, pattern: /terraform\s+(show|apply|plan)|kubectl\s+(apply|exec|create)|helm\s+(install|upgrade)/gi },
  { name: 'proc-docker-access', category: 'cicd', weight: 4, pattern: /\/proc\/\d+\/mem|\/var\/run\/docker\.sock|docker\.sock/gi },
  // Persistence
  { name: 'shell-profile', category: 'persist', weight: 4, pattern: /\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile/gi },
  { name: 'system-persist', category: 'persist', weight: 4, pattern: /crontab|launchctl\s+load|systemctl\s+enable|systemd.*service|\.pth|Library\/LaunchAgents|HKEY_(?:LOCAL_MACHINE|CURRENT_USER)|reg(?:\.exe)?\s+add/gi },
  // Data packaging
  { name: 'archive-encrypt', category: 'data-pkg', weight: 3, pattern: /tar\s+[a-z]*c[a-z]*f|openssl\s+enc|gpg\s+--encrypt|zip\s+-[er]/gi },
  { name: 'known-artifacts', category: 'data-pkg', weight: 4, pattern: /tpcp\.tar\.gz|payload\.enc|\.tar\.gz.*\/tmp|\/tmp.*\.tar\.gz/gi },
  // Hooking
  { name: 'monkey-patch', category: 'hook', weight: 4, pattern: /module\.constructor\.prototype|Module\._resolveFilename|Module\._load|__proto__.*require/gi },
  { name: 'prototype-pollute', category: 'hook', weight: 3, pattern: /Object\.prototype\[|__proto__\s*=/gi },
  // Time-bomb
  { name: 'timebomb-date', category: 'timebomb', weight: 3, pattern: /new\s+Date\(\)\.getFullYear\(\)\s*[><=!]+\s*\d{4}|Date\.now\(\)\s*[><=!]+\s*(?:\d{13}|[A-Z_]{4,})|const\s+[A-Z_]{4,}\s*=\s*1[5-9]\d{11}/gi },
  { name: 'timebomb-delay', category: 'timebomb', weight: 3, pattern: /setTimeout\s*\([^,]+,\s*\d{6,}\)|setInterval\s*\([^,]+,\s*\d{6,}\)/gi },
  { name: 'conditional-os', category: 'timebomb', weight: 3, pattern: /(?:process\.platform|os\.platform\(\))\s*===?\s*['"](win32|linux|darwin)['"][\s\S]{0,300}exec|os\.name\s*==\s*['"](?:nt|posix)['"][\s\S]{0,300}subprocess/gis },
  // Trojan source
  { name: 'unicode-bidi', category: 'trojan-source', weight: 4, pattern: /[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200f\u061c]/g },
  { name: 'zero-width-chars', category: 'trojan-source', weight: 4, pattern: /[\u200b\u200c\u200d\ufeff\u2060]/g },
];

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

const LOW_VALUE_PATHS = [
  /__tests__\//i, /\.spec\.(ts|js|tsx|jsx)$/i, /\.test\.(ts|js|tsx|jsx)$/i,
  /\/test\//i, /\.stories\./i, /\.d\.ts$/i, /\/types?\.(ts|js)$/i,
  /\/mocks?\//i, /\/fixtures?\//i, /\/docs?\//i, /\/examples?\//i,
  /\.md$/i, /\.map$/i, /LICENSE/i, /\.ya?ml$/i, /\.json$/i,
];

const HIGH_VALUE_PATHS = [
  /package\.json$/i, /Dockerfile/i, /\.sh$/i, /webpack.*config/i,
  /\.github\/workflows/i, /setup\.(py|cfg)$/i, /pyproject\.toml$/i,
  /main\.(ts|js)$/i, /index\.(ts|js)$/i, /scripts?\//i, /\.py$/i,
];

export interface TriageFeatures {
  counts: number[];          // 64 raw pattern match counts
  totalScore: number;        // Weighted + combo + multiplier score
  nCategories: number;       // Number of distinct threat categories
  pathAdjust: number;        // Path-based multiplier
  finalScore: number;        // totalScore × pathAdjust
}

export function extractTriageFeatures(code: string, filePath: string = ''): TriageFeatures {
  const counts: number[] = [];
  const matchedNames = new Set<string>();
  const categories = new Set<string>();

  for (const { name, category, pattern } of TRIAGE_PATTERNS) {
    pattern.lastIndex = 0;
    const matches = code.match(pattern) ?? [];
    counts.push(matches.length);
    if (matches.length > 0) {
      matchedNames.add(name);
      categories.add(category);
    }
  }

  // Base weighted score
  let totalScore = 0;
  for (let i = 0; i < TRIAGE_PATTERNS.length; i++) {
    totalScore += counts[i] * TRIAGE_PATTERNS[i].weight;
  }

  // Category multiplier
  const nCategories = categories.size;
  if (nCategories >= 3) totalScore = Math.round(totalScore * 2.5);
  else if (nCategories >= 2) totalScore = Math.round(totalScore * 1.8);

  // Combo bonuses
  const hasNetwork = [...matchedNames].some(n => NETWORK_NAMES.has(n));
  const hasExec = [...matchedNames].some(n => EXEC_NAMES.has(n));
  if (matchedNames.has('install-script') && (hasNetwork || hasExec)) totalScore += 10;
  if (matchedNames.has('python-setup-override') && (hasNetwork || hasExec)) totalScore += 10;
  if ((matchedNames.has('env-bulk-dump') || matchedNames.has('credential-files')) && hasNetwork) totalScore += 8;
  if (matchedNames.has('base64-decode-exec') && hasExec) totalScore += 6;
  if (matchedNames.has('python-pip-install') && (matchedNames.has('hex-base64-blob') || matchedNames.has('encoded-powershell'))) totalScore += 6;
  if (matchedNames.has('child-process') && matchedNames.has('curl-wget-nc')) totalScore += 6;
  if (matchedNames.has('exec-chr-combo') && totalScore < 8) totalScore = 8;
  if (matchedNames.has('known-c2') && totalScore < 8) totalScore = 8;

  // Path adjustment
  let pathAdjust = 1.0;
  if (LOW_VALUE_PATHS.some(p => p.test(filePath))) pathAdjust = 0.3;
  if (HIGH_VALUE_PATHS.some(p => p.test(filePath))) pathAdjust = 1.5;
  if (filePath.startsWith('package.json:')) pathAdjust = 3.0;
  if (/\.min\.js$/i.test(filePath)) pathAdjust = totalScore < 6 ? 0.3 : 1.2;

  const finalScore = Math.round(totalScore * pathAdjust);

  return { counts, totalScore, nCategories, pathAdjust, finalScore };
}

// ── Package-Level Features (15) ─────────────────────────────────────────

export interface PackageLevelFeatures {
  maxTriageScore: number;
  meanTriageScore: number;
  sumTriageScore: number;
  nChunks: number;
  nFiles: number;
  nChunksWithTriage: number;
  fracWithTriage: number;
  maxEntropy: number;
  maxLineLen: number;
  maxCategories: number;
  hasInstallHook: number;
  hasKnownC2: number;
  scoreRatio: number;  // this chunk's score / package max
}

export function computePackageFeatures(
  fileTriageScores: Map<string, number>,
  fileTriageResults: Map<string, TriageFeatures>,
  fileStatFeatures: Map<string, number[]>,
): PackageLevelFeatures {
  const scores = [...fileTriageScores.values()];
  const maxScore = scores.length ? Math.max(...scores) : 0;
  const meanScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
  const sumScore = scores.reduce((a, b) => a + b, 0);
  const nFiles = fileTriageScores.size;
  const nWithTriage = scores.filter(s => s > 0).length;

  let maxEntropy = 0;
  let maxLineLen = 0;
  for (const feat of fileStatFeatures.values()) {
    if (feat[0] > maxEntropy) maxEntropy = feat[0];
    if (feat[2] > maxLineLen) maxLineLen = feat[2];
  }

  let maxCats = 0;
  let hasInstallHook = 0;
  let hasC2 = 0;
  for (const tr of fileTriageResults.values()) {
    if (tr.nCategories > maxCats) maxCats = tr.nCategories;
    // install-script is pattern index 48
    if (tr.counts[48] > 0) hasInstallHook = 1;
    // known-c2 is pattern index 8
    if (tr.counts[8] > 0) hasC2 = 1;
  }

  return {
    maxTriageScore: maxScore,
    meanTriageScore: meanScore,
    sumTriageScore: sumScore,
    nChunks: scores.length,  // will be updated per-chunk
    nFiles,
    nChunksWithTriage: nWithTriage,
    fracWithTriage: nFiles ? nWithTriage / nFiles : 0,
    maxEntropy,
    maxLineLen,
    maxCategories: maxCats,
    hasInstallHook,
    hasKnownC2: hasC2,
    scoreRatio: 0,  // set per-file
  };
}

// ── Combine into feature vector ─────────────────────────────────────────

export function buildFeatureVector(
  statFeatures: number[],
  triageFeatures: TriageFeatures,
  pkgFeatures?: PackageLevelFeatures,
): number[] {
  const vec = [
    ...statFeatures,                          // 115
    ...triageFeatures.counts,                 // 64
    triageFeatures.totalScore,                // 1
    triageFeatures.nCategories,               // 1
    triageFeatures.pathAdjust,                // 1
    triageFeatures.finalScore,                // 1
  ];                                          // = 183

  if (pkgFeatures) {
    vec.push(
      pkgFeatures.maxTriageScore,
      pkgFeatures.meanTriageScore,
      pkgFeatures.sumTriageScore,
      pkgFeatures.nChunks,
      pkgFeatures.nFiles,
      pkgFeatures.nChunksWithTriage,
      pkgFeatures.fracWithTriage,
      pkgFeatures.maxEntropy,
      pkgFeatures.maxLineLen,
      pkgFeatures.maxCategories,
      pkgFeatures.hasInstallHook,
      pkgFeatures.hasKnownC2,
      pkgFeatures.scoreRatio,
    );                                        // +13 = 196
  }

  return vec;
}
