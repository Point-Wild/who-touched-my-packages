# Supply Chain Analyzer

AI-powered detection of supply chain poisoning threats in npm and PyPI packages. Uses a two-phase approach: programmatic triage scoring against 35+ threat indicator patterns, followed by per-file LLM analysis to confirm or dismiss each suspicious file.

## Architecture

The analyzer uses a two-phase investigation strategy:

```
Phase 1 (Programmatic)                    Phase 2 (LLM per-file)
┌─────────────────────┐                   ┌──────────────────────────┐
│ Triage all files     │                   │ For each suspicious file │
│ against 35+ threat   │──► Top N files ──►│ • Read full content      │
│ indicator patterns   │    (score ≥ 8)    │ • LLM determines intent  │
│ with compound scoring│                   │ • Report findings        │
└─────────────────────┘                   └──────────────────────────┘
```

This is wrapped in a 4-stage [LangGraph](https://github.com/langchain-ai/langgraphjs) pipeline:

```
Dependency[] ──► fetch_metadata ──► primary_analysis ──► deep_investigation ──► aggregate ──► SupplyChainResult
                 │                  │                     │ (conditional)        │
                 │ Query registries  │ Triage + per-file   │ Re-analyze HIGH/     │ Deduplicate,
                 │ Download tarballs │ LLM investigation   │ CRITICAL findings    │ sort, summarize
                 │ Extract source    │                     │ Confirm/downgrade    │
```

### Stage 1: Fetch Metadata (`nodes/fetch-metadata.ts`)

Queries npm/PyPI registries in parallel, downloads package tarballs, and extracts text files (<500KB), install scripts, and entry points.

### Stage 2: Primary Analysis (`nodes/primary-analysis.ts`)

Two-phase investigation per package:

**Phase 1 — Programmatic Triage** (`tools.ts: runTriage()`)
- Scores every file against 35+ threat indicator patterns
- Applies compound scoring: files matching multiple threat categories (e.g., network + creds + exec) score exponentially higher
- Applies path-based weighting:
  - Install scripts: 3x boost
  - Build configs, scripts, entry points: 1.5x boost
  - Test files, docs, type definitions: 0.3x suppression
- Returns a ranked list of suspicious files above the score threshold

**Phase 2 — Per-file LLM Analysis**
- Each suspicious file is sent to the LLM individually with its triage indicators and full content
- The LLM has 4 tools for additional context:

| Tool | Purpose |
|------|---------|
| `list_files` | List package files with optional glob filtering |
| `read_file` | Read specific file contents |
| `grep_package` | Regex search across extracted files with context lines |
| `report_findings` | Submit discovered security findings (incremental) |

- Findings accumulate across files — no findings are lost even if the LLM stops early on a given file
- Every file above the triage threshold is analyzed — the LLM cannot skip files

### Stage 3: Deep Investigation (`nodes/deep-investigation.ts`)

Conditionally triggered when HIGH/CRITICAL findings exist with confidence >= 0.3. A second LLM pass re-analyzes each finding with full source context and returns a verdict: `CONFIRMED`, `DOWNGRADED`, or `FALSE_POSITIVE`.

### Stage 4: Aggregate (`nodes/aggregate.ts`)

Deduplicates findings, sorts by severity then confidence, and compiles the final `SupplyChainResult` with summary statistics.

## Triage Indicator Categories

The programmatic triage scans for these pattern families:

| Category | Indicators | Examples |
|----------|-----------|---------|
| Network | `http-request-api`, `curl-wget-nc`, `socket-connect`, `dns-exfil`, `known-c2`, `metadata-endpoint`, `http-post-data` | `https.request()`, `curl`, `dns.resolve`, `169.254.169.254` |
| Credentials | `credential-files`, `system-files`, `homedir-read` | `~/.ssh/id_rsa`, `~/.aws/credentials`, `/etc/shadow` |
| Crypto | `crypto-wallets`, `seed-mnemonic`, `browser-wallets` | `~/.bitcoin/`, `wallet.dat`, MetaMask directories |
| Environment | `env-bulk-dump`, `env-iterate-all`, `env-filter-pattern`, `env-regex-secrets`, `env-spread-into-payload` | `JSON.stringify(process.env)`, `Object.keys(process.env).filter()` |
| Execution | `dynamic-exec`, `base64-decode-exec`, `marshal-pickle`, `child-process`, `string-concat-hide` | `new Function()`, `eval()`, `execSync()`, `.join('')` |
| Build/Install | `install-script`, `build-injection` | `preinstall`, `BannerPlugin`, webpack injection |
| CI/CD | `ci-workflow-write`, `ci-tool-exec`, `proc-docker-access` | `.github/workflows`, `terraform show`, `docker.sock` |
| Persistence | `shell-profile`, `system-persist` | `.bashrc`, `crontab`, `systemd` |
| Data Packaging | `archive-encrypt`, `known-artifacts` | `tar czf`, `openssl enc`, `tpcp.tar.gz` |
| Hooking | `monkey-patch`, `prototype-pollute` | `module.constructor.prototype`, `__proto__` |

## Threat Categories (Findings)

| Category | Examples |
|----------|---------|
| `network-exfiltration` | HTTP/DNS requests, socket connections, known C2 domains, cloud metadata endpoints |
| `credential-harvesting` | SSH keys, AWS credentials, Docker configs, `.npmrc` |
| `crypto-wallet-theft` | Bitcoin/Ethereum/Solana wallet files, seed phrases |
| `environment-scanning` | Bulk `process.env` dumps, targeted secret extraction |
| `code-obfuscation` | `eval()`, `new Function()`, base64 decoding, marshal/pickle |
| `persistence` | Shell profile injection, cron jobs, systemd services |
| `data-packaging` | Archive creation + encryption before exfiltration |
| `cicd-poisoning` | GitHub Actions/GitLab CI injection, kubectl manipulation |

## Usage

```typescript
import { analyzeSupplyChain } from './supply-chain';

const result = await analyzeSupplyChain(dependencies, {
  apiKey: 'sk-...',          // or set THREATPOINT_API_KEY env var
  model: 'claude-sonnet-4-5-20241022', // default
  provider: 'anthropic',     // 'anthropic' | 'openai' | 'openrouter'
  concurrency: 3,            // parallel package analyses
});

console.log(result.summary);
// { total: 5, critical: 1, high: 2, medium: 1, low: 1, byCategory: { ... } }
```

### API Key Resolution

The API key is resolved in order:

1. `options.apiKey` parameter
2. `THREATPOINT_API_KEY` environment variable
3. `~/.threatpoint` file (first line)

### Progress Callback

```typescript
await analyzeSupplyChain(deps, options, (stage, done, total) => {
  console.log(`${stage}: ${done}/${total}`);
});
```

### Verbose Logging

Set `SC_VERBOSE=1` to see detailed triage scores, per-file analysis progress, and tool call traces.

## Output

```typescript
interface SupplyChainResult {
  findings: SupplyChainFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    byCategory: Partial<Record<ThreatCategory, number>>;
  };
  packagesAnalyzed: number;
  timestamp: Date;
  model: string;
}

interface SupplyChainFinding {
  packageName: string;
  packageVersion: string;
  ecosystem: 'npm' | 'pypi';
  category: ThreatCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;        // 0-1
  title: string;
  description: string;
  evidence: string;          // Exact code from the package
  remediation: string;
  deepInvestigated: boolean;
}
```

## Directory Structure

```
supply-chain/
├── index.ts              # Entry point & public API
├── types.ts              # Type definitions
├── graph.ts              # LangGraph workflow orchestration
├── utils.ts              # Helpers (pMap, depKey, extractJSON, resolveApiKey)
├── llm/
│   ├── client.ts         # LLM provider factory (Anthropic, OpenAI, OpenRouter)
│   ├── tools.ts          # Triage engine, threat indicators, agent tools
│   └── prompts.ts        # System prompts & per-file analysis prompts
├── nodes/
│   ├── fetch-metadata.ts # Stage 1: registry fetch & tarball extraction
│   ├── primary-analysis.ts # Stage 2: triage + per-file LLM analysis
│   ├── deep-investigation.ts # Stage 3: high-severity validation
│   └── aggregate.ts      # Stage 4: dedup, sort, summarize
└── registry/
    ├── npm.ts            # NPM registry integration
    └── pypi.ts           # PyPI registry integration
```

## LLM Providers

| Provider | Model Examples | Config |
|----------|---------------|--------|
| Anthropic (default) | `claude-sonnet-4-5-20241022` | Direct API, maxTokens=8192 |
| OpenAI | `gpt-4o` | Standard OpenAI API |
| OpenRouter | Any supported model | Custom baseURL routing |
