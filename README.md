# 🛡️ Who Touched My Packages?

A beautiful, fast CLI tool for auditing dependencies and finding vulnerabilities in your projects. Supports npm, PyPI, Cargo, Go modules, and RubyGems with a gorgeous terminal UI.

## ✨ Features

- 🔍 **Recursive scanning** - Finds all Node.js, Python, Ruby, Go, and Rust package dependency files in your project
- 🐙 **Remote repository scanning** - Clone and scan any Git repository directly
- 🌐 **Multiple data sources** - Queries OSV for comprehensive coverage
- 🔐 **Provenance verification** - Checks for SLSA provenance attestations on npm and PyPI packages
- 🎨 **Beautiful UI** - Colorful, emoji-rich terminal output with light/dark mode detection
- 📊 **Detailed reports** - Shows severity, CVSS scores, affected versions, and fix information
- 📄 **Interactive HTML reports** - Beautiful HTML reports with charts, tables, and dependency graphs (default output)
- 🎯 **Flexible filtering** - Filter by severity level
- 🤖 **CI/CD ready** - JSON output and exit codes for automation
- ⚡ **Fast** - Parallel API requests and efficient scanning
- 🔌 **Extensible** - Easy to add new data sources and package managers

## 📦 Installation

```bash
npm install -g who-touched-my-packages
```

Or use directly with npx:

```bash
npx who-touched-my-packages

# e.g. 
npx who-touched-my-packages --repo https://github.com/appsecco/dvna # Vulnerable Node app
npx who-touched-my-packages --repo https://github.com/anxolerd/dvpwa # Vulnerable Python app
```

## 🚀 Usage

### Basic scan (current directory)
```bash
wtmp
# or
who-touched-my-packages
```

### Scan a specific directory
```bash
wtmp --path /path/to/project
```

### Scan a remote repository
```bash
wtmp --repo https://github.com/user/repository
```

### Scan a specific branch
```bash
wtmp --repo https://github.com/user/repository --branch develop
```

### Filter by severity
```bash
wtmp --severity HIGH
```

### Use terminal output instead of HTML report
```bash
wtmp --no-html
```

### JSON output for CI/CD
```bash
wtmp --json
```

### Fail on vulnerabilities (for CI/CD)
```bash
wtmp --fail-on HIGH
```

### Exclude patterns
```bash
wtmp --exclude test fixtures examples
```

## 📋 Command Line Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--path <dir>` | `-p` | Directory to scan | Current directory |
| `--repo <url>` | `-r` | Git repository URL to clone and scan | None |
| `--branch <name>` | `-b` | Branch to checkout when cloning repository | Default branch |
| `--exclude <patterns...>` | `-e` | Patterns to exclude from scanning | `[]` |
| `--severity <level>` | `-s` | Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW) | All |
| `--fail-on <level>` | `-f` | Exit with error if vulnerabilities at or above this level are found | None |
| `--json` | `-j` | Output results as JSON | `false` |
| `--output <file>` | `-o` | Save report to file instead of stdout/browser | None |
| `--html` | | Generate interactive HTML report and open in browser (default) | `true` |
| `--no-html` | | Disable HTML report generation and use terminal output | `false` |
| `--no-open` | | Generate HTML report but do not open in browser | `false` |
| `--quiet` | `-q` | Suppress non-error output | `false` |
| `--verbose` | `-v` | Verbose output | `false` |
| `--no-color` | | Disable colored terminal output | `false` |
| `--timeout <seconds>` | | Operation timeout in seconds | `300` |
| `--git-clone-depth <number>` | | Git clone depth for shallow clones (`0` = full clone) | `0` |
| `--max-depth <number>` | | Maximum directory recursion depth (`0` = unlimited) | `0` |
| `--supply-chain` | | Enable supply chain security analysis | `false` |
| `--supply-chain-model <model>` | | LLM model for supply chain analysis (see [Providers](#supply-chain-llm-providers)) | `claude-sonnet-4-6` |
| `--llm-provider <provider>` | | LLM provider — auto-detected from model name when omitted | Auto-detected |
| `--supply-chain-concurrency <number>` | | Number of concurrent LLM requests | `3` |
| `--supply-chain-dry-run` | | Skip actual LLM calls (for testing) | `false` |
| `--version` | | Show version | |
| `--help` | `-h` | Show help | |

## 📄 HTML Reports (Default Output)

By default, the tool generates an interactive HTML report that opens automatically in your browser. The report includes three tabs:

### Overview Tab
- **Statistics tiles** showing total vulnerabilities by severity
- **Pie chart** displaying severity distribution
- **Bar chart** showing vulnerability counts
- Summary of scanned packages

### Vulnerabilities Tab
- **Searchable table** of all detected vulnerabilities
- **Filter by severity** (Critical, High, Medium, Low, Unknown)
- **VSCode links** to open affected files directly in your editor
- **CVE/CVSS links** to external vulnerability databases
- Detailed information including:
  - Vulnerability ID and title
  - Package name and version
  - CVSS score
  - File paths where the vulnerable package is used
  - Links to references (CVE, GitHub, NVD)

### Dependency Graph Tab
- **Interactive visualization** of your dependency tree
- **Highlighted vulnerable packages** in red
- **Zoom and pan** controls
- Based on the same graph technology as [bungraph](https://github.com/knackstedt/bungraph)

The report automatically opens in your default browser after generation and is saved to your system's temp directory.

## 🎨 Output Examples

### Terminal Output
```
┌  🛡️ Who Touched My Packages?
  ⚠️  This program is a work in progress. Accuracy is not guaranteed.

✔ Scan complete

📄 Scanned Files (3):
────────────────────────────────────────
📦 client/package.json
📦 docs/package.json  
📦 package.json

════════════════════════════════════════════════════════════
🛡️ Security Audit Results
════════════════════════════════════════════════════════════

Vulnerabilities Found: 20 (+10 unknown severity)

� Critical: 13
⚠️  High: 7
⚡ Medium: 8

════════════════════════════════════════════════════════════

📋 Vulnerability Details:
────────────────────────────────────────────────────────────

� CRITICAL - CVE-2021-23337
Package: lodash@4.17.20
Title: Command Injection in lodash
CVSS Score: 7.2
Affected: >=0 <4.17.21
Fixed in: 4.17.21

References:
  • https://nvd.nist.gov/vuln/detail/CVE-2021-23337
  • https://github.com/advisories/GHSA-35jh-r3h4-6jhm

Source: OSV
────────────────────────────────────────────────────────────

🟡 MEDIUM - GHSA-5wg4-74h6-q47v
Package: bcrypt@1.0.3
Title: Integer Overflow in bcrypt
CVSS Score: 5.9
Affected: >=0 <5.0.0
Fixed in: 5.0.0

In bcrypt (npm package) before version 5.0.0, data is truncated 
wrong when its length is greater than 255 bytes.

References:
  • https://nvd.nist.gov/vuln/detail/CVE-2020-7689
  • https://github.com/kelektiv/node.bcrypt.js/issues/776

Source: OSV
────────────────────────────────────────────────────────────

💡 12 additional finding(s) with limited information hidden. Use --verbose to see all.

════════════════════════════════════════════════════════════
📊 Final Summary
════════════════════════════════════════════════════════════
Files Scanned: 3
Packages Analyzed: 45
Vulnerabilities Found: 30

By Severity:
  🚨 Critical: 13
  ⚠️  High: 7
  ⚡ Medium: 8
  💡 Low: 0
  ❓ Unknown: 2

════════════════════════════════════════════════════════════

❌ 20 critical/high severity vulnerabilities require immediate attention!
```

### JSON Output
```json
{
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "unknown": 0
  },
  "scannedPackages": 45,
  "timestamp": "2024-03-25T12:00:00.000Z",
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "packageName": "lodash",
      "packageVersion": "4.17.20",
      "ecosystem": "npm",
      "severity": "CRITICAL",
      "title": "Prototype Pollution in lodash",
      "cvss": 9.8,
      "affectedVersions": ">=4.0.0 <4.17.21",
      "fixedVersions": "4.17.21",
      "references": [...]
    }
  ]
}
```

## 🔌 Data Sources

Currently integrated:
- **OSV (Open Source Vulnerabilities)** - Google's comprehensive vulnerability database

See [datasources.md](./datasources.md) for details on all current and planned data sources.

## 🧪 Testing

The repo includes several ad hoc test harnesses for vulnerability detection and supply chain analysis.

### Run the core test suite

These aggregate commands are available:
- `npm run test:all` runs both the static and LLM-backed suites
- `npm run test:all:static` runs typecheck, and known-vulnerable package checks
- `npm run test:all:llm` runs the LLM-backed malicious package fixtures only

```bash
npm run test:all
npm run test:all:static
npm run test:all:llm
```

To pass a specific provider/model through the aggregate LLM runner:

```bash
npm run test:all:llm -- --llm-provider openrouter --supply-chain-model anthropic/claude-sonnet-4-5
npm run test:all:llm --llm-provider openrouter --supply-chain-model anthropic/claude-sonnet-4-5
```

### Run individual CVE/advisory checks

These test `checker.checkDependencies(...)` directly against OSV-backed vulnerable package versions.

```bash
npm run test:cve:npm
npm run test:cve:python
npm run test:cve:go
npm run test:cve:rust
npm run test:cve:ruby
```

### Run LLM-backed package analysis tests

These require the provider-specific API key for the selected model:
- `ANTHROPIC_API_KEY` for Anthropic
- `OPENAI_API_KEY` for OpenAI
- `GOOGLE_API_KEY` for Gemini
- `OPENROUTER_API_KEY` for OpenRouter

```bash
OPENROUTER_API_KEY=sk-or-v1-... npm run test:llm:npm
OPENROUTER_API_KEY=sk-or-v1-... npm run test:llm:python
OPENROUTER_API_KEY=sk-or-v1-... npm run test:llm:go
OPENROUTER_API_KEY=sk-or-v1-... npm run test:llm:rust
OPENROUTER_API_KEY=sk-or-v1-... npm run test:llm:ruby
```

You can also override the LLM provider/model per test:

```bash
OPENAI_API_KEY=... npm run test:llm:npm -- --llm-provider openai --supply-chain-model gpt-5.4
ANTHROPIC_API_KEY=... npm run test:llm:python -- --llm-provider anthropic --supply-chain-model claude-sonnet-4-6
OPENROUTER_API_KEY=... npm run test:llm:rust --llm-provider openrouter --supply-chain-model anthropic/claude-sonnet-4-5
```

### Run specialized test harnesses

```bash
npm run test:malware:litellm
npm run test:integration
```

## � Provenance Verification

The tool automatically verifies package provenance to help ensure supply chain security. This feature checks whether packages have cryptographic attestations proving their build integrity and origin.

### How It Works

**For npm packages:**
- Queries the npm registry for each package
- Checks for SLSA provenance attestations in `dist.attestations.provenance`
- Only packages with `predicateType: "https://slsa.dev/provenance/v1"` are marked as enabled
- Old PGP signatures (`dist.signatures`) are **not** considered provenance

**For PyPI packages:**
- Queries PyPI's JSON API for each package
- Checks for PEP 740 attestations in the release metadata
- Looks for attestation objects in the `urls` array

### What You'll See

**Terminal output:**
```
════════════════════════════════════════════════════════════
🛡️ Provenance Verification
════════════════════════════════════════════════════════════

✅ 19 packages with provenance
⚠️ 26 packages without provenance

Packages without provenance:
  • commander@11.1.0
  • express@4.18.0
  • lodash@4.17.21
  ... and 23 more

════════════════════════════════════════════════════════════
```

**HTML report:**
- **Provenance column** in the Dependencies tab showing:
  - ✓ Enabled (green) - Package has SLSA provenance attestations
  - ⚠️ Missing (red) - No provenance attestations found
  - Unknown (gray) - Verification failed or package not checked
- **"No provenance only" filter** to show packages lacking attestations
- **CSV export** includes provenance status

### Why Provenance Matters

Provenance attestations provide cryptographic proof that:
- The package was built from specific source code
- The build process is reproducible and auditable
- The package hasn't been tampered with after building

Packages without provenance are not necessarily malicious, but they lack this additional layer of supply chain security verification.

### Debug Mode

Enable detailed provenance checking logs:
```bash
WTMP_DEBUG=1 wtmp --path /your/project
```

This will show exactly which packages have provenance and what the registry responses contain.

## �� Configuration

### Environment Variables

- `GITHUB_TOKEN` - Optional GitHub personal access token for higher API rate limits
- `ANTHROPIC_API_KEY` - API key for Anthropic LLM provider (supply chain analysis)
- `OPENAI_API_KEY` - API key for OpenAI LLM provider (supply chain analysis)
- `GOOGLE_API_KEY` - API key for Google Gemini LLM provider (supply chain analysis)
- `OPENROUTER_API_KEY` - API key for OpenRouter LLM provider (supply chain analysis)
- `SC_MAX_LLM_FILES` - Maximum files per package sent to LLM (default: `10`)

Use `--verbose` for detailed supply chain analysis logging (triage scores, tool calls).

### Supply Chain LLM Providers

The provider is **auto-detected** from the model name — you usually only need `--supply-chain-model`:

```bash
# Anthropic (default) — model starts with "claude"
wtmp --supply-chain --supply-chain-model claude-sonnet-4-6

# OpenAI — model starts with "gpt" or "o3"
wtmp --supply-chain --supply-chain-model gpt-5.3-codex

# Gemini (direct Google API) — model starts with "gemini"
wtmp --supply-chain --supply-chain-model gemini-2.5-pro

# Gemini via OpenRouter — model starts with "google/"
wtmp --supply-chain --supply-chain-model google/gemini-2.5-pro

# OpenRouter — model contains "/"
wtmp --supply-chain --supply-chain-model anthropic/claude-sonnet-4-6

# Explicit provider override (if auto-detection doesn't match)
wtmp --supply-chain --supply-chain-model my-custom-model --llm-provider openai
```

| Provider | Auto-detected when model... | Env Var | Example Models |
|----------|---------------------------|---------|----------------|
| **Anthropic** (default) | starts with `claude` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6`, `claude-haiku-4-5-20251001` |
| **OpenAI** | starts with `gpt` / `o1` / `o3` | `OPENAI_API_KEY` | `gpt-5.3-codex`, `gpt-5.4`, `o3`, `o4-mini` |
| **Gemini** | starts with `gemini` or `google/` | `GOOGLE_API_KEY` | `gemini-2.5-pro`, `gemini-2.5-flash` |
| **OpenRouter** | contains `/` (other) | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4-6`, `openai/gpt-5.3-codex` |

### Exit Codes

- `0` - No vulnerabilities found (or below `--fail-on` threshold)
- `1` - Vulnerabilities found at or above `--fail-on` threshold
- `2` - Error occurred during execution

## 🤝 CI/CD Integration

### GitHub Actions
```yaml
- name: Audit Dependencies
  run: npx who-touched-my-packages --json --fail-on HIGH
```

### GitLab CI
```yaml
audit:
  script:
    - npx who-touched-my-packages --json --fail-on HIGH
```

### Jenkins
```groovy
sh 'npx who-touched-my-packages --json --fail-on HIGH'
```

## 🛠️ Development

### Build from source
```bash
git clone https://github.com/yourusername/who-touched-my-packages.git
cd who-touched-my-packages
npm install
npm run build
npm link
```

### Project Structure
```
src/
├── scanner/          # File finding and dependency parsing
├── auditor/          # Vulnerability checking
│   └── datasources/  # Pluggable data source implementations
├── ui/               # Terminal UI and formatting
└── utils/            # Utilities and configuration
```

## 📝 Supported Package Managers

- ✅ Node.js npm (`package.json`)
- ✅ Python pip (`requirements.txt`)
- ✅ Ruby Gemfile (`Gemfile.lock`)
- ✅ Rust cargo (`Cargo.lock, Cargo.toml`)
- ✅ Go modules (`go.sum, go.mod`)
- 📋 Planned: Maven, Composer, Bundler, and more

## 🤔 Why Another Security Tool?

- **Beautiful UX** - Security tools should be pleasant to use
- **Multiple sources** - Don't rely on a single vulnerability database
- **Extensible** - Easy to add new data sources and package managers
- **Fast** - Optimized for large monorepos
- **Free** - No API keys or paid plans required (though some sources support them)

## 📄 License

MIT

## 🙏 Acknowledgments

- [OSV](https://osv.dev) - Open Source Vulnerabilities database
- [@clack/prompts](https://github.com/natemoo-re/clack) - Beautiful CLI prompts
- [picocolors](https://github.com/alexeyraspopov/picocolors) - Terminal colors

## 🐛 Issues & Contributing

Found a bug or want to contribute? Please open an issue or PR on GitHub!
