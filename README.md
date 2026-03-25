# 🛡️ Who Touched My Packages?

A beautiful, fast CLI tool for auditing dependencies and finding vulnerabilities in your projects. Supports npm (JavaScript/TypeScript) and PyPI (Python) packages with a gorgeous terminal UI.

## ✨ Features

- 🔍 **Recursive scanning** - Finds all `package.json` and `requirements.txt` files in your project
- 🐙 **Remote repository scanning** - Clone and scan any Git repository directly
- 🌐 **Multiple data sources** - Queries OSV and GitHub Advisory Database for comprehensive coverage
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
| `--html` | | Generate interactive HTML report and open in browser (default) | `true` |
| `--no-html` | | Disable HTML report generation and use terminal output | `false` |
| `--supply-chain` | | Enable supply chain security analysis | `false` |
| `--supply-chain-model <model>` | | LLM model to use for supply chain analysis | `claude-sonnet-4-5-20241022` |
| `--supply-chain-provider <provider>` | | LLM provider (anthropic, openrouter, openai) | `anthropic` |
| `--supply-chain-concurrency <number>` | | Number of concurrent LLM requests | `3` |
| `--supply-chain-dry-run` | | Skip actual LLM calls (for testing) | `false` |
| `--verbose` | `-v` | Verbose output | `false` |
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
- **GitHub Advisory Database** - GitHub's curated security advisories

See [datasources.md](./datasources.md) for details on all current and planned data sources.

## 🔧 Configuration

### Environment Variables

- `GITHUB_TOKEN` - Optional GitHub personal access token for higher API rate limits

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

- ✅ npm (`package.json`)
- ✅ Python pip (`requirements.txt`)
- 📋 Planned: Cargo, Go modules, Maven, Composer, Bundler, and more

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
- [GitHub Advisory Database](https://github.com/advisories) - Security advisories
- [@clack/prompts](https://github.com/natemoo-re/clack) - Beautiful CLI prompts
- [picocolors](https://github.com/alexeyraspopov/picocolors) - Terminal colors

## 🐛 Issues & Contributing

Found a bug or want to contribute? Please open an issue or PR on GitHub!
