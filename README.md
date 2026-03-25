# 🛡️ Who Touched My Deps?

A beautiful, fast CLI tool for auditing dependencies and finding vulnerabilities in your projects. Supports npm (JavaScript/TypeScript) and PyPI (Python) packages with a gorgeous terminal UI.

## ✨ Features

- 🔍 **Recursive scanning** - Finds all `package.json` and `requirements.txt` files in your project
- 🐙 **Remote repository scanning** - Clone and scan any Git repository directly
- 🌐 **Multiple data sources** - Queries OSV and GitHub Advisory Database for comprehensive coverage
- 🎨 **Beautiful UI** - Colorful, emoji-rich terminal output with light/dark mode detection
- 📊 **Detailed reports** - Shows severity, CVSS scores, affected versions, and fix information
- 🔧 **Flexible filtering** - Filter by severity level
- 🤖 **CI/CD ready** - JSON output and exit codes for automation
- ⚡ **Fast** - Parallel API requests and efficient scanning
- 🔌 **Extensible** - Easy to add new data sources and package managers

## 📦 Installation

```bash
npm install -g who-touched-my-deps
```

Or use directly with npx:

```bash
npx who-touched-my-deps
```

## 🚀 Usage

### Basic scan (current directory)
```bash
wtmd
# or
who-touched-my-deps
```

### Scan a specific directory
```bash
wtmd --path /path/to/project
```

### Scan a remote repository
```bash
wtmd --repo https://github.com/user/repository
```

### Scan a specific branch
```bash
wtmd --repo https://github.com/user/repository --branch develop
```

### Filter by severity
```bash
wtmd --severity HIGH
```

### JSON output for CI/CD
```bash
wtmd --json
```

### Fail on vulnerabilities (for CI/CD)
```bash
wtmd --fail-on HIGH
```

### Exclude patterns
```bash
wtmd --exclude test fixtures examples
```

## 📋 Command Line Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--path <dir>` | `-p` | Directory to scan | Current directory |
| `--repo <url>` | `-r` | Git repository URL to clone and scan | None |
| `--branch <name>` | `-b` | Branch to checkout when cloning repository | Default branch |
| `--exclude <patterns...>` | `-e` | Patterns to exclude | `[]` |
| `--severity <level>` | `-s` | Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW) | All |
| `--fail-on <level>` | `-f` | Exit with error if vulnerabilities at or above this level are found | None |
| `--json` | `-j` | Output results as JSON | `false` |
| `--verbose` | `-v` | Verbose output | `false` |
| `--version` | | Show version | |
| `--help` | `-h` | Show help | |

## 🎨 Output Examples

### Terminal Output
```
🛡️ Who Touched My Deps?
  Scanning dependencies for vulnerabilities...

✔ Found 3 dependency file(s)
✔ Parsed 45 package(s)

════════════════════════════════════════════════════════════
🛡️ Security Audit Summary
════════════════════════════════════════════════════════════

Scanned Packages: 45
Total Vulnerabilities: 3

🔴 Critical: 1
🟠 High: 2

════════════════════════════════════════════════════════════

📋 Vulnerability Details:
────────────────────────────────────────────────────────────

🔴 CRITICAL - CVE-2023-12345
Package: lodash@4.17.20
Title: Prototype Pollution in lodash
CVSS Score: 9.8
Affected: >=4.0.0 <4.17.21
Fixed in: 4.17.21

References:
  • https://nvd.nist.gov/vuln/detail/CVE-2023-12345
  • https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
Source: OSV
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
  run: npx who-touched-my-deps --json --fail-on HIGH
```

### GitLab CI
```yaml
audit:
  script:
    - npx who-touched-my-deps --json --fail-on HIGH
```

### Jenkins
```groovy
sh 'npx who-touched-my-deps --json --fail-on HIGH'
```

## 🛠️ Development

### Build from source
```bash
git clone https://github.com/yourusername/who-touched-my-deps.git
cd who-touched-my-deps
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
