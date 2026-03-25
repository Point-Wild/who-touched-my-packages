---
title: Installation
description: How to install Who Touched My Deps
---

## Prerequisites

- **Node.js** 18.0.0 or higher
- **npm** or **npx**

## Global Installation

Install the tool globally to use it anywhere:

```bash
npm install -g who-touched-my-deps
```

After installation, you can use the `wtmd` or `who-touched-my-deps` command:

```bash
wtmd --version
```

## Using npx (No Installation)

Run the tool directly without installing:

```bash
npx who-touched-my-deps
```

This is useful for:
- One-time scans
- CI/CD pipelines
- Testing before installing

## Local Installation

Install as a dev dependency in your project:

```bash
npm install --save-dev who-touched-my-deps
```

Add to your `package.json` scripts:

```json
{
  "scripts": {
    "audit": "wtmd",
    "audit:ci": "wtmd --json --fail-on HIGH"
  }
}
```

Run with:

```bash
npm run audit
```

## Verify Installation

Check that the tool is installed correctly:

```bash
wtmd --version
# Output: 0.1.0

wtmd --help
# Shows all available options
```

## Next Steps

- [Quick Start Guide](/quick-start/) - Run your first scan
- [Command Line Options](/usage/cli-options/) - Learn all available options
- [CI/CD Integration](/usage/ci-cd/) - Set up automated scanning
