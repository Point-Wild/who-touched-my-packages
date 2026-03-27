---
title: Provenance Verification
description: Learn how package provenance verification works and why it matters for supply chain security
---

Package provenance verification is an automatic security feature that checks whether your dependencies have cryptographic attestations proving their build integrity and origin.

## What is Provenance?

Provenance attestations provide cryptographic proof that:
- The package was built from specific source code
- The build process is reproducible and auditable  
- The package hasn't been tampered with after building

This is part of the [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) framework for improving software supply chain security.

## How It Works

### npm Packages

For each npm package, the tool:
1. Queries the npm registry API for the specific version
2. Checks for SLSA provenance attestations in `dist.attestations.provenance`
3. Verifies the presence of `predicateType: "https://slsa.dev/provenance/v1"`

**Important:** Old PGP signatures (`dist.signatures`) are **not** considered provenance. Many packages have PGP signatures but lack modern SLSA attestations.

**Example of a package with provenance:**
```json
{
  "dist": {
    "attestations": {
      "url": "https://registry.npmjs.org/-/npm/v1/attestations/socket.io@4.8.1",
      "provenance": {
        "predicateType": "https://slsa.dev/provenance/v1"
      }
    }
  }
}
```

### PyPI Packages

For Python packages, the tool:
1. Queries PyPI's JSON API for the package version
2. Checks for [PEP 740](https://peps.python.org/pep-0740/) attestations
3. Looks for attestation objects in the release metadata's `urls` array

**Note:** PEP 740 attestations are relatively new to PyPI and adoption is still growing.

## What You'll See

### Terminal Output

After scanning, you'll see a provenance verification summary:

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
  • ora@8.2.0
  • picocolors@1.1.1
  ... and 21 more

════════════════════════════════════════════════════════════
```

### HTML Report

The Dependencies tab includes a **Provenance** column showing:

- **✓ Enabled** (green) - Package has SLSA provenance attestations
- **⚠️ Missing** (red) - No provenance attestations found
- **Unknown** (gray) - Verification failed or package not checked

You can filter the table using the **"No provenance only"** checkbox to focus on packages lacking attestations.

### CSV Export

When exporting dependencies to CSV, the provenance status is included as a column with values:
- `Enabled`
- `Missing`
- `Unknown`

## Interpreting Results

### Packages WITH Provenance ✓

These packages have been built with modern supply chain security practices:
- Built using GitHub Actions or similar CI/CD with provenance support
- Cryptographically signed build attestations
- Traceable back to source code

**Examples:** Many packages from organizations like Langchain, Socket.io, and others using npm provenance.

### Packages WITHOUT Provenance ⚠️

**This does not mean the package is malicious!** It simply means:
- The package was published before provenance was available
- The maintainer hasn't enabled provenance in their build process
- The package uses a build system that doesn't support attestations yet

Most npm packages currently lack provenance as it's a relatively new feature (introduced in 2023).

### Unknown Status

This typically means:
- Network error when querying the registry
- Package version not found in the registry
- API rate limiting

## Debug Mode

Enable detailed logging to see exactly what's being checked:

```bash
WTMP_DEBUG=1 wtmp --path /your/project
```

This will output detailed information like:

```
[Provenance] Verifying 45 packages...
[Provenance] NPM: 45, Python: 0
[Provenance] Fetching NPM: https://registry.npmjs.org/@clack%2Fprompts/1.1.0
[Provenance] NPM response for @clack/prompts: {"version":"1.1.0","hasAttestations":true,"hasProvenance":true,"predicateType":"https://slsa.dev/provenance/v1"}
[Provenance] NPM @clack/prompts@1.1.0: hasProvenance=true
```

## Best Practices

1. **Monitor trends** - Track which of your dependencies have provenance over time
2. **Prefer packages with provenance** - When choosing between similar packages, consider provenance as a factor
3. **Don't panic** - Lack of provenance doesn't mean a package is unsafe, especially for well-established packages
4. **Encourage adoption** - Consider opening issues or PRs to help maintainers enable provenance

## Enabling Provenance for Your Packages

If you maintain npm packages, you can enable provenance by:

1. Publishing from GitHub Actions
2. Using `npm publish --provenance`
3. Ensuring your workflow has the necessary permissions

See [npm's provenance documentation](https://docs.npmjs.com/generating-provenance-statements) for details.

## Technical Details

### Implementation

The verification is performed by:
- `src/auditor/package-verifier.ts` - Core verification logic
- Runs after dependency tree building
- Results are applied to both terminal and HTML report data

### API Endpoints

- **npm:** `https://registry.npmjs.org/{package}/{version}`
- **PyPI:** `https://pypi.org/pypi/{package}/{version}/json`

### Performance

- Verification runs in parallel for all packages
- Typically adds 2-5 seconds to scan time
- Failed verifications don't block the scan
- Results are cached in memory during the scan

## Related Resources

- [SLSA Framework](https://slsa.dev/)
- [npm Provenance Documentation](https://docs.npmjs.com/generating-provenance-statements)
- [PEP 740 - PyPI Attestations](https://peps.python.org/pep-0740/)
- [Sigstore](https://www.sigstore.dev/) - The signing infrastructure used by npm
