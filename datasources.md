# Vulnerability Data Sources

This document lists all vulnerability data sources that can be integrated into **who-touched-my-packages**.

## Currently Implemented

### 1. OSV (Open Source Vulnerabilities)
- **Provider**: Google
- **URL**: https://osv.dev
- **API**: https://api.osv.dev/v1/querybatch
- **License**: https://www.apache.org/licenses/LICENSE-2.0
- **Coverage**: npm, PyPI, Go, Rust, Maven, NuGet, and more
- **Rate Limits**: No authentication required, generous rate limits
- **Cost**: Free
- **Data Quality**: High - aggregates data from multiple sources
- **Implementation Status**: ✅ Implemented

**Features**:
- Batch query support (multiple packages at once)
- Version-specific vulnerability checks
- CVSS scores and severity ratings
- Detailed affected version ranges
- Fix version information

### 2. GitHub Advisory Database
- **Provider**: GitHub
- **URL**: https://github.com/advisories
- **API**: https://api.github.com/graphql
- **License**: https://creativecommons.org/licenses/by/4.0/
- **Coverage**: npm, PyPI, Maven, NuGet, Composer, Go, Rust
- **Rate Limits**: 5,000 requests/hour (authenticated), 60/hour (unauthenticated)
- **Authentication**: Optional GITHUB_TOKEN environment variable
- **Cost**: Free
- **Data Quality**: High - curated by GitHub security team
- **Implementation Status**: ✅ Implemented

**Features**:
- GraphQL API for flexible queries
- CVSS v3 scores
- CWE classifications
- Detailed descriptions and references
- First patched version information

## Planned Data Sources

### 3. npm Audit API
- **Provider**: npm
- **URL**: https://www.npmjs.com
- **API**: https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
- **Coverage**: npm packages only
- **Rate Limits**: Unknown
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- Official npm vulnerability database
- Most up-to-date for npm ecosystem
- Includes severity ratings and recommendations

### 4. Snyk Vulnerability Database
- **Provider**: Snyk
- **URL**: https://snyk.io
- **API**: https://api.snyk.io/v1/test
- **Coverage**: npm, PyPI, Maven, NuGet, Ruby, Go, Docker
- **Rate Limits**: Varies by plan
- **Authentication**: API token required
- **Cost**: Free tier available, paid plans for more features
- **Implementation Status**: 📋 Planned

**Benefits**:
- Comprehensive vulnerability database
- Includes license compliance checks
- Remediation advice
- Container scanning support

### 5. Sonatype OSS Index
- **Provider**: Sonatype
- **URL**: https://ossindex.sonatype.org
- **API**: https://ossindex.sonatype.org/api/v3/component-report
- **Coverage**: npm, PyPI, Maven, NuGet, Composer, Go, Ruby
- **Rate Limits**: 128 requests/day (unauthenticated), higher with account
- **Authentication**: Optional
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- Free and no authentication required for basic use
- Good coverage across ecosystems
- Component quality scores

### 6. PyPI Safety DB
- **Provider**: PyUp.io
- **URL**: https://github.com/pyupio/safety-db
- **API**: Git repository (JSON files)
- **Coverage**: Python/PyPI only
- **Rate Limits**: None (static data)
- **Cost**: Free (open source)
- **Implementation Status**: 📋 Planned

**Benefits**:
- Python-specific vulnerability database
- Regularly updated
- Can be used offline

### 7. National Vulnerability Database (NVD)
- **Provider**: NIST
- **URL**: https://nvd.nist.gov
- **API**: https://services.nvd.nist.gov/rest/json/cves/2.0
- **Coverage**: All software (CVE database)
- **Rate Limits**: 5 requests/30 seconds (unauthenticated), 50/30s (with API key)
- **Authentication**: Optional API key (recommended)
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- Authoritative CVE database maintained by NIST
- Comprehensive CVSS v2 and v3 scoring
- Detailed technical information and references
- CWE classifications
- CPE (Common Platform Enumeration) matching
- CISA KEV catalog integration

### 8. CIRCL Vulnerability-Lookup
- **Provider**: CIRCL (Computer Incident Response Center Luxembourg)
- **URL**: https://vulnerability.circl.lu
- **API**: https://vulnerability.circl.lu/api
- **Coverage**: Multi-source aggregator (NVD, GitHub, PySec, CISA, etc.)
- **Rate Limits**: None specified (public service)
- **Authentication**: Not required for public API
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- Aggregates data from 15+ sources including NVD, GitHub, PySec, CISA KEV
- No authentication required
- OpenAPI documented
- RSS/Atom feeds available
- EPSS (Exploit Prediction Scoring System) integration
- Supports CVD (Coordinated Vulnerability Disclosure)
- Includes IoT vulnerabilities from VARIoT database

**Data Sources Included**:
- NIST NVD, CISA KEV
- PySec, CVEProject, Cloud Security Alliance GSD
- OpenSSF Malicious Packages
- CSAF feeds (CERT-Bund, Cisco, Red Hat, Siemens, etc.)
- JVN iPedia (Japan), Tailscale bulletins
- CWE and CAPEC databases

### 9. deps.dev API
- **Provider**: Google Open Source Security Team
- **URL**: https://deps.dev
- **API**: https://api.deps.dev/v3alpha
- **Coverage**: npm, Maven, PyPI, Go, Cargo (Rust)
- **Rate Limits**: None specified (globally replicated, highly available)
- **Authentication**: Not required
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- No API key required - simple unauthenticated HTTPS API
- Globally replicated and highly available
- Real dependency graph resolution (transitive dependencies)
- Hash-based queries for vendored dependencies
- Advisory data from OSV database
- Package metadata and licensing information
- Ecosystem-wide impact analysis
- Returns JSON objects

**Unique Features**:
- Query by package hash to detect hidden vulnerable dependencies
- Full transitive dependency graphs
- Version-specific advisory lookups
- Supports multiple ecosystems in single API

### 10. CISA KEV Catalog
- **Provider**: CISA (Cybersecurity and Infrastructure Security Agency)
- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **API**: Direct JSON/CSV download
- **API Endpoints**:
  - JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - CSV: https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
- **Coverage**: Known exploited vulnerabilities (all software)
- **Rate Limits**: None (static file download)
- **Authentication**: Not required
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- Authoritative list of actively exploited vulnerabilities
- Required for federal agencies under BOD 22-01
- Includes remediation due dates
- High-priority vulnerabilities for patching
- Simple JSON/CSV format
- Can be cached locally
- Updated regularly

**Data Fields**:
- CVE ID, vendor/project, product, vulnerability name
- Date added to catalog
- Short description
- Required action
- Due date for remediation
- Known ransomware campaign usage

### 11. Retire.js
- **Provider**: Open source community
- **URL**: https://retirejs.github.io/retire.js/
- **API**: JSON repository
- **Coverage**: JavaScript libraries (frontend)
- **Rate Limits**: None (static data)
- **Cost**: Free
- **Implementation Status**: 📋 Planned

**Benefits**:
- Focuses on frontend JavaScript vulnerabilities
- Detects outdated libraries
- Can be used offline

## Integration Architecture

The tool uses a pluggable data source architecture:

```typescript
abstract class DataSource {
  abstract name: string;
  abstract checkVulnerabilities(dependencies: Dependency[]): Promise<Vulnerability[]>;
}
```

Each data source:
1. Implements the `DataSource` abstract class
2. Handles its own API authentication and rate limiting
3. Transforms responses to a common `Vulnerability` format
4. Includes retry logic for network failures

Results from multiple sources are:
- Merged together
- Deduplicated by vulnerability ID
- Sorted by severity

## Adding New Data Sources

To add a new data source:

1. Create a new file in `src/auditor/datasources/`
2. Extend the `DataSource` abstract class
3. Implement the `checkVulnerabilities` method
4. Export from `src/auditor/datasources/index.ts`
5. Add to the data sources array in `src/index.ts`

Example:
```typescript
export class MyDataSource extends DataSource {
  name = 'MySource';
  
  async checkVulnerabilities(dependencies: Dependency[]): Promise<Vulnerability[]> {
    // Implementation
  }
}
```

## Environment Variables

- `GITHUB_TOKEN`: Optional GitHub personal access token for higher rate limits
- `SNYK_TOKEN`: Required for Snyk integration (when implemented)
- `NVD_API_KEY`: Optional NVD API key for higher rate limits (when implemented)

## Rate Limiting Strategy

The tool implements:
- Automatic retry with exponential backoff
- Respect for `Retry-After` headers
- Batch requests where supported
- Graceful degradation (continues if one source fails)
