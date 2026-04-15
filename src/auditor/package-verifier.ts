import type { Dependency } from '../scanner/types.js';

// Enable debug logging
const DEBUG = process.env.WTMP_DEBUG === '1';

function log(...args: unknown[]) {
  if (DEBUG) {
    console.log('[Provenance]', ...args);
  }
}

export interface VerificationResult {
  packageName: string;
  version: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  hasProvenance: boolean;
  provenanceUrl?: string;
  error?: string;
}

/**
 * Verifies package provenance for NPM and Python packages.
 * For NPM: Checks npm registry for provenance attestation
 * For Python: Checks PyPI for attestations (PEP 740)
 */
export interface VerifyPackagesOptions {
  /** Maximum number of verification requests to run in parallel. Defaults to 10. */
  concurrency?: number;
}

export async function verifyPackages(
  dependencies: Dependency[],
  options: VerifyPackagesOptions = {},
): Promise<VerificationResult[]> {
  const concurrency = Math.max(1, options.concurrency ?? 10);

  log(`Verifying ${dependencies.length} packages (concurrency=${concurrency})...`);

  const npmDeps = dependencies.filter(d => d.ecosystem === 'npm');
  const pythonDeps = dependencies.filter(d => d.ecosystem === 'pypi');

  log(`NPM: ${npmDeps.length}, Python: ${pythonDeps.length}`);

  const tasks: Array<() => Promise<VerificationResult>> = [
    ...npmDeps.map(dep => async () => {
      try {
        const result = await verifyNpmPackage(dep.name, dep.version);
        log(`NPM ${dep.name}@${dep.version}: hasProvenance=${result.hasProvenance}`, result.error || '');
        return result;
      } catch (error) {
        log(`NPM ${dep.name}@${dep.version}: ERROR`, error);
        return {
          packageName: dep.name,
          version: dep.version,
          ecosystem: 'npm' as const,
          hasProvenance: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    }),
    ...pythonDeps.map(dep => async () => {
      try {
        const result = await verifyPythonPackage(dep.name, dep.version);
        log(`PyPI ${dep.name}@${dep.version}: hasProvenance=${result.hasProvenance}`, result.error || '');
        return result;
      } catch (error) {
        log(`PyPI ${dep.name}@${dep.version}: ERROR`, error);
        return {
          packageName: dep.name,
          version: dep.version,
          ecosystem: 'pypi' as const,
          hasProvenance: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    }),
  ];

  return runWithConcurrency(tasks, concurrency);
}

/**
 * Runs the given async tasks with at most `concurrency` in flight at a time.
 * Results are returned in the same order as the input tasks.
 */
async function runWithConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  concurrency: number,
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let nextIndex = 0;

  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= tasks.length) return;
      results[index] = await tasks[index]();
    }
  });

  await Promise.all(workers);
  return results;
}

/**
 * Verifies NPM package provenance using npm registry API.
 * Checks for attestations in the package metadata.
 */
async function verifyNpmPackage(name: string, version: string): Promise<VerificationResult> {
  try {
    // Handle scoped packages
    const encodedName = name.startsWith('@')
      ? `@${encodeURIComponent(name.slice(1))}`
      : encodeURIComponent(name);

    // Try the version as-is first
    let url = `https://registry.npmjs.org/${encodedName}/${version}`;

    // If version looks like a range or is '*', we can't query a specific version
    if (version === '*' || version.startsWith('^') || version.startsWith('~') || version.includes('>') || version.includes('<')) {
      // Get the latest version info
      url = `https://registry.npmjs.org/${encodedName}/latest`;
    }

    log(`Fetching NPM: ${url}`);

    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      log(`NPM HTTP error: ${response.status} for ${name}@${version}`);
      return {
        packageName: name,
        version,
        ecosystem: 'npm',
        hasProvenance: false,
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json() as {
      version?: string;
      dist?: {
        attestations?: {
          provenance?: {
            predicateType?: string;
          };
          url?: string;
        } | null;
      };
    };

    log(`NPM response for ${name}:`, JSON.stringify({
      version: data.version,
      hasAttestations: !!data.dist?.attestations,
      hasProvenance: !!data.dist?.attestations?.provenance,
      predicateType: data.dist?.attestations?.provenance?.predicateType,
    }));

    // Check for provenance attestation (SLSA provenance)
    // Only packages with dist.attestations.provenance.predicateType have real provenance
    const hasProvenance = !!(
      data.dist?.attestations?.provenance?.predicateType
    );

    const provenanceUrl = data.dist?.attestations?.url;

    return {
      packageName: name,
      version,
      ecosystem: 'npm',
      hasProvenance,
      provenanceUrl,
    };
  } catch (error) {
    log(`NPM exception for ${name}@${version}:`, error);
    return {
      packageName: name,
      version,
      ecosystem: 'npm',
      hasProvenance: false,
      error: error instanceof Error ? error.message : 'Failed to verify',
    };
  }
}

/**
 * Verifies Python package provenance using PyPI API.
 * Checks for attestations (PEP 740) in the release metadata.
 */
async function verifyPythonPackage(name: string, version: string): Promise<VerificationResult> {
  try {
    // Normalize package name per PEP 503
    const normalizedName = name.toLowerCase().replace(/[-_.]+/g, '-');

    // If version is '*', we can't query a specific version
    let url: string;
    if (version === '*' || version.startsWith('>') || version.startsWith('<')) {
      url = `https://pypi.org/pypi/${normalizedName}/json`;
    } else {
      url = `https://pypi.org/pypi/${normalizedName}/${version}/json`;
    }

    log(`Fetching PyPI: ${url}`);

    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      log(`PyPI HTTP error: ${response.status} for ${name}@${version}`);
      return {
        packageName: name,
        version,
        ecosystem: 'pypi',
        hasProvenance: false,
        error: `HTTP ${response.status}`,
      };
    }

    const data = await response.json() as {
      info?: { version?: string };
      urls?: Array<{
        attestations?: {
          provenance?: { url?: string };
        };
      }>;
    };

    log(`PyPI response for ${name}:`, JSON.stringify({
      version: data.info?.version,
      urlCount: data.urls?.length,
      hasAttestations: data.urls?.some(u => !!u.attestations),
    }));

    // Check for attestations in the release
    // PEP 740 defines attestations that are stored in the release metadata
    const urls = data.urls || [];
    let hasProvenance = false;
    let provenanceUrl: string | undefined;

    for (const artifact of urls) {
      if (artifact.attestations) {
        hasProvenance = true;
        // Find the attestation URL or provenance information
        if (artifact.attestations.provenance?.url) {
          provenanceUrl = artifact.attestations.provenance.url;
        }
        break;
      }
    }

    return {
      packageName: name,
      version,
      ecosystem: 'pypi',
      hasProvenance,
      provenanceUrl,
    };
  } catch (error) {
    log(`PyPI exception for ${name}@${version}:`, error);
    return {
      packageName: name,
      version,
      ecosystem: 'pypi',
      hasProvenance: false,
      error: error instanceof Error ? error.message : 'Failed to verify',
    };
  }
}

/**
 * Applies verification results to dependencies, mutating them in place.
 */
export function applyVerificationResults(
  dependencies: Dependency[],
  results: VerificationResult[]
): void {
  const resultMap = new Map(
    results.map(r => [`${r.packageName}@${r.version}`, r])
  );

  log(`Applying ${results.length} results to ${dependencies.length} dependencies`);

  let appliedCount = 0;
  for (const dep of dependencies) {
    const key = `${dep.name}@${dep.version}`;
    const result = resultMap.get(key);
    if (result) {
      dep.provenance = result.hasProvenance;
      appliedCount++;
      log(`Applied ${dep.name}@${dep.version}: provenance=${result.hasProvenance}`);
    } else {
      log(`No result found for ${key}`);
    }
  }

  log(`Applied results to ${appliedCount} dependencies`);
}
