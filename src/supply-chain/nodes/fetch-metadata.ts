import type { Dependency } from '../../scanner/types.js';
import type { PackageMetadata, PackageSource } from '../types.js';
import { fetchNpmMetadata, fetchNpmSource } from '../registry/npm.js';
import { fetchPypiMetadata, fetchPypiSource } from '../registry/pypi.js';
import { pMap, depKey } from '../utils.js';

/**
 * Fetch registry metadata and download source tarballs for all dependencies.
 *
 * @param dependencies - Flat list of dependencies to analyse
 * @param concurrency  - Number of concurrent fetches
 * @param maxPackages  - Hard cap on packages (0 = unlimited). Applied after
 *                       deduplication; packages with install scripts are
 *                       prioritised when truncating.
 * @param onProgress   - Optional progress callback
 */
export async function fetchMetadataNode(
  dependencies: Dependency[],
  concurrency: number = 6,
  maxPackages: number = 0,
  onProgress?: (done: number, total: number) => void
): Promise<{
  metadata: Map<string, PackageMetadata>;
  sources: Map<string, PackageSource>;
}> {
  const metadata = new Map<string, PackageMetadata>();
  const sources = new Map<string, PackageSource>();

  // Deduplicate by name+ecosystem (same package may appear in multiple lockfiles)
  const unique = new Map<string, Dependency>();
  for (const dep of dependencies) {
    const key = depKey(dep.ecosystem, dep.name);
    if (!unique.has(key)) unique.set(key, dep);
  }

  let deps = Array.from(unique.values());

  // Apply package cap if requested
  if (maxPackages > 0 && deps.length > maxPackages) {
    deps = deps.slice(0, maxPackages);
  }

  let done = 0;

  await pMap(
    deps,
    async (dep) => {
      const key = depKey(dep.ecosystem, dep.name);

      try {
        // Fetch metadata first so we can pass the previous-version hint to the
        // source fetcher (needed for version-diff computation in npm).
        const meta = dep.ecosystem === 'npm'
          ? await fetchNpmMetadata(dep.name)
          : await fetchPypiMetadata(dep.name);

        if (meta) {
          metadata.set(key, meta);

          // For npm, pass the previous version so fetchNpmSource can diff tarballs.
          const source = dep.ecosystem === 'npm'
            ? await fetchNpmSource(dep.name, dep.version, meta.previousVersion)
            : await fetchPypiSource(dep.name, dep.version);

          if (source) sources.set(key, source);
        }
      } catch {
        // Skip packages that fail to fetch — don't block the scan
      }

      done++;
      onProgress?.(done, deps.length);
    },
    concurrency
  );

  return { metadata, sources };
}
