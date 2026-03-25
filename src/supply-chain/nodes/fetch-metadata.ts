import type { Dependency } from '../../scanner/types.js';
import type { PackageMetadata, PackageSource } from '../types.js';
import { fetchNpmMetadata, fetchNpmSource } from '../registry/npm.js';
import { fetchPypiMetadata, fetchPypiSource } from '../registry/pypi.js';
import { pMap, depKey } from '../utils.js';

/**
 * Fetch registry metadata and download source tarballs for all dependencies.
 */
export async function fetchMetadataNode(
  dependencies: Dependency[],
  concurrency: number = 6,
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

  const deps = Array.from(unique.values());
  let done = 0;

  await pMap(
    deps,
    async (dep) => {
      const key = depKey(dep.ecosystem, dep.name);

      try {
        // Fetch metadata and source in parallel
        const [meta, source] = await Promise.all([
          dep.ecosystem === 'npm'
            ? fetchNpmMetadata(dep.name)
            : fetchPypiMetadata(dep.name),
          dep.ecosystem === 'npm'
            ? fetchNpmSource(dep.name, dep.version)
            : fetchPypiSource(dep.name, dep.version),
        ]);

        if (meta) metadata.set(key, meta);
        if (source) sources.set(key, source);
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
