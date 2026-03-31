import type { Dependency } from '../../scanner/types.js';
import type { PackageFetchError, PackageMetadata, PackageSource } from '../types.js';
import { fetchCratesMetadata, fetchCratesSource } from '../registry/crates.js';
import { fetchGoMetadata, fetchGoSource } from '../registry/golang.js';
import { fetchNpmMetadata, fetchNpmSource } from '../registry/npm.js';
import { fetchPypiMetadata, fetchPypiSource } from '../registry/pypi.js';
import { describeFetchError, pMap, depKey } from '../utils.js';

type SupplyChainDependency = Dependency & {
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
};

function isSupplyChainDependency(dep: Dependency): dep is SupplyChainDependency {
  return dep.ecosystem === 'npm' || dep.ecosystem === 'pypi' || dep.ecosystem === 'cargo' || dep.ecosystem === 'go';
}

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
  fetchErrors: PackageFetchError[];
}> {
  const metadata = new Map<string, PackageMetadata>();
  const sources = new Map<string, PackageSource>();
  const fetchErrors: PackageFetchError[] = [];

  // Deduplicate by name+ecosystem (same package may appear in multiple lockfiles)
  const unique = new Map<string, Dependency>();
  for (const dep of dependencies) {
    const key = depKey(dep.ecosystem, dep.name);
    if (!unique.has(key)) unique.set(key, dep);
  }

  let deps = Array.from(unique.values()).filter(isSupplyChainDependency);

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
        const meta = dep.ecosystem === 'npm'
          ? await fetchNpmMetadata(dep.name)
          : dep.ecosystem === 'pypi'
            ? await fetchPypiMetadata(dep.name)
            : dep.ecosystem === 'cargo'
              ? await fetchCratesMetadata(dep.name)
              : await fetchGoMetadata(dep.name);

        if (meta) {
          metadata.set(key, meta);
        }
      } catch (error) {
        const { message, statusCode } = describeFetchError(error);
        fetchErrors.push({
          packageName: dep.name,
          packageVersion: dep.version,
          ecosystem: dep.ecosystem,
          stage: 'metadata',
          message,
          statusCode,
        });
        done++;
        onProgress?.(done, deps.length);
        return;
      }

      try {
        const meta = metadata.get(key);
        if (!meta) {
          done++;
          onProgress?.(done, deps.length);
          return;
        }

        const source = dep.ecosystem === 'npm'
          ? await fetchNpmSource(dep.name, dep.version, meta.previousVersion)
          : dep.ecosystem === 'pypi'
            ? await fetchPypiSource(dep.name, dep.version)
            : dep.ecosystem === 'cargo'
              ? await fetchCratesSource(dep.name, dep.version)
              : await fetchGoSource(dep.name, dep.version);

        if (source) {
          sources.set(key, source);
        } else {
          fetchErrors.push({
            packageName: dep.name,
            packageVersion: dep.version,
            ecosystem: dep.ecosystem,
            stage: 'source',
            message: `No source archive available for ${dep.name}@${dep.version}`,
          });
        }
      } catch (error) {
        const { message, statusCode } = describeFetchError(error);
        fetchErrors.push({
          packageName: dep.name,
          packageVersion: dep.version,
          ecosystem: dep.ecosystem,
          stage: 'source',
          message,
          statusCode,
        });
      }

      done++;
      onProgress?.(done, deps.length);
    },
    concurrency
  );

  return { metadata, sources, fetchErrors };
}
