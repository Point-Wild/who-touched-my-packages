/**
 * Shared package-registry caches used by both the dependency-tree resolver
 * and downstream consumers (e.g. package-age). Extracting them here avoids
 * redundant network fetches when the same package data has already been
 * pulled by another stage of the pipeline.
 */

export type RegistryEcosystem = 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';

export const NPM_REGISTRY_CACHE = new Map<string, any>();
export const PYPI_REGISTRY_CACHE = new Map<string, any>();
export const CRATES_REGISTRY_CACHE = new Map<string, any>();
export const GO_PROXY_CACHE = new Map<string, any>();
export const RUBYGEMS_CACHE = new Map<string, any>();

/**
 * Attempt to extract an ISO publish timestamp for a specific (name, version)
 * from any registry data that has already been cached by the resolver.
 *
 * Returns null when no cached entry provides the info; callers should fall
 * back to a direct registry fetch in that case.
 */
export function getCachedPublishedAt(
  ecosystem: RegistryEcosystem,
  name: string,
  version: string,
): string | null {
  switch (ecosystem) {
    case 'pypi':
      return extractPypiPublishedAt(name, version);
    case 'cargo':
      return extractCargoPublishedAt(name, version);
    case 'go':
      return extractGoPublishedAt(name, version);
    case 'ruby':
      return extractRubyPublishedAt(name, version);
    case 'npm':
      // Resolver caches the single-version manifest, which does not include
      // the `time` map needed for per-version publish dates.
      return null;
    default:
      return null;
  }
}

function extractPypiPublishedAt(name: string, version: string): string | null {
  // Resolver cache keys are `${name}@${versionSpec}`. Scan entries matching
  // this name whose cached payload corresponds to the requested version.
  const namePrefix = `${name}@`;
  for (const [key, data] of PYPI_REGISTRY_CACHE) {
    if (!key.startsWith(namePrefix)) continue;
    if (data?.info?.version !== version) continue;

    let earliest: string | null = null;
    for (const file of (data.urls ?? []) as Array<{ upload_time_iso_8601?: string; upload_time?: string }>) {
      const t = file.upload_time_iso_8601 ?? file.upload_time;
      if (t && (!earliest || t < earliest)) earliest = t;
    }
    if (earliest) return earliest;
  }
  return null;
}

function extractCargoPublishedAt(name: string, version: string): string | null {
  // Resolver caches `/crates/${name}` responses which include every version's
  // `created_at`, so any entry for this crate will contain what we need.
  const namePrefix = `${name}@`;
  for (const [key, data] of CRATES_REGISTRY_CACHE) {
    if (!key.startsWith(namePrefix)) continue;
    const versions = data?.versions as Array<{ num?: string; created_at?: string }> | undefined;
    const match = versions?.find(v => v.num === version);
    if (match?.created_at) return match.created_at;
  }
  return null;
}

function extractGoPublishedAt(name: string, version: string): string | null {
  // Resolver caches `.info` responses which directly expose `.Time`.
  const namePrefix = `${name}@`;
  for (const [key, data] of GO_PROXY_CACHE) {
    if (!key.startsWith(namePrefix)) continue;
    const cachedVersion: string | undefined = data?.Version;
    if (!cachedVersion) continue;
    const normalized = cachedVersion.replace(/^v/, '');
    const requested = version.replace(/^v/, '');
    if (normalized === requested && typeof data?.Time === 'string') {
      return data.Time;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lookup / store helpers for supply-chain consumers.
//
// The resolver caches some of the same JSON documents that supply-chain
// registry modules would otherwise re-fetch. These helpers let supply-chain
// check the shared cache before issuing a network call, and populate it after
// its own fetches so later stages benefit too.
//
// Only the JSON manifest portion can be reused; binary tarball downloads are
// always re-issued because we don't keep them in memory.
// ---------------------------------------------------------------------------

/**
 * Look up an npm single-version manifest (shape of `/{name}/{version}`) that
 * any prior stage may have cached. Returns null when no entry matches.
 */
export function getCachedNpmVersionManifest(name: string, version: string): any | null {
  const namePrefix = `${name}@`;
  for (const [key, data] of NPM_REGISTRY_CACHE) {
    if (!key.startsWith(namePrefix)) continue;
    if (data?.version === version) return data;
  }
  return null;
}

export function setCachedNpmVersionManifest(name: string, version: string, data: any): void {
  NPM_REGISTRY_CACHE.set(`${name}@${version}`, data);
}

/**
 * Look up a PyPI release document (shape of `/{name}/{version}/json` or
 * `/{name}/json`) where `info.version` matches the requested version.
 */
export function getCachedPypiRelease(name: string, version: string): any | null {
  const namePrefix = `${name}@`;
  for (const [key, data] of PYPI_REGISTRY_CACHE) {
    if (!key.startsWith(namePrefix)) continue;
    if (data?.info?.version === version) return data;
  }
  return null;
}

export function setCachedPypiRelease(name: string, version: string, data: any): void {
  PYPI_REGISTRY_CACHE.set(`${name}@${version}`, data);
}

/**
 * Look up the full crates.io document for a crate (shape of `/crates/{name}`),
 * independent of version — the resolver always fetches the full document.
 */
export function getCachedCratesDoc(name: string): any | null {
  const namePrefix = `${name}@`;
  for (const [key, data] of CRATES_REGISTRY_CACHE) {
    if (key.startsWith(namePrefix) && data?.crate) return data;
  }
  return null;
}

export function setCachedCratesDoc(name: string, data: any): void {
  CRATES_REGISTRY_CACHE.set(`${name}@*`, data);
}

function extractRubyPublishedAt(name: string, version: string): string | null {
  const namePrefix = `${name}@`;
  for (const [key, data] of RUBYGEMS_CACHE) {
    if (!key.startsWith(namePrefix)) continue;
    if (data?.version === version || data?.number === version) {
      const ts = data?.created_at ?? data?.built_at;
      if (typeof ts === 'string') return ts;
    }
  }
  return null;
}
