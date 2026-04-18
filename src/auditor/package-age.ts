import { getCachedPublishedAt, registryFetchRaw } from '../scanner/registry-cache.js';
import type { Dependency } from '../scanner/types.js';
import type { Vulnerability } from './types.js';

export interface PackageAgeInfo {
  publishedAt: string;
  ageDays: number;
}

function escapeGoModulePath(modulePath: string): string {
  return modulePath
    .split('/')
    .map(segment =>
      encodeURIComponent(segment.replace(/[A-Z]/g, match => `!${match.toLowerCase()}`))
    )
    .join('/');
}

async function fetchVersionPublishedAt(
  ecosystem: Dependency['ecosystem'],
  name: string,
  version: string
): Promise<string | null> {
  // Reuse data already pulled by the dependency-tree resolver when possible
  // to avoid redundant registry round-trips.
  const cached = getCachedPublishedAt(ecosystem, name, version);
  if (cached) return cached;

  try {
    switch (ecosystem) {
      case 'npm': {
        const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
        const result = await registryFetchRaw(url);
        if (!result.ok) return null;
        const meta = result.data as { time?: Record<string, string> };
        return meta.time?.[version] ?? null;
      }
      case 'pypi': {
        const url = `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;
        const result = await registryFetchRaw(url);
        if (!result.ok) return null;
        const data = result.data as { urls?: Array<{ upload_time_iso_8601?: string; upload_time?: string }> };
        let earliest: string | null = null;
        for (const file of data.urls ?? []) {
          const t = file.upload_time_iso_8601 ?? file.upload_time;
          if (t && (!earliest || t < earliest)) earliest = t;
        }
        return earliest;
      }
      case 'cargo': {
        const url = `https://crates.io/api/v1/crates/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
        const result = await registryFetchRaw(url);
        if (!result.ok) return null;
        const data = result.data as { version?: { created_at?: string } };
        return data.version?.created_at ?? null;
      }
      case 'go': {
        const url = `https://proxy.golang.org/${escapeGoModulePath(name)}/@v/${encodeURIComponent(version)}.info`;
        const result = await registryFetchRaw(url);
        if (!result.ok) return null;
        const data = result.data as { Time?: string };
        return data.Time ?? null;
      }
      case 'ruby': {
        const url = `https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`;
        const result = await registryFetchRaw(url);
        if (!result.ok) return null;
        const versions = result.data as Array<{ number?: string; created_at?: string; built_at?: string }>;
        const match = versions.find(v => String(v.number) === version);
        return match?.created_at ?? match?.built_at ?? null;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * Fetch version-specific publish dates for every unique (ecosystem,name,version)
 * referenced by a set of vulnerabilities. Returns a lookup keyed by
 * `${ecosystem}:${name}@${version}`.
 */
export async function fetchPackageAges(
  vulnerabilities: Vulnerability[],
  concurrency = 8
): Promise<Map<string, PackageAgeInfo>> {
  const unique = new Map<string, { ecosystem: Dependency['ecosystem']; name: string; version: string }>();
  for (const vuln of vulnerabilities) {
    if (!vuln.packageVersion) continue;
    const key = `${vuln.ecosystem}:${vuln.packageName}@${vuln.packageVersion}`;
    if (!unique.has(key)) {
      unique.set(key, { ecosystem: vuln.ecosystem, name: vuln.packageName, version: vuln.packageVersion });
    }
  }

  const entries = Array.from(unique.entries());
  const results = new Map<string, PackageAgeInfo>();
  const now = Date.now();

  let cursor = 0;
  const workers: Promise<void>[] = [];
  const workerCount = Math.min(concurrency, entries.length);
  for (let i = 0; i < workerCount; i++) {
    workers.push((async () => {
      while (true) {
        const idx = cursor++;
        if (idx >= entries.length) return;
        const [key, { ecosystem, name, version }] = entries[idx];
        const publishedAt = await fetchVersionPublishedAt(ecosystem, name, version);
        if (publishedAt) {
          const ts = new Date(publishedAt).getTime();
          if (!Number.isNaN(ts)) {
            results.set(key, {
              publishedAt,
              ageDays: Math.floor((now - ts) / 86_400_000),
            });
          }
        }
      }
    })());
  }
  await Promise.all(workers);
  return results;
}

export function applyPackageAges(
  vulnerabilities: Vulnerability[],
  ages: Map<string, PackageAgeInfo>
): void {
  for (const vuln of vulnerabilities) {
    const info = ages.get(`${vuln.ecosystem}:${vuln.packageName}@${vuln.packageVersion}`);
    if (info) {
      vuln.packagePublishedAt = info.publishedAt;
      vuln.packageAgeDays = info.ageDays;
    }
  }
}
