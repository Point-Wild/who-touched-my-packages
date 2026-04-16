/**
 * Shared package-registry caches used by both the dependency-tree resolver
 * and downstream consumers (e.g. package-age). Extracting them here avoids
 * redundant network fetches when the same package data has already been
 * pulled by another stage of the pipeline.
 *
 * Two cache layers:
 *   L1 — URL-keyed: deduplicates identical HTTP requests across all pipeline
 *         stages. Any JSON or text GET to a registry URL is served from here
 *         on the second request. Binary downloads (tarballs) bypass L1.
 *   L2 — Semantic: the per-ecosystem Maps (NPM_REGISTRY_CACHE, etc.) that
 *         allow cross-version / cross-endpoint lookups (e.g. extracting a
 *         publish date from a full-package doc that was fetched for a
 *         different purpose).
 */

// ---------------------------------------------------------------------------
// L1 cache — URL-keyed
// ---------------------------------------------------------------------------

const DEBUG = process.env.WTMP_DEBUG === '1';

let cacheEnabled = true;

/** Disable or enable the L1 URL cache globally. */
export function setCacheEnabled(enabled: boolean): void {
  cacheEnabled = enabled;
  if (!enabled) {
    URL_JSON_CACHE.clear();
    URL_TEXT_CACHE.clear();
    INFLIGHT_JSON.clear();
    INFLIGHT_TEXT.clear();
    INFLIGHT_RAW.clear();
    log('L1 cache DISABLED');
  }
}

function log(...args: unknown[]) {
  if (DEBUG) {
    console.log('[RegistryCache]', ...args);
  }
}

/** Sentinel stored in URL_JSON_CACHE for URLs that returned non-OK. */
const NEGATIVE_HIT = Symbol('NEGATIVE_HIT');

/** Cached JSON responses keyed by the request URL. */
const URL_JSON_CACHE = new Map<string, any>();

/** Cached text responses keyed by the request URL. */
const URL_TEXT_CACHE = new Map<string, string>();

/**
 * In-flight request dedup: if two callers ask for the same URL before the
 * first one resolves, the second one piggy-backs on the same promise instead
 * of opening a new connection.
 */
const INFLIGHT_JSON = new Map<string, Promise<any>>();
const INFLIGHT_TEXT = new Map<string, Promise<string | null>>();

/**
 * Fetch a JSON registry endpoint, returning the cached result when available.
 *
 * Usage: drop-in replacement for `fetch(url).then(r => r.json())`.
 * Returns the parsed JSON body, or throws on non-OK responses.
 *
 * **Binary downloads (tarballs, .crate, .gem, .zip) must NOT use this** —
 * call native `fetch()` directly for those.
 */
export async function registryFetchJson<T = any>(
  url: string,
  init?: RequestInit,
): Promise<T> {
  if (cacheEnabled) {
    const cached = URL_JSON_CACHE.get(url);
    if (cached === NEGATIVE_HIT) {
      log('L1 HIT (json, negative)', url);
      throw Object.assign(new Error(`HTTP 404 for ${url} (cached)`), { status: 404 });
    }
    if (cached !== undefined) {
      log('L1 HIT (json)', url);
      return cached as T;
    }

    const inflight = INFLIGHT_JSON.get(url);
    if (inflight) {
      log('L1 DEDUP (json)', url);
      return inflight as Promise<T>;
    }
  }

  log(cacheEnabled ? 'L1 MISS (json)' : 'L1 BYPASS (json)', url);
  const promise = (async () => {
    const res = await fetch(url, init);
    if (!res.ok) {
      log('L1 FETCH FAIL', res.status, url);
      if (cacheEnabled) URL_JSON_CACHE.set(url, NEGATIVE_HIT);
      INFLIGHT_JSON.delete(url);
      throw Object.assign(new Error(`HTTP ${res.status} for ${url}`), { status: res.status });
    }
    const data = await res.json();
    if (cacheEnabled) URL_JSON_CACHE.set(url, data);
    INFLIGHT_JSON.delete(url);
    log('L1 STORED (json)', url);
    return data;
  })();

  if (cacheEnabled) INFLIGHT_JSON.set(url, promise);
  return promise as Promise<T>;
}

/**
 * Like `registryFetchJson` but for endpoints that return plain text
 * (e.g. Go proxy `.mod` files, version lists).
 *
 * Returns `null` on non-OK responses instead of throwing.
 */
export async function registryFetchText(
  url: string,
  init?: RequestInit,
): Promise<string | null> {
  if (cacheEnabled) {
    const cached = URL_TEXT_CACHE.get(url);
    if (cached !== undefined) {
      log('L1 HIT (text)', url);
      return cached;
    }

    const inflight = INFLIGHT_TEXT.get(url);
    if (inflight) {
      log('L1 DEDUP (text)', url);
      return inflight;
    }
  }

  log(cacheEnabled ? 'L1 MISS (text)' : 'L1 BYPASS (text)', url);
  const promise = (async () => {
    const res = await fetch(url, init);
    INFLIGHT_TEXT.delete(url);
    if (!res.ok) {
      log('L1 FETCH FAIL', res.status, url);
      return null;
    }
    const text = await res.text();
    if (cacheEnabled) URL_TEXT_CACHE.set(url, text);
    log('L1 STORED (text)', url);
    return text;
  })();

  if (cacheEnabled) INFLIGHT_TEXT.set(url, promise);
  return promise;
}

/**
 * Fetch that returns the raw Response (for non-OK status checking by caller).
 * Still deduplicates at the URL level by caching the parsed JSON body.
 * Returns `{ ok, status, data }` so callers can branch on status.
 */
type RawResult = { ok: true; status: number; data: any } | { ok: false; status: number; data: null };
const INFLIGHT_RAW = new Map<string, Promise<RawResult>>();

export async function registryFetchRaw(
  url: string,
  init?: RequestInit,
): Promise<RawResult> {
  if (cacheEnabled) {
    const cached = URL_JSON_CACHE.get(url);
    if (cached === NEGATIVE_HIT) {
      log('L1 HIT (raw, negative)', url);
      return { ok: false, status: 404, data: null };
    }
    if (cached !== undefined) {
      log('L1 HIT (raw)', url);
      return { ok: true, status: 200, data: cached };
    }

    const inflight = INFLIGHT_RAW.get(url);
    if (inflight) {
      log('L1 DEDUP (raw)', url);
      return inflight;
    }
  }

  log(cacheEnabled ? 'L1 MISS (raw)' : 'L1 BYPASS (raw)', url);
  const promise = (async (): Promise<RawResult> => {
    const res = await fetch(url, init);
    INFLIGHT_RAW.delete(url);
    if (!res.ok) {
      log('L1 FETCH FAIL', res.status, url);
      if (cacheEnabled) URL_JSON_CACHE.set(url, NEGATIVE_HIT);
      return { ok: false, status: res.status, data: null };
    }

    let data: any;
    try {
      data = await res.json();
    } catch {
      log('L1 JSON PARSE FAIL', url);
      if (cacheEnabled) URL_JSON_CACHE.set(url, NEGATIVE_HIT);
      return { ok: false, status: res.status, data: null };
    }
    if (cacheEnabled) URL_JSON_CACHE.set(url, data);
    log('L1 STORED (raw)', url);
    return { ok: true, status: res.status, data };
  })();

  if (cacheEnabled) INFLIGHT_RAW.set(url, promise);
  return promise;
}

// ---------------------------------------------------------------------------
// L2 cache — semantic, per-ecosystem
// ---------------------------------------------------------------------------

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
  let result: string | null = null;
  switch (ecosystem) {
    case 'pypi':
      result = extractPypiPublishedAt(name, version);
      break;
    case 'cargo':
      result = extractCargoPublishedAt(name, version);
      break;
    case 'go':
      result = extractGoPublishedAt(name, version);
      break;
    case 'ruby':
      result = extractRubyPublishedAt(name, version);
      break;
    case 'npm':
      // Resolver caches the single-version manifest, which does not include
      // the `time` map needed for per-version publish dates.
      break;
  }
  if (result) {
    log('L2 HIT (publishedAt)', `${ecosystem}:${name}@${version}`);
  } else {
    log('L2 MISS (publishedAt)', `${ecosystem}:${name}@${version}`);
  }
  return result;
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
