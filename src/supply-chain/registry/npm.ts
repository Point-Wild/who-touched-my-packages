import {
  registryFetchJson,
  registryFetchRaw,
} from '../../scanner/registry-cache.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from '../types.js';
import { createRegistryFetchError } from '../utils.js';
import { downloadAndExtractTarGz } from './tarball.js';
import {
  computeTyposquatCandidate,
  isDependencyConfusion,
  computeRegistryRiskScore,
} from './signals.js';
import { computeTimeSignals } from './shared.js';

const REGISTRY_BASE = 'https://registry.npmjs.org';
const DOWNLOADS_BASE = 'https://api.npmjs.org/downloads/point/last-week';

/**
 * Fetch the full package registry document and return the previous version string
 * (one before latest) alongside the full metadata. Exposed so fetchNpmSource can
 * reuse it without a second network call.
 */
export async function fetchNpmPackageDoc(packageName: string): Promise<any | null> {
  const encoded = encodeURIComponent(packageName);
  return registryFetchJson(`${REGISTRY_BASE}/${encoded}`);
}

export async function fetchNpmMetadata(packageName: string): Promise<PackageMetadata | null> {
  const encoded = encodeURIComponent(packageName);

  const [meta, dlRes] = await Promise.all([
    fetchNpmPackageDoc(packageName),
    registryFetchRaw(`${DOWNLOADS_BASE}/${encoded}`).catch(() => null),
  ]);

  if (!meta) return null;

  const latestVersion: string = meta['dist-tags']?.latest ?? '';
  const latestMeta = meta.versions?.[latestVersion] ?? {};
  const time: Record<string, string> = meta.time ?? {};
  const scripts = latestMeta.scripts ?? {};

  const installScripts: Record<string, string> = {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (scripts[hook]) installScripts[hook] = scripts[hook];
  }

  let weeklyDownloads = 0;
  if (dlRes?.ok) {
    weeklyDownloads = dlRes.data?.downloads ?? 0;
  }

  // Current maintainers (top-level list is most reliable for the package as a whole)
  const currentMaintainers: string[] = (meta.maintainers ?? [])
    .map((m: any) => (m.name ?? m.email ?? 'unknown') as string);

  // Find previous version to detect maintainer changes
  const allVersions = Object.keys(meta.versions ?? {});
  allVersions.sort((a, b) => {
    // Lexicographic semver sort — good enough for ordering within a major
    return a.localeCompare(b, undefined, { numeric: true });
  });
  const latestIdx = allVersions.indexOf(latestVersion);
  const prevVersion: string | null = latestIdx > 0 ? allVersions[latestIdx - 1] : null;
  const prevMeta = prevVersion ? (meta.versions[prevVersion] ?? {}) : {};
  const previousMaintainers: string[] = (prevMeta.maintainers ?? [])
    .map((m: any) => (m.name ?? m.email ?? 'unknown') as string);
  const newMaintainers = currentMaintainers.filter(n => !previousMaintainers.includes(n));

  // Sigstore / npm provenance (dist.attestations added ~2023)
  const hasProvenance = !!(latestMeta.dist?.attestations);

  // Time signals
  const createdAt = time.created ?? '';
  const updatedAt = time.modified ?? '';
  const { packageAgeDays, publishedDaysAgo } = computeTimeSignals(createdAt, updatedAt);

  const signalsWithoutScore: Omit<RegistrySignals, 'riskScore'> = {
    maintainerChangedInLatestRelease: newMaintainers.length > 0,
    previousMaintainers,
    newMaintainers,
    packageAgeDays,
    publishedDaysAgo,
    typosquatCandidate: computeTyposquatCandidate(packageName, 'npm'),
    isDependencyConfusion: isDependencyConfusion(packageName),
    hasProvenance,
  };

  const registrySignals: RegistrySignals = {
    ...signalsWithoutScore,
    riskScore: computeRegistryRiskScore(signalsWithoutScore),
  };

  return {
    name: packageName,
    ecosystem: 'npm',
    latestVersion,
    previousVersion: prevVersion ?? undefined,
    createdAt,
    updatedAt,
    weeklyDownloads,
    maintainers: currentMaintainers,
    hasInstallScripts: Object.keys(installScripts).length > 0,
    installScripts,
    repositoryUrl: meta.repository?.url ?? undefined,
    description: meta.description ?? undefined,
    license: meta.license ?? undefined,
    registrySignals,
  };
}

export async function fetchNpmSource(
  packageName: string,
  version: string,
  previousVersion?: string
): Promise<PackageSource | null> {
  const encoded = encodeURIComponent(packageName);

  const meta = await registryFetchJson(`${REGISTRY_BASE}/${encoded}/${version}`);
  const tarballUrl = meta.dist?.tarball;
  if (!tarballUrl) {
    throw new Error(`npm package ${packageName}@${version} does not expose a tarball URL`);
  }

  const scripts = meta.scripts ?? {};
  const installScripts: Record<string, string> = {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (scripts[hook]) installScripts[hook] = scripts[hook];
  }

  const mainEntry = (meta.main ?? 'index.js').replace(/^\.\//, '');

  // Download and extract the tarball
  const tarRes = await fetch(tarballUrl);
  if (!tarRes.ok) throw createRegistryFetchError('npm', packageName, tarRes.status, version);

  const NPM_TEXT_PATTERN = /\.(js|ts|mjs|cjs|py|sh|json|yml|yaml|toml|cfg|ini|txt|md)$/i;
  const { fileList, fileContents } = await downloadAndExtractTarGz(tarRes, NPM_TEXT_PATTERN);

  // Find entry point — try exact match, then with .js extension
  const entryKey = Object.keys(fileContents).find(f => {
    const stripped = f.replace(/^package\//, '');
    return stripped === mainEntry
      || stripped === `${mainEntry}.js`
      || stripped === `${mainEntry}/index.js`;
  });

  // Identify suspicious files
  const suspiciousPatterns = [
    /postinstall\.(js|sh|ts)$/i,
    /preinstall\.(js|sh|ts)$/i,
    /setup\.(js|sh)$/i,
    /install\.(js|sh|ts)$/i,
  ];

  const suspiciousFiles: Record<string, string> = {};
  for (const [path, content] of Object.entries(fileContents)) {
    const basename = path.split('/').pop() ?? '';
    if (suspiciousPatterns.some(p => p.test(basename))) {
      suspiciousFiles[path] = content;
    }
  }

  // Also grab scripts referenced in install hooks
  for (const [hook, cmd] of Object.entries(installScripts)) {
    const scriptMatch = cmd.match(/node\s+(.+?)(?:\s|$)/);
    if (scriptMatch) {
      const scriptPath = scriptMatch[1];
      const fullKey = Object.keys(fileContents).find(
        f => f === `package/${scriptPath}` || f.endsWith(`/${scriptPath}`)
      );
      if (fullKey && fileContents[fullKey]) {
        suspiciousFiles[`${hook}:${scriptPath}`] = fileContents[fullKey];
      }
    }
  }

  // Compute version diff: which files are NEW vs. the previous version?
  let newFilesInVersion: string[] | undefined;
  if (previousVersion) {
    try {
      const prevResult = await registryFetchRaw(`${REGISTRY_BASE}/${encodeURIComponent(packageName)}/${previousVersion}`);
      if (prevResult.ok) {
        const prevMeta = prevResult.data;
        const prevTarball = prevMeta.dist?.tarball;
        if (prevTarball) {
          const prevTarRes = await fetch(prevTarball);
          if (prevTarRes.ok) {
            const { fileList: prevList } = await downloadAndExtractTarGz(prevTarRes, NPM_TEXT_PATTERN);
            const prevSet = new Set(prevList.map(f => f.replace(/^package\//, '')));
            newFilesInVersion = fileList
              .map(f => f.replace(/^package\//, ''))
              .filter(f => !prevSet.has(f));
          }
        }
      }
    } catch {
      // Non-fatal — version diff is best-effort
    }
  }

  return {
    name: packageName,
    ecosystem: 'npm',
    version,
    entryPoint: entryKey ? fileContents[entryKey] : undefined,
    installScripts,
    fileList,
    fileContents,
    suspiciousFiles,
    previousVersion,
    newFilesInVersion,
  };
}
