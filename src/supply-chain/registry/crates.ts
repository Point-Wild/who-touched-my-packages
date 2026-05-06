import { registryFetchJson } from '../../scanner/registry-cache.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from '../types.js';
import { createRegistryFetchError } from '../utils.js';
import { downloadAndExtractTarGz } from './tarball.js';
import {
  computeTyposquatCandidate,
  isDependencyConfusion,
  computeRegistryRiskScore,
} from './signals.js';
import { computeTimeSignals } from './shared.js';

const CRATES_BASE = 'https://crates.io/api/v1/crates';

export async function fetchCratesMetadata(packageName: string): Promise<PackageMetadata | null> {
  const data = await registryFetchJson(`${CRATES_BASE}/${encodeURIComponent(packageName)}`) as any;
  const crate = data.crate ?? {};
  const versions = Array.isArray(data.versions) ? data.versions : [];
  const newestVersion = versions.find((v: any) => v.num === crate.newest_version) ?? versions[0] ?? {};
  const previousVersion = versions.find((v: any) => v.num !== crate.newest_version)?.num;

  const createdAt = crate.created_at ?? newestVersion.created_at ?? '';
  const updatedAt = crate.updated_at ?? newestVersion.updated_at ?? '';
  const maintainers = Array.isArray(data.keywords) ? data.keywords.map((k: any) => String(k.id ?? k.keyword ?? '')) : [];

  const { packageAgeDays, publishedDaysAgo } = computeTimeSignals(createdAt, updatedAt);

  const signalsWithoutScore: Omit<RegistrySignals, 'riskScore'> = {
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays,
    publishedDaysAgo,
    typosquatCandidate: computeTyposquatCandidate(packageName, 'cargo'),
    isDependencyConfusion: isDependencyConfusion(packageName),
    hasProvenance: false,
  };

  return {
    name: packageName,
    ecosystem: 'cargo',
    latestVersion: crate.newest_version ?? '',
    previousVersion,
    createdAt,
    updatedAt,
    weeklyDownloads: crate.downloads ?? 0,
    maintainers,
    hasInstallScripts: false,
    installScripts: {},
    repositoryUrl: crate.repository ?? crate.homepage ?? undefined,
    description: crate.description ?? undefined,
    license: crate.license ?? undefined,
    registrySignals: {
      ...signalsWithoutScore,
      riskScore: computeRegistryRiskScore(signalsWithoutScore),
    },
  };
}

export async function fetchCratesSource(
  packageName: string,
  version: string
): Promise<PackageSource | null> {
  const tarballUrl = `https://static.crates.io/crates/${encodeURIComponent(packageName)}/${encodeURIComponent(packageName)}-${encodeURIComponent(version)}.crate`;
  const res = await fetch(tarballUrl);
  if (!res.ok) throw createRegistryFetchError('crates.io', packageName, res.status, version);

  const CRATE_TEXT_PATTERN = /\.(rs|toml|md|txt|json|ya?ml|sh|lock)$/i;
  const { fileList, fileContents } = await downloadAndExtractTarGz(res, CRATE_TEXT_PATTERN);

  const entryKey = Object.keys(fileContents).find(
    f => /\/src\/(lib|main)\.rs$/i.test(f)
  );

  const suspiciousPatterns = [
    /build\.rs$/i,
    /\/src\/main\.rs$/i,
    /\/src\/lib\.rs$/i,
    /Cargo\.toml$/i,
  ];

  const suspiciousFiles: Record<string, string> = {};
  for (const [path, content] of Object.entries(fileContents)) {
    if (suspiciousPatterns.some(pattern => pattern.test(path))) {
      suspiciousFiles[path] = content;
    }
  }

  const installScripts: Record<string, string> = {};
  const buildScript = Object.entries(fileContents).find(([path]) => /build\.rs$/i.test(path));
  if (buildScript) {
    installScripts['build.rs'] = buildScript[1];
  }

  return {
    name: packageName,
    ecosystem: 'cargo',
    version,
    entryPoint: entryKey ? fileContents[entryKey] : undefined,
    installScripts,
    fileList,
    fileContents,
    suspiciousFiles,
  };
}
