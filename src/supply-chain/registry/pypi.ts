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

const PYPI_BASE = 'https://pypi.org/pypi';
const STATS_BASE = 'https://pypistats.org/api/packages';

export async function fetchPypiMetadata(packageName: string): Promise<PackageMetadata | null> {
  const data = await registryFetchJson(`${PYPI_BASE}/${packageName}/json`) as any;
  const info = data.info ?? {};
  const releases = data.releases ?? {};
  const versions = Object.keys(releases);

  // Get creation date from earliest release
  let createdAt = '';
  let updatedAt = '';
  for (const version of versions) {
    const files = releases[version] ?? [];
    for (const file of files) {
      const t = file.upload_time_iso_8601 ?? file.upload_time;
      if (t && (!createdAt || t < createdAt)) createdAt = t;
      if (t && (!updatedAt || t > updatedAt)) updatedAt = t;
    }
  }

  let weeklyDownloads = 0;
  try {
    const statsResult = await registryFetchRaw(`${STATS_BASE}/${packageName}/recent`);
    if (statsResult.ok) {
      weeklyDownloads = statsResult.data?.data?.last_week ?? 0;
    }
  } catch {
    // Stats service may be unavailable
  }

  const maintainers: string[] = [];
  if (info.author) maintainers.push(info.author);
  if (info.maintainer && info.maintainer !== info.author) maintainers.push(info.maintainer);

  // PyPI packages with setup.py have implicit install scripts
  const hasInstallScripts = versions.some(v =>
    (releases[v] ?? []).some((f: any) => f.filename?.endsWith('.tar.gz'))
  );

  // Registry risk signals
  const now = Date.now();
  const packageAgeDays = createdAt
    ? Math.floor((now - new Date(createdAt).getTime()) / 86_400_000) : 0;
  const publishedDaysAgo = updatedAt
    ? Math.floor((now - new Date(updatedAt).getTime()) / 86_400_000) : 0;

  // PyPI Trusted Publisher provenance: check if any release file has
  // metadata_version >= 2.3 (the version that added provenance support)
  const latestFiles: any[] = releases[info.version ?? ''] ?? [];
  const hasProvenance = latestFiles.some(
    (f: any) => f.provenance_url != null || f.metadata_version >= '2.3'
  );

  const signalsWithoutScore: Omit<RegistrySignals, 'riskScore'> = {
    // PyPI API doesn't expose per-release maintainer history reliably
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays,
    publishedDaysAgo,
    typosquatCandidate: computeTyposquatCandidate(packageName, 'pypi'),
    isDependencyConfusion: isDependencyConfusion(packageName),
    hasProvenance,
  };

  const registrySignals: RegistrySignals = {
    ...signalsWithoutScore,
    riskScore: computeRegistryRiskScore(signalsWithoutScore),
  };

  return {
    name: packageName,
    ecosystem: 'pypi',
    latestVersion: info.version ?? '',
    createdAt,
    updatedAt,
    weeklyDownloads,
    maintainers,
    hasInstallScripts,
    installScripts: {},
    repositoryUrl: info.project_urls?.Source ?? info.project_urls?.Repository ?? info.home_page ?? undefined,
    description: info.summary ?? undefined,
    license: info.license ?? undefined,
    registrySignals,
  };
}

export async function fetchPypiSource(
  packageName: string,
  version: string
): Promise<PackageSource | null> {
  const data = await registryFetchJson(`${PYPI_BASE}/${packageName}/${version}/json`) as any;
  const releases = data.urls ?? [];

  // Prefer sdist (.tar.gz) for source inspection
  const sdist = releases.find((r: any) => r.packagetype === 'sdist' && r.filename?.endsWith('.tar.gz'));

  if (!sdist) {
    return {
      name: packageName,
      ecosystem: 'pypi',
      version,
      installScripts: {},
      fileList: [],
      fileContents: {},
      suspiciousFiles: {},
    };
  }

  const tarRes = await fetch(sdist.url);
  if (!tarRes.ok) throw createRegistryFetchError('PyPI', packageName, tarRes.status, version);

  const PYPI_TEXT_PATTERN = /\.(py|js|ts|sh|json|yml|yaml|toml|cfg|ini|txt|md|pth)$/i;
  const { fileList, fileContents } = await downloadAndExtractTarGz(tarRes, PYPI_TEXT_PATTERN);

  // Find entry points
  const entryKey = Object.keys(fileContents).find(
    f => f.endsWith('/__init__.py') && f.split('/').length <= 3
  );

  // Identify suspicious files
  const suspiciousPatterns = [
    /setup\.py$/,
    /setup\.cfg$/,
    /conftest\.py$/,
    /__init__\.py$/,
  ];

  const suspiciousFiles: Record<string, string> = {};
  for (const [path, content] of Object.entries(fileContents)) {
    const basename = path.split('/').pop() ?? '';
    if (suspiciousPatterns.some(p => p.test(basename))) {
      suspiciousFiles[path] = content;
    }
  }

  // setup.py is the main install-time script for Python
  const installScripts: Record<string, string> = {};
  const setupPy = Object.entries(fileContents).find(([p]) => p.endsWith('/setup.py'));
  if (setupPy) {
    installScripts['setup.py'] = setupPy[1];
  }

  return {
    name: packageName,
    ecosystem: 'pypi',
    version,
    entryPoint: entryKey ? fileContents[entryKey] : undefined,
    installScripts,
    fileList,
    fileContents,
    suspiciousFiles,
  };
}
