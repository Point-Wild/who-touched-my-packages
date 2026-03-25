import type { PackageMetadata, PackageSource } from '../types.js';
import { downloadAndExtractTarGz } from './tarball.js';

const PYPI_BASE = 'https://pypi.org/pypi';
const STATS_BASE = 'https://pypistats.org/api/packages';

export async function fetchPypiMetadata(packageName: string): Promise<PackageMetadata | null> {
  const res = await fetch(`${PYPI_BASE}/${packageName}/json`);
  if (!res.ok) return null;

  const data = await res.json() as any;
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
    const statsRes = await fetch(`${STATS_BASE}/${packageName}/recent`);
    if (statsRes.ok) {
      const stats = await statsRes.json() as any;
      weeklyDownloads = stats.data?.last_week ?? 0;
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
  };
}

export async function fetchPypiSource(
  packageName: string,
  version: string
): Promise<PackageSource | null> {
  const res = await fetch(`${PYPI_BASE}/${packageName}/${version}/json`);
  if (!res.ok) return null;

  const data = await res.json() as any;
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
  if (!tarRes.ok) return null;

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

