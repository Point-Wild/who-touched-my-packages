import type { PackageMetadata, PackageSource } from '../types.js';
import { downloadAndExtractTarGz } from './tarball.js';

const REGISTRY_BASE = 'https://registry.npmjs.org';
const DOWNLOADS_BASE = 'https://api.npmjs.org/downloads/point/last-week';

export async function fetchNpmMetadata(packageName: string): Promise<PackageMetadata | null> {
  const encoded = encodeURIComponent(packageName);

  const [metaRes, dlRes] = await Promise.all([
    fetch(`${REGISTRY_BASE}/${encoded}`),
    fetch(`${DOWNLOADS_BASE}/${encoded}`).catch(() => null),
  ]);

  if (!metaRes.ok) return null;

  const meta = await metaRes.json() as any;
  const latestVersion = meta['dist-tags']?.latest ?? '';
  const latestMeta = meta.versions?.[latestVersion] ?? {};
  const time = meta.time ?? {};
  const scripts = latestMeta.scripts ?? {};

  const installScripts: Record<string, string> = {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (scripts[hook]) installScripts[hook] = scripts[hook];
  }

  let weeklyDownloads = 0;
  if (dlRes?.ok) {
    const dlData = await dlRes.json() as any;
    weeklyDownloads = dlData.downloads ?? 0;
  }

  const maintainers = (meta.maintainers ?? []).map((m: any) => m.name ?? m.email ?? 'unknown');

  return {
    name: packageName,
    ecosystem: 'npm',
    latestVersion,
    createdAt: time.created ?? '',
    updatedAt: time.modified ?? '',
    weeklyDownloads,
    maintainers,
    hasInstallScripts: Object.keys(installScripts).length > 0,
    installScripts,
    repositoryUrl: meta.repository?.url ?? undefined,
    description: meta.description ?? undefined,
    license: meta.license ?? undefined,
  };
}

export async function fetchNpmSource(
  packageName: string,
  version: string
): Promise<PackageSource | null> {
  const encoded = encodeURIComponent(packageName);
  const metaRes = await fetch(`${REGISTRY_BASE}/${encoded}/${version}`);
  if (!metaRes.ok) return null;

  const meta = await metaRes.json() as any;
  const tarballUrl = meta.dist?.tarball;
  if (!tarballUrl) return null;

  const scripts = meta.scripts ?? {};
  const installScripts: Record<string, string> = {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (scripts[hook]) installScripts[hook] = scripts[hook];
  }

  const mainEntry = (meta.main ?? 'index.js').replace(/^\.\//, '');

  // Download and extract the tarball
  const tarRes = await fetch(tarballUrl);
  if (!tarRes.ok) return null;

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

  return {
    name: packageName,
    ecosystem: 'npm',
    version,
    entryPoint: entryKey ? fileContents[entryKey] : undefined,
    installScripts,
    fileList,
    fileContents,
    suspiciousFiles,
  };
}

