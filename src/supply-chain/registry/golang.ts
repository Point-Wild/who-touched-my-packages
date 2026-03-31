import type { PackageMetadata, PackageSource, RegistrySignals } from '../types.js';
import { createRegistryFetchError } from '../utils.js';
import { downloadAndExtractZip } from './tarball.js';
import {
  computeTyposquatCandidate,
  isDependencyConfusion,
  computeRegistryRiskScore,
} from './signals.js';

const GO_PROXY_BASE = 'https://proxy.golang.org';

function escapeGoModulePath(modulePath: string): string {
  return modulePath
    .split('/')
    .map(segment =>
      encodeURIComponent(segment.replace(/[A-Z]/g, match => `!${match.toLowerCase()}`))
    )
    .join('/');
}

export async function fetchGoMetadata(packageName: string): Promise<PackageMetadata | null> {
  const escaped = escapeGoModulePath(packageName);
  const [latestRes, versionsRes] = await Promise.all([
    fetch(`${GO_PROXY_BASE}/${escaped}/@latest`).catch(() => null),
    fetch(`${GO_PROXY_BASE}/${escaped}/@v/list`).catch(() => null),
  ]);

  if (!latestRes) throw new Error(`Go proxy request failed for ${packageName}`);
  if (!latestRes.ok) throw createRegistryFetchError('Go proxy', packageName, latestRes.status);

  const latest = await latestRes.json() as { Version?: string; Time?: string };
  const versionsText = versionsRes?.ok ? await versionsRes.text() : '';
  const versions = versionsText.split('\n').map(v => v.trim()).filter(Boolean);
  const latestVersion = latest.Version ?? '';
  const previousVersion = versions.filter(v => v !== latestVersion).pop();
  const createdAt = latest.Time ?? '';
  const updatedAt = latest.Time ?? '';

  const now = Date.now();
  const packageAgeDays = createdAt
    ? Math.floor((now - new Date(createdAt).getTime()) / 86_400_000) : 0;
  const publishedDaysAgo = updatedAt
    ? Math.floor((now - new Date(updatedAt).getTime()) / 86_400_000) : 0;

  const signalsWithoutScore: Omit<RegistrySignals, 'riskScore'> = {
    maintainerChangedInLatestRelease: false,
    previousMaintainers: [],
    newMaintainers: [],
    packageAgeDays,
    publishedDaysAgo,
    typosquatCandidate: computeTyposquatCandidate(packageName, 'go'),
    isDependencyConfusion: isDependencyConfusion(packageName),
    hasProvenance: false,
  };

  return {
    name: packageName,
    ecosystem: 'go',
    latestVersion,
    previousVersion,
    createdAt,
    updatedAt,
    weeklyDownloads: 0,
    maintainers: [],
    hasInstallScripts: false,
    installScripts: {},
    repositoryUrl: packageName.startsWith('github.com/') ? `https://${packageName}` : undefined,
    description: undefined,
    license: undefined,
    registrySignals: {
      ...signalsWithoutScore,
      riskScore: computeRegistryRiskScore(signalsWithoutScore),
    },
  };
}

export async function fetchGoSource(
  packageName: string,
  version: string
): Promise<PackageSource | null> {
  const escaped = escapeGoModulePath(packageName);
  const res = await fetch(`${GO_PROXY_BASE}/${escaped}/@v/${encodeURIComponent(version)}.zip`);
  if (!res.ok) throw createRegistryFetchError('Go proxy', packageName, res.status, version);

  const GO_TEXT_PATTERN = /\.(go|mod|sum|md|txt|json|ya?ml|sh)$/i;
  const { fileList, fileContents } = await downloadAndExtractZip(res, GO_TEXT_PATTERN);

  const entryKey = Object.keys(fileContents).find(path =>
    /\/(main|init)\.go$/i.test(path) || /\/go\.mod$/i.test(path)
  );

  const suspiciousPatterns = [
    /\/go\.mod$/i,
    /\/main\.go$/i,
    /\/init\.go$/i,
    /\.sh$/i,
  ];

  const suspiciousFiles: Record<string, string> = {};
  for (const [path, content] of Object.entries(fileContents)) {
    if (suspiciousPatterns.some(pattern => pattern.test(path))) {
      suspiciousFiles[path] = content;
    }
  }

  return {
    name: packageName,
    ecosystem: 'go',
    version,
    entryPoint: entryKey ? fileContents[entryKey] : undefined,
    installScripts: {},
    fileList,
    fileContents,
    suspiciousFiles,
  };
}
