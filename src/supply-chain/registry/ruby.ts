import { registryFetchJson, registryFetchRaw } from '../../scanner/registry-cache.js';
import type { PackageMetadata, PackageSource, RegistrySignals } from '../types.js';
import { createRegistryFetchError } from '../utils.js';
import { downloadAndExtractGem } from './tarball.js';
import {
  computeTyposquatCandidate,
  isDependencyConfusion,
  computeRegistryRiskScore,
} from './signals.js';

const RUBYGEMS_BASE = 'https://rubygems.org/api/v1';

export async function fetchRubyMetadata(packageName: string): Promise<PackageMetadata | null> {
  const [gem, versionsResult] = await Promise.all([
    registryFetchJson(`${RUBYGEMS_BASE}/gems/${encodeURIComponent(packageName)}.json`) as Promise<any>,
    registryFetchRaw(`${RUBYGEMS_BASE}/versions/${encodeURIComponent(packageName)}.json`).catch(() => null),
  ]);

  const versions: any[] = versionsResult?.ok ? versionsResult.data : [];

  const latestVersion = gem.version ?? '';
  const previousVersion = versions
    .map(v => String(v.number ?? ''))
    .find(v => v && v !== latestVersion);

  const createdAt = gem.version_created_at ?? gem.created_at ?? '';
  const updatedAt = gem.version_created_at ?? gem.updated_at ?? '';
  const maintainers = String(gem.authors ?? '')
    .split(',')
    .map((part: string) => part.trim())
    .filter(Boolean);

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
    typosquatCandidate: computeTyposquatCandidate(packageName, 'ruby'),
    isDependencyConfusion: isDependencyConfusion(packageName),
    hasProvenance: false,
  };

  return {
    name: packageName,
    ecosystem: 'ruby',
    latestVersion,
    previousVersion,
    createdAt,
    updatedAt,
    weeklyDownloads: gem.downloads ?? gem.version_downloads ?? 0,
    maintainers,
    hasInstallScripts: false,
    installScripts: {},
    repositoryUrl: gem.source_code_uri ?? gem.homepage_uri ?? gem.project_uri ?? undefined,
    description: gem.info ?? undefined,
    license: gem.licenses?.join(', ') ?? undefined,
    registrySignals: {
      ...signalsWithoutScore,
      riskScore: computeRegistryRiskScore(signalsWithoutScore),
    },
  };
}

export async function fetchRubySource(
  packageName: string,
  version: string
): Promise<PackageSource | null> {
  const versionResult = await registryFetchRaw(`${RUBYGEMS_BASE}/versions/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}.json`);
  const versionMeta = versionResult.ok ? versionResult.data : null;
  const gemUrl = versionMeta?.gem_uri ?? `https://rubygems.org/downloads/${encodeURIComponent(packageName)}-${encodeURIComponent(version)}.gem`;
  const gemRes = await fetch(gemUrl);
  if (!gemRes.ok) throw createRegistryFetchError('RubyGems', packageName, gemRes.status, version);

  const RUBY_TEXT_PATTERN = /(^|\/)(Rakefile|Gemfile|.*\.(rb|ru|rake|gemspec|yml|yaml|json|toml|cfg|ini|txt|md|sh))$/i;
  const { fileList, fileContents } = await downloadAndExtractGem(gemRes, RUBY_TEXT_PATTERN);

  const normalizedName = packageName.replace(/-/g, '_');
  const entryKey = Object.keys(fileContents).find(path =>
    path.endsWith(`/lib/${normalizedName}.rb`) ||
    path.endsWith(`/lib/${packageName}.rb`) ||
    path.endsWith('/lib.rb')
  );

  const suspiciousPatterns = [
    /extconf\.rb$/i,
    /\.gemspec$/i,
    /Rakefile$/i,
    /\/bin\//i,
  ];

  const suspiciousFiles: Record<string, string> = {};
  for (const [path, content] of Object.entries(fileContents)) {
    if (suspiciousPatterns.some(pattern => pattern.test(path))) {
      suspiciousFiles[path] = content;
    }
  }

  const installScripts: Record<string, string> = {};
  for (const [path, content] of Object.entries(fileContents)) {
    const basename = path.split('/').pop() ?? '';
    if (basename === 'extconf.rb' || basename.endsWith('.gemspec')) {
      installScripts[basename] = content;
    }
  }

  return {
    name: packageName,
    ecosystem: 'ruby',
    version,
    entryPoint: entryKey ? fileContents[entryKey] : undefined,
    installScripts,
    fileList,
    fileContents,
    suspiciousFiles,
  };
}
