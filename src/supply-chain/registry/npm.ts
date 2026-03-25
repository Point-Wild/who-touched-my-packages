import { createGunzip } from 'node:zlib';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { PackageMetadata, PackageSource } from '../types.js';

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
  const encoded = packageName.replace('/', '%2f');
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

  const mainEntry = meta.main ?? 'index.js';

  // Download and extract the tarball
  const tarRes = await fetch(tarballUrl);
  if (!tarRes.ok) return null;

  const { fileList, fileContents } = await extractTarGz(tarRes);

  // Find entry point
  const entryKey = Object.keys(fileContents).find(
    f => f === `package/${mainEntry}` || f.endsWith(`/${mainEntry}`)
  );

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
    suspiciousFiles,
  };
}

interface TarExtractResult {
  fileList: string[];
  fileContents: Record<string, string>;
}

/**
 * Extract a .tar.gz buffer in memory using minimal tar parsing.
 * Only extracts text files under 500KB to avoid memory issues.
 */
async function extractTarGz(response: Response): Promise<TarExtractResult> {
  const fileList: string[] = [];
  const fileContents: Record<string, string> = {};
  const MAX_FILE_SIZE = 500_000;
  const MAX_FILES_TO_READ = 100;

  const buffer = Buffer.from(await response.arrayBuffer());

  // Decompress gzip
  const decompressed = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const gunzip = createGunzip();
    const input = Readable.from(buffer);

    gunzip.on('data', (chunk: Buffer) => chunks.push(chunk));
    gunzip.on('end', () => resolve(Buffer.concat(chunks)));
    gunzip.on('error', reject);

    pipeline(input, gunzip).catch(reject);
  });

  // Parse tar (512-byte block format)
  let offset = 0;
  let filesRead = 0;

  while (offset < decompressed.length - 512) {
    const header = decompressed.subarray(offset, offset + 512);

    // Check for end-of-archive (two zero blocks)
    if (header.every(b => b === 0)) break;

    const name = header.subarray(0, 100).toString('utf-8').replace(/\0/g, '').trim();
    const sizeOctal = header.subarray(124, 136).toString('utf-8').replace(/\0/g, '').trim();
    const size = parseInt(sizeOctal, 8) || 0;
    const typeFlag = header[156];

    offset += 512; // Move past header

    if (name && typeFlag !== 53) { // 53 = '5' (directory)
      fileList.push(name);

      // Read content for text-like files
      const isTextFile = /\.(js|ts|mjs|cjs|py|sh|json|yml|yaml|toml|cfg|ini|txt|md)$/i.test(name);
      if (isTextFile && size > 0 && size < MAX_FILE_SIZE && filesRead < MAX_FILES_TO_READ) {
        fileContents[name] = decompressed.subarray(offset, offset + size).toString('utf-8');
        filesRead++;
      }
    }

    // Advance past file data (padded to 512-byte boundary)
    offset += Math.ceil(size / 512) * 512;
  }

  return { fileList, fileContents };
}
