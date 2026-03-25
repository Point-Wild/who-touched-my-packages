import { createGunzip } from 'node:zlib';
import { createReadStream, createWriteStream } from 'node:fs';
import { unlink, rmdir, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export interface TarExtractResult {
  fileList: string[];
  fileContents: Record<string, string>;
}

/**
 * Download a tarball response to a temporary file, extract it, then clean up.
 * Keeps the full tarball off the heap during extraction.
 */
export async function downloadAndExtractTarGz(
  response: Response,
  textFilePattern: RegExp
): Promise<TarExtractResult> {
  const dir = await mkdtemp(join(tmpdir(), 'wtmp-'));
  const tmpPath = join(dir, 'pkg.tar.gz');

  try {
    // Stream response body to a temp file
    const body = response.body;
    if (!body) throw new Error('Empty response body');

    const dest = createWriteStream(tmpPath);
    await pipeline(Readable.fromWeb(body), dest);

    // Read the temp file and decompress
    const decompressed = await decompressFile(tmpPath);

    return parseTar(decompressed, textFilePattern);
  } finally {
    // Clean up temp file
    await unlink(tmpPath).catch(() => {});
    await rmdir(dir).catch(() => {});
  }
}

async function decompressFile(filePath: string): Promise<Buffer> {
  const chunks: Buffer[] = [];
  const gunzip = createGunzip();
  const input = createReadStream(filePath);

  gunzip.on('data', (chunk: Buffer) => chunks.push(chunk));

  await pipeline(input, gunzip);

  return Buffer.concat(chunks);
}

function parseTar(
  decompressed: Buffer,
  textFilePattern: RegExp
): TarExtractResult {
  const fileList: string[] = [];
  const fileContents: Record<string, string> = {};
  const MAX_FILE_SIZE = 500_000;

  let offset = 0;

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

      if (textFilePattern.test(name) && size > 0 && size < MAX_FILE_SIZE) {
        fileContents[name] = decompressed.subarray(offset, offset + size).toString('utf-8');
      }
    }

    // Advance past file data (padded to 512-byte boundary)
    offset += Math.ceil(size / 512) * 512;
  }

  return { fileList, fileContents };
}
