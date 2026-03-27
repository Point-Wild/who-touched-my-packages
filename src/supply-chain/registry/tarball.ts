import { createGunzip } from 'node:zlib';
import { inflateRawSync } from 'node:zlib';
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

export async function downloadAndExtractZip(
  response: Response,
  textFilePattern: RegExp
): Promise<TarExtractResult> {
  const body = response.body;
  if (!body) {
    throw new Error('Empty response body');
  }

  const chunks: Buffer[] = [];
  for await (const chunk of Readable.fromWeb(body)) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return parseZip(Buffer.concat(chunks), textFilePattern);
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

function parseZip(
  zipBuffer: Buffer,
  textFilePattern: RegExp
): TarExtractResult {
  const fileList: string[] = [];
  const fileContents: Record<string, string> = {};
  const MAX_FILE_SIZE = 500_000;
  const eocdOffset = findEndOfCentralDirectory(zipBuffer);
  if (eocdOffset === -1) {
    return { fileList, fileContents };
  }

  const centralDirectoryOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
  const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
  let offset = centralDirectoryOffset;

  for (let entryIndex = 0; entryIndex < totalEntries && offset + 46 <= zipBuffer.length; entryIndex++) {
    const signature = zipBuffer.readUInt32LE(offset);
    if (signature !== 0x02014b50) {
      break;
    }

    const compressionMethod = zipBuffer.readUInt16LE(offset + 10);
    const compressedSize = zipBuffer.readUInt32LE(offset + 20);
    const uncompressedSize = zipBuffer.readUInt32LE(offset + 24);
    const fileNameLength = zipBuffer.readUInt16LE(offset + 28);
    const extraFieldLength = zipBuffer.readUInt16LE(offset + 30);
    const fileCommentLength = zipBuffer.readUInt16LE(offset + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(offset + 42);
    const fileName = zipBuffer
      .subarray(offset + 46, offset + 46 + fileNameLength)
      .toString('utf-8');

    if (fileName && !fileName.endsWith('/')) {
      fileList.push(fileName);

      if (textFilePattern.test(fileName) && uncompressedSize > 0 && uncompressedSize < MAX_FILE_SIZE) {
        const localSignature = zipBuffer.readUInt32LE(localHeaderOffset);
        if (localSignature === 0x04034b50) {
          const localFileNameLength = zipBuffer.readUInt16LE(localHeaderOffset + 26);
          const localExtraFieldLength = zipBuffer.readUInt16LE(localHeaderOffset + 28);
          const dataStart = localHeaderOffset + 30 + localFileNameLength + localExtraFieldLength;
          const dataEnd = dataStart + compressedSize;
          const compressedData = zipBuffer.subarray(dataStart, dataEnd);

          let content: Buffer | null = null;
          if (compressionMethod === 0) {
            content = compressedData;
          } else if (compressionMethod === 8) {
            content = inflateRawSync(compressedData);
          }

          if (content) {
            fileContents[fileName] = content.toString('utf-8');
          }
        }
      }
    }

    offset += 46 + fileNameLength + extraFieldLength + fileCommentLength;
  }

  return { fileList, fileContents };
}

function findEndOfCentralDirectory(zipBuffer: Buffer): number {
  for (let offset = zipBuffer.length - 22; offset >= Math.max(0, zipBuffer.length - 65557); offset--) {
    if (zipBuffer.readUInt32LE(offset) === 0x06054b50) {
      return offset;
    }
  }

  return -1;
}
