import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startStaticServer } from './server.js';
import type { ReportData } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export async function generateAndServeReport(data: ReportData): Promise<{ url: string; close: () => void }> {
  const reportDir = join(tmpdir(), 'who-touched-my-deps-reports');
  mkdirSync(reportDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dataPath = join(reportDir, `data-${timestamp}.json`);

  // Write the data file
  writeFileSync(dataPath, JSON.stringify(data, null, 2), 'utf-8');

  // Get the client dist path (assuming it's built)
  const clientDistPath = join(__dirname, '../../../client/dist');

  // Collect all file paths that should be accessible
  const filePaths = new Set<string>();
  data.dependencies.forEach(dep => {
    filePaths.add(dep.file);
  });

  // Start the server (will find available port automatically)
  const server = await startStaticServer({
    distPath: clientDistPath,
    dataPath,
    filePaths,
  });

  return server;
}
