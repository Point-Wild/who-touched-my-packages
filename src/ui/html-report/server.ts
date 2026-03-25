import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    
    server.listen(startPort, () => {
      const port = (server.address() as any).port;
      server.close(() => resolve(port));
    });
    
    server.on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        resolve(findAvailablePort(startPort + 1));
      } else {
        reject(err);
      }
    });
  });
}

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

interface ServerOptions {
  port?: number;
  distPath: string;
  dataPath: string;
  filePaths: Set<string>;
}

export async function startStaticServer(options: ServerOptions): Promise<{ url: string; close: () => void }> {
  const { distPath, dataPath, filePaths } = options;
  const port = await findAvailablePort(options.port || 3000);

  const server = createServer(async (req, res) => {
    try {
      // Handle API routes
      if (req.url?.startsWith('/api/')) {
        if (req.url === '/api/data') {
          // Serve the report data
          const data = await readFile(dataPath, 'utf-8');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(data);
          return;
        }

        if (req.url.startsWith('/api/file?path=')) {
          // Serve individual dependency files
          const url = new URL(req.url, `http://localhost:${port}`);
          const filePath = url.searchParams.get('path');
          
          if (filePath && filePaths.has(filePath)) {
            try {
              const content = await readFile(filePath, 'utf-8');
              res.writeHead(200, { 'Content-Type': 'text/plain' });
              res.end(content);
              return;
            } catch (error) {
              res.writeHead(404, { 'Content-Type': 'text/plain' });
              res.end('File not found');
              return;
            }
          } else {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Access denied');
            return;
          }
        }

        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }

      // Serve static files
      let filePath = req.url === '/' ? '/index.html' : req.url || '/index.html';
      filePath = join(distPath, filePath);

      try {
        const content = await readFile(filePath);
        const ext = extname(filePath);
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
      } catch (error) {
        // If file not found, serve index.html for client-side routing
        if (req.url && !req.url.includes('.')) {
          try {
            const indexPath = join(distPath, 'index.html');
            const content = await readFile(indexPath);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(content);
          } catch {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
          }
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not found');
        }
      }
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal server error');
    }
  });

  return new Promise((resolve, reject) => {
    server.listen(port, () => {
      resolve({
        url: `http://localhost:${port}`,
        close: () => server.close(),
      });
    });

    server.on('error', reject);
  });
}
