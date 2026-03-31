import { readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type { DependencyFile } from './types.js';

const IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'coverage',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  'target',
  'vendor',
]);

const TARGET_FILES = new Set(['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'Cargo.toml', 'Cargo.lock', 'go.mod', 'go.sum', 'Gemfile.lock']);

export async function findDependencyFiles(
  rootPath: string,
  excludePatterns: string[] = [],
  maxDepth: number = 0
): Promise<DependencyFile[]> {
  const results: DependencyFile[] = [];
  
  async function walk(currentPath: string, currentDepth: number): Promise<void> {
    try {
      // Check depth limit if specified
      if (maxDepth > 0 && currentDepth > maxDepth) {
        return;
      }
      
      const entries = await readdir(currentPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = join(currentPath, entry.name);
        
        if (entry.isDirectory()) {
          if (IGNORE_DIRS.has(entry.name)) {
            continue;
          }
          
          const relPath = relative(rootPath, fullPath);
          if (excludePatterns.some(pattern => relPath.includes(pattern))) {
            continue;
          }
          
          await walk(fullPath, currentDepth + 1);
        } else if (entry.isFile() && TARGET_FILES.has(entry.name)) {
          const type = entry.name as DependencyFile['type'];
          results.push({
            path: fullPath,
            type,
            relativePath: relative(rootPath, fullPath),
          });
        }
      }
    } catch (error) {
      // Silently skip directories we can't read
    }
  }
  
  await walk(rootPath, 1);
  return results;
}
