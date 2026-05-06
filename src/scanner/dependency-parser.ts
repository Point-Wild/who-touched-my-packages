import { readFile } from 'node:fs/promises';
import type { Dependency, DependencyFile } from './types.js';
import { parseDependencies as parseFromModules } from './parsers/index.js';

export async function parseDependencies(files: DependencyFile[]): Promise<Dependency[]> {
  const dependencies: Dependency[] = [];
  
  for (const file of files) {
    try {
      const content = await readFile(file.path, 'utf-8');
      const fileWithContent = { ...file, content };
      dependencies.push(...parseFromModules(fileWithContent));
    } catch (error) {
      // Skip files we can't read
    }
  }
  
  return dependencies;
}
