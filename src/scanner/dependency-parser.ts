import { readFile } from 'node:fs/promises';
import type { Dependency, DependencyFile } from './types.js';

export async function parseDependencies(files: DependencyFile[]): Promise<Dependency[]> {
  const dependencies: Dependency[] = [];
  
  for (const file of files) {
    try {
      const content = await readFile(file.path, 'utf-8');
      
      if (file.type === 'package.json') {
        dependencies.push(...parsePackageJson(content, file.path));
      } else if (file.type === 'requirements.txt') {
        dependencies.push(...parseRequirementsTxt(content, file.path));
      }
    } catch (error) {
      // Skip files we can't read
    }
  }
  
  return dependencies;
}

function parsePackageJson(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  
  try {
    const pkg = JSON.parse(content);
    
    if (pkg.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        dependencies.push({
          name,
          version: cleanVersion(version as string),
          versionSpec: version as string,
          ecosystem: 'npm',
          file: filePath,
          isDev: false,
        });
      }
    }
    
    if (pkg.devDependencies) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        dependencies.push({
          name,
          version: cleanVersion(version as string),
          versionSpec: version as string,
          ecosystem: 'npm',
          file: filePath,
          isDev: true,
        });
      }
    }
  } catch (error) {
    // Invalid JSON, skip
  }
  
  return dependencies;
}

function parseRequirementsTxt(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Skip lines with options (like -e, -r, --index-url)
    if (trimmed.startsWith('-')) {
      continue;
    }
    
    // Parse package specification
    // Formats: package==1.0.0, package>=1.0.0, package~=1.0.0, package
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)([>=<~!]+)?(.+)?/);
    
    if (match) {
      const name = match[1];
      const operator = match[2] || '';
      const version = match[3] || '*';
      
      dependencies.push({
        name,
        version: cleanVersion(version),
        versionSpec: operator + version,
        ecosystem: 'pypi',
        file: filePath,
      });
    }
  }
  
  return dependencies;
}

function cleanVersion(version: string): string {
  // Remove common prefixes and operators
  return version
    .replace(/^[\^~>=<]+/, '')
    .replace(/\s+/g, '')
    .split(',')[0] // Take first version if multiple
    .split('||')[0] // Take first version if OR
    .trim();
}
