import { readFile } from 'node:fs/promises';
import type { Dependency, DependencyFile } from '../types.js';

export function parsePackageJson(content: string, filePath: string): Dependency[] {
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

export function parsePackageLockJson(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    const lockfile = JSON.parse(content);
    
    // v2/v3 format uses packages.dependencies
    if (lockfile.packages) {
      for (const [path, pkg] of Object.entries(lockfile.packages)) {
        if (path === '' || !pkg || typeof pkg !== 'object') continue;
        
        const pkgData = pkg as Record<string, unknown>;
        const name = path.replace('node_modules/', '').split('/node_modules/').pop() || '';
        const version = (pkgData.version as string) || '';
        
        if (name && version) {
          const key = `${name}@${version}`;
          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push({
              name,
              version,
              versionSpec: version,
              ecosystem: 'npm',
              file: filePath,
              isDev: pkgData.dev === true,
              isPinned: true,
            });
          }
        }
      }
    }
    
    // v1 format uses dependencies
    if (lockfile.dependencies) {
      for (const [name, dep] of Object.entries(lockfile.dependencies)) {
        if (!dep || typeof dep !== 'object') continue;
        
        const depData = dep as Record<string, unknown>;
        const version = (depData.version as string) || '';
        
        if (version) {
          const key = `${name}@${version}`;
          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push({
              name,
              version,
              versionSpec: version,
              ecosystem: 'npm',
              file: filePath,
              isDev: depData.dev === true,
              isPinned: true,
            });
          }
        }
      }
    }
  } catch (error) {
    // Invalid JSON, skip
  }
  
  return dependencies;
}

export function parseYarnLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    // Yarn lockfile v1 format: entries start with a quoted key like "pkg@version":
    // followed by indented properties. Entries are separated by lines that aren't indented.
    const lines = content.split('\n');
    let currentEntry: string[] = [];
    let inEntry = false;
    
    const flushEntry = () => {
      if (currentEntry.length === 0) return;
      
      const firstLine = currentEntry[0].trim();
      // Parse package spec from first line: "name@version": or name@version:
      const specMatch = firstLine.match(/^"?([^@\s]+)@(.+?)"?:?$/);
      if (!specMatch) {
        currentEntry = [];
        return;
      }
      
      let name = specMatch[1];
      const versionLine = currentEntry.find(l => l.trim().startsWith('version'));
      if (!versionLine) {
        currentEntry = [];
        return;
      }
      
      const versionMatch = versionLine.match(/version\s+"([^"]+)"/);
      if (!versionMatch) {
        currentEntry = [];
        return;
      }
      
      const version = versionMatch[1];
      
      // Handle npm: protocol for aliased packages
      if (name.startsWith('npm:')) {
        const aliasMatch = name.match(/npm:(.+)/);
        if (aliasMatch) {
          name = aliasMatch[1].split('@')[0];
        }
      }
      
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        
        // Check if dev dependency - yarn uses "dev: true" at entry level
        const isDev = currentEntry.some(l => l.trim() === 'dev: true');
        
        dependencies.push({
          name,
          version,
          versionSpec: version,
          ecosystem: 'npm',
          file: filePath,
          isDev,
          isPinned: true,
        });
      }
      
      currentEntry = [];
    };
    
    for (const line of lines) {
      // Skip empty lines and comments
      if (!line.trim() || line.trim().startsWith('#')) {
        if (inEntry) flushEntry();
        inEntry = false;
        continue;
      }
      
      // New entry starts when we see a non-indented line with package@version
      if (!line.startsWith(' ') && !line.startsWith('\t')) {
        if (inEntry) flushEntry();
        inEntry = true;
        currentEntry = [line];
      } else if (inEntry) {
        currentEntry.push(line);
      }
    }
    
    // Don't forget the last entry
    if (inEntry) flushEntry();
    
  } catch (error) {
    // Skip on parse error
  }
  
  return dependencies;
}

export function parsePnpmLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    // Parse packages section from pnpm-lock.yaml
    // Format: packages:
    //   /package@version:
    //     resolution: {integrity: ...}
    //     engines: {node: '>=18'}
    const lines = content.split('\n');
    let inPackages = false;
    let currentPackage: { name?: string; version?: string } | null = null;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Start of packages section
      if (trimmed === 'packages:') {
        inPackages = true;
        continue;
      }
      
      // End of packages section (new top-level section that isn't indented)
      // Only break if we see a top-level section (no indentation) that's not packages
      if (inPackages && trimmed.match(/^[a-z]+:$/) && !line.startsWith(' ') && trimmed !== 'packages:') {
        // Save the last package before breaking
        if (currentPackage?.name && currentPackage?.version) {
          const key = `${currentPackage.name}@${currentPackage.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push({
              name: currentPackage.name,
              version: currentPackage.version,
              versionSpec: currentPackage.version,
              ecosystem: 'npm',
              file: filePath,
              isPinned: true,
            });
          }
        }
        break;
      }
      
      if (!inPackages) continue;
      
      // Parse package entry: /package@version: or package@version:
      const pkgMatch = trimmed.match(/^\/?([^@/][^@]*)@(.+):$/);
      if (pkgMatch) {
        if (currentPackage?.name && currentPackage?.version) {
          const key = `${currentPackage.name}@${currentPackage.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push({
              name: currentPackage.name,
              version: currentPackage.version,
              versionSpec: currentPackage.version,
              ecosystem: 'npm',
              file: filePath,
              isPinned: true,
            });
          }
        }
        currentPackage = {
          name: pkgMatch[1],
          version: pkgMatch[2],
        };
      }
    }
    
    // Don't forget the last package
    if (currentPackage?.name && currentPackage?.version) {
      const key = `${currentPackage.name}@${currentPackage.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        dependencies.push({
          name: currentPackage.name,
          version: currentPackage.version,
          versionSpec: currentPackage.version,
          ecosystem: 'npm',
          file: filePath,
          isPinned: true,
        });
      }
    }
  } catch (error) {
    // Skip on parse error
  }
  
  return dependencies;
}

export function parseBunLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    // Bun lock can be JSON or text format
    // Try JSON first
    const lockfile = JSON.parse(content);
    
    if (lockfile.packages) {
      for (const [key, pkg] of Object.entries(lockfile.packages)) {
        if (!pkg || typeof pkg !== 'object') continue;
        
        // key format: package@version or npm:package@version
        const pkgKey = key.replace(/^npm:/, '');
        const atIndex = pkgKey.lastIndexOf('@');
        if (atIndex <= 0) continue;
        
        const name = pkgKey.slice(0, atIndex);
        const version = pkgKey.slice(atIndex + 1);
        
        if (name && version && !seen.has(key)) {
          seen.add(key);
          const pkgData = pkg as Record<string, unknown>;
          dependencies.push({
            name,
            version,
            versionSpec: version,
            ecosystem: 'npm',
            file: filePath,
            isDev: pkgData.dev === true,
            isPinned: true,
          });
        }
      }
    }
  } catch {
    // Not valid JSON, try text format
    // Text format: package@version entries
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      // Parse format: package@version or npm:package@version
      const match = trimmed.match(/^(?:npm:)?([^@\s]+)@([^\s,]+)/);
      if (match) {
        const name = match[1];
        const version = match[2];
        const key = `${name}@${version}`;
        
        if (!seen.has(key)) {
          seen.add(key);
          dependencies.push({
            name,
            version,
            versionSpec: version,
            ecosystem: 'npm',
            file: filePath,
            isPinned: true,
          });
        }
      }
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
