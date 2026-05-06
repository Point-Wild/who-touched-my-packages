import type { Dependency } from '../types.js';

export function parseGoMod(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let inRequire = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Track require blocks
    if (trimmed.startsWith('require')) {
      inRequire = true;
      continue;
    }
    
    if (trimmed === ')') {
      inRequire = false;
      continue;
    }
    
    // Parse dependency lines
    if (inRequire || trimmed.startsWith('require ')) {
      // Format: module_name version or "module_name version"
      const match = trimmed.match(/([a-zA-Z0-9_./-]+)\s+v?([0-9.]+)/);
      if (match) {
        const name = match[1];
        const version = match[2];
        
        dependencies.push({
          name,
          version,
          versionSpec: version,
          ecosystem: 'go',
          file: filePath,
          isDev: false,
        });
      }
    }
  }
  
  return dependencies;
}

export function parseGoSum(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Format: module_name version hash
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      const name = parts[0];
      const version = parts[1];
      
      if (name && version && !seen.has(`${name}@${version}`)) {
        seen.add(`${name}@${version}`);
        dependencies.push({
          name,
          version,
          versionSpec: version,
          ecosystem: 'go',
          file: filePath,
          isDev: false,
          isPinned: true,
        });
      }
    }
  }
  
  return dependencies;
}
