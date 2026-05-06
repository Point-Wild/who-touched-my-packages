import type { Dependency } from '../types.js';

export function parseCargoToml(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let inDependencies = false;
  let inDevDependencies = false;
  let inBuildDependencies = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Track sections
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      inDependencies = trimmed === '[dependencies]';
      inDevDependencies = trimmed === '[dev-dependencies]';
      inBuildDependencies = trimmed === '[build-dependencies]';
      continue;
    }
    
    // Parse dependency lines
    if (inDependencies || inDevDependencies || inBuildDependencies) {
      // Format: name = "version" or name = { version = "1.0", features = [...] }
      const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (match) {
        const name = match[1];
        const version = match[2];
        
        dependencies.push({
          name,
          version,
          versionSpec: version,
          ecosystem: 'cargo',
          file: filePath,
          isDev: inDevDependencies || inBuildDependencies,
        });
      } else {
        // Try table format: name = { version = "1.0" }
        const tableMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{/);
        if (tableMatch) {
          const name = tableMatch[1];
          const versionMatch = trimmed.match(/version\s*=\s*"([^"]+)"/);
          const version = versionMatch ? versionMatch[1] : '';
          
          dependencies.push({
            name,
            version,
            versionSpec: version,
            ecosystem: 'cargo',
            file: filePath,
            isDev: inDevDependencies || inBuildDependencies,
          });
        }
      }
    }
  }
  
  return dependencies;
}

export function parseCargoLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    const lockfile = JSON.parse(content);
    
    if (lockfile.packages) {
      for (const pkg of lockfile.packages) {
        const name = pkg.name;
        const version = pkg.version;
        
        if (name && version && !seen.has(`${name}@${version}`)) {
          seen.add(`${name}@${version}`);
          dependencies.push({
            name,
            version,
            versionSpec: version,
            ecosystem: 'cargo',
            file: filePath,
            isDev: false,
            isPinned: true,
          });
        }
      }
    }
  } catch (error) {
    // Parse error, skip
  }
  
  return dependencies;
}
