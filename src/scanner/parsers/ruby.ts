import type { Dependency } from '../types.js';

export function parseGemfile(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let inGroup = false;
  let isDev = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Track group blocks
    if (trimmed.startsWith('group')) {
      inGroup = true;
      isDev = trimmed.includes(':development') || trimmed.includes(':test');
      continue;
    }
    
    if (trimmed === 'end') {
      inGroup = false;
      isDev = false;
      continue;
    }
    
    // Parse gem lines
    if (trimmed.startsWith('gem')) {
      // Format: gem 'name', 'version' or gem 'name', version: '1.0'
      const match = trimmed.match(/gem\s+['"]([^'"]+)['"]/);
      if (match) {
        const name = match[1];
        
        // Try to extract version
        const versionMatch = trimmed.match(/version:\s*['"]([^'"]+)['"]/);
        const version = versionMatch ? versionMatch[1] : '';
        
        // Also check for simple format: gem 'name', '1.0'
        const simpleVersionMatch = trimmed.match(/gem\s+['"][^'"]+['"],\s*['"]([^'"]+)['"]/);
        const simpleVersion = simpleVersionMatch ? simpleVersionMatch[1] : version;
        
        dependencies.push({
          name,
          version: simpleVersion,
          versionSpec: simpleVersion,
          ecosystem: 'ruby',
          file: filePath,
          isDev: isDev,
        });
      }
    }
  }
  
  return dependencies;
}

export function parseGemfileLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    const lockfile = JSON.parse(content);
    
    if (lockfile.specs) {
      for (const spec of lockfile.specs) {
        const name = spec.name;
        const version = spec.version;
        
        if (name && version && !seen.has(`${name}@${version}`)) {
          seen.add(`${name}@${version}`);
          dependencies.push({
            name,
            version,
            versionSpec: version,
            ecosystem: 'ruby',
            file: filePath,
            isDev: false,
            isPinned: true,
          });
        }
      }
    }
  } catch (error) {
    // Not JSON, try YAML-like parsing
    const lines = content.split('\n');
    let inSpecs = false;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed === 'specs:') {
        inSpecs = true;
        continue;
      }
      
      if (inSpecs && !trimmed.startsWith('-')) {
        inSpecs = false;
        continue;
      }
      
      if (inSpecs) {
        // Format: - name (version)
        const match = trimmed.match(/-\s+([a-zA-Z0-9_-]+)\s+\(([^)]+)\)/);
        if (match) {
          const name = match[1];
          const version = match[2];
          
          if (!seen.has(`${name}@${version}`)) {
            seen.add(`${name}@${version}`);
            dependencies.push({
              name,
              version,
              versionSpec: version,
              ecosystem: 'ruby',
              file: filePath,
              isDev: false,
              isPinned: true,
            });
          }
        }
      }
    }
  }
  
  return dependencies;
}
