import type { Dependency } from '../types.js';

export function parseRequirementsTxt(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip empty lines, comments, and options
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue;
    }
    
    // Parse requirement: package[extras]==version, package>=version, etc.
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:\[[^\]]+\])?\s*([>=<~!]+)?\s*([^\s,#]+)/);
    if (match) {
      const name = match[1];
      const version = match[3] || '';
      const versionSpec = match[2] ? `${match[2]}${match[3]}` : version;
      
      dependencies.push({
        name,
        version,
        versionSpec,
        ecosystem: 'pypi',
        file: filePath,
        isDev: false,
      });
    } else {
      // Fallback: just take the package name if we can't parse version
      const nameMatch = trimmed.match(/^([a-zA-Z0-9_-]+)/);
      if (nameMatch) {
        dependencies.push({
          name: nameMatch[1],
          version: '',
          versionSpec: trimmed,
          ecosystem: 'pypi',
          file: filePath,
          isDev: false,
        });
      }
    }
  }
  
  return dependencies;
}

export function parsePyProjectToml(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  
  try {
    // Simple parsing - extract dependencies from project.dependencies and project.optional-dependencies
    // This is a simplified parser; for full TOML parsing, a proper library would be needed
    
    const lines = content.split('\n');
    let inDependencies = false;
    let inOptionalDeps = false;
    let currentSection = '';
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Track sections
      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        currentSection = trimmed.slice(1, -1);
        inDependencies = currentSection === 'project.dependencies';
        inOptionalDeps = currentSection.startsWith('project.optional-dependencies');
        continue;
      }
      
      // Parse dependency lines
      if (inDependencies || inOptionalDeps) {
        const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:\[[^\]]+\])?\s*=\s*"([^"]+)"/);
        if (match) {
          const name = match[1];
          const version = match[2];
          
          dependencies.push({
            name,
            version,
            versionSpec: version,
            ecosystem: 'pypi',
            file: filePath,
            isDev: inOptionalDeps,
          });
        }
      }
    }
  } catch (error) {
    // Parse error, skip
  }
  
  return dependencies;
}

export function parsePipfile(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  
  try {
    const pipfile = JSON.parse(content);
    
    if (pipfile.packages) {
      for (const [name, spec] of Object.entries(pipfile.packages)) {
        const version = typeof spec === 'string' ? spec : (spec as any).version || '';
        dependencies.push({
          name,
          version,
          versionSpec: version,
          ecosystem: 'pypi',
          file: filePath,
          isDev: false,
        });
      }
    }
    
    if (pipfile['dev-packages']) {
      for (const [name, spec] of Object.entries(pipfile['dev-packages'])) {
        const version = typeof spec === 'string' ? spec : (spec as any).version || '';
        dependencies.push({
          name,
          version,
          versionSpec: version,
          ecosystem: 'pypi',
          file: filePath,
          isDev: true,
        });
      }
    }
  } catch (error) {
    // Parse error, skip
  }
  
  return dependencies;
}
