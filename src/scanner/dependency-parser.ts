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
      } else if (file.type === 'Cargo.toml') {
        dependencies.push(...parseCargoToml(content, file.path));
      } else if (file.type === 'Cargo.lock') {
        dependencies.push(...parseCargoLock(content, file.path));
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

function parseCargoToml(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let inDependencies = false;
  let inDevDependencies = false;
  let currentSection = '';
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Check for section headers
    if (trimmed.startsWith('[')) {
      const section = trimmed.replace(/\[|\]/g, '').trim();
      currentSection = section;
      inDependencies = section === 'dependencies' || section.endsWith('.dependencies');
      inDevDependencies = section === 'dev-dependencies' || section === 'build-dependencies';
      continue;
    }
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Parse dependency lines
    // Format: package = "version" or package = { version = "1.0", optional = true }
    if (inDependencies || inDevDependencies) {
      // Match simple format: name = "version"
      const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (simpleMatch) {
        const name = simpleMatch[1];
        const versionSpec = simpleMatch[2];
        const isExactVersion = !versionSpec.includes('^') && !versionSpec.includes('~') && 
                               !versionSpec.includes('>') && !versionSpec.includes('<') &&
                               !versionSpec.includes('*');
        
        dependencies.push({
          name,
          version: cleanVersion(versionSpec),
          versionSpec,
          ecosystem: 'cargo',
          file: filePath,
          isDev: inDevDependencies,
          isPinned: isExactVersion,
        });
      } else {
        // Match inline table format: name = { version = "1.0" }
        const tableMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{/);
        if (tableMatch) {
          const name = tableMatch[1];
          // Look for version in the same line or subsequent lines
          let versionSpec = '';
          const inlineVersionMatch = trimmed.match(/version\s*=\s*"([^"]+)"/);
          if (inlineVersionMatch) {
            versionSpec = inlineVersionMatch[1];
          }
          
          const isExactVersion = !!(versionSpec && !versionSpec.includes('^') && !versionSpec.includes('~') && 
                                 !versionSpec.includes('>') && !versionSpec.includes('<') &&
                                 !versionSpec.includes('*'));
          
          dependencies.push({
            name,
            version: versionSpec ? cleanVersion(versionSpec) : '*',
            versionSpec: versionSpec || '*',
            ecosystem: 'cargo',
            file: filePath,
            isDev: inDevDependencies,
            isPinned: isExactVersion,
          });
        }
      }
    }
  }
  
  return dependencies;
}

function parseCargoLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let currentPackage: Partial<Dependency> | null = null;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // New package entry starts with [[package]]
    if (trimmed === '[[package]]') {
      if (currentPackage?.name && currentPackage?.version) {
        dependencies.push({
          name: currentPackage.name,
          version: currentPackage.version,
          versionSpec: currentPackage.version,
          ecosystem: 'cargo',
          file: filePath,
          isDev: false,
          isPinned: true, // Cargo.lock versions are always pinned
        });
      }
      currentPackage = {};
      continue;
    }
    
    // Parse name
    const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch && currentPackage) {
      currentPackage.name = nameMatch[1];
    }
    
    // Parse version
    const versionMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
    if (versionMatch && currentPackage) {
      currentPackage.version = versionMatch[1];
    }
  }
  
  // Don't forget the last package
  if (currentPackage?.name && currentPackage?.version) {
    dependencies.push({
      name: currentPackage.name,
      version: currentPackage.version,
      versionSpec: currentPackage.version,
      ecosystem: 'cargo',
      file: filePath,
      isDev: false,
      isPinned: true, // Cargo.lock versions are always pinned
    });
  }
  
  return dependencies;
}
