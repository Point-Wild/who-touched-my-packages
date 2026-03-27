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
      } else if (file.type === 'go.mod') {
        dependencies.push(...parseGoMod(content, file.path));
      } else if (file.type === 'go.sum') {
        dependencies.push(...parseGoSum(content, file.path));
      } else if (file.type === 'Gemfile.lock') {
        dependencies.push(...parseGemfileLock(content, file.path));
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

function parseCargoToml(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const sectionNames = new Set([
    'dependencies',
    'dev-dependencies',
    'build-dependencies',
    'workspace.dependencies',
    'target',
  ]);

  let currentSection = '';
  let currentTargetDependencySection = false;

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) {
      continue;
    }

    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1];
      currentTargetDependencySection =
        currentSection.startsWith('target.') && currentSection.endsWith('.dependencies');
      continue;
    }

    const isDependencySection =
      sectionNames.has(currentSection) ||
      currentSection.endsWith('.dependencies') ||
      currentTargetDependencySection;

    if (!isDependencySection) {
      continue;
    }

    const inlineMatch = rawLine.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*["']([^"']+)["']/);
    if (inlineMatch) {
      const [, name, versionSpec] = inlineMatch;
      dependencies.push({
        name,
        version: cleanVersion(versionSpec),
        versionSpec,
        ecosystem: 'cratesio',
        file: filePath,
        isDev: currentSection.includes('dev-dependencies'),
      });
      continue;
    }

    const tableMatch = rawLine.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*\{(.+)\}\s*$/);
    if (!tableMatch) {
      continue;
    }

    const [, name, tableBody] = tableMatch;
    const versionMatch = tableBody.match(/version\s*=\s*["']([^"']+)["']/);
    const pathOnly = /\bpath\s*=/.test(tableBody) && !versionMatch;
    const gitOnly = /\bgit\s*=/.test(tableBody) && !versionMatch;

    if (pathOnly || gitOnly || !versionMatch) {
      continue;
    }

    const versionSpec = versionMatch[1];
    dependencies.push({
      name,
      version: cleanVersion(versionSpec),
      versionSpec,
      ecosystem: 'cratesio',
      file: filePath,
      isDev: currentSection.includes('dev-dependencies'),
    });
  }

  return dependencies;
}

function parseGoMod(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  let inRequireBlock = false;

  for (const rawLine of content.split('\n')) {
    const commentStripped = rawLine.replace(/\/\/.*$/, '').trim();

    if (!commentStripped) {
      continue;
    }

    if (commentStripped === 'require (') {
      inRequireBlock = true;
      continue;
    }

    if (inRequireBlock && commentStripped === ')') {
      inRequireBlock = false;
      continue;
    }

    const requireLine = inRequireBlock
      ? commentStripped
      : commentStripped.startsWith('require ')
        ? commentStripped.slice('require '.length).trim()
        : null;

    if (!requireLine) {
      continue;
    }

    const match = requireLine.match(/^(\S+)\s+(\S+)$/);
    if (!match) {
      continue;
    }

    const [, name, versionSpec] = match;
    dependencies.push({
      name,
      version: versionSpec.trim(),
      versionSpec,
      ecosystem: 'golang',
      file: filePath,
    });
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

function parseGoMod(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let inRequire = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Check for require block start
    if (trimmed.startsWith('require (')) {
      inRequire = true;
      continue;
    }
    
    // Check for require block end
    if (inRequire && trimmed === ')') {
      inRequire = false;
      continue;
    }
    
    // Single-line require: require package version
    if (!inRequire && trimmed.startsWith('require ')) {
      const reqMatch = trimmed.match(/require\s+(\S+)\s+(\S+)/);
      if (reqMatch) {
        const name = reqMatch[1];
        const versionSpec = reqMatch[2];
        const isIndirect = trimmed.includes('// indirect');
        
        dependencies.push({
          name,
          version: cleanVersion(versionSpec),
          versionSpec,
          ecosystem: 'go',
          file: filePath,
          isDev: isIndirect,
          isPinned: versionSpec.startsWith('v') && !versionSpec.includes('+incompatible') && 
                    !/v\d+\.\d+\.\d+-/.test(versionSpec),
        });
      }
      continue;
    }
    
    // Inside require block
    if (inRequire) {
      // Match: package version [// indirect]
      const match = trimmed.match(/^(\S+)\s+(\S+)(?:\s*\/\/\s*(indirect|deprecated))?/);
      if (match) {
        const name = match[1];
        const versionSpec = match[2];
        const isIndirect = trimmed.includes('// indirect');
        
        dependencies.push({
          name,
          version: cleanVersion(versionSpec),
          versionSpec,
          ecosystem: 'go',
          file: filePath,
          isDev: isIndirect,
          isPinned: versionSpec.startsWith('v') && !versionSpec.includes('+incompatible') && 
                    !/v\d+\.\d+\.\d+-/.test(versionSpec),
        });
      }
    }
  }
  
  return dependencies;
}

function parseGoSum(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  const seen = new Set<string>();
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Parse go.sum line format: package version hash
    // Format: github.com/pkg/errors v0.9.1 h1:abc123...
    const match = trimmed.match(/^(\S+)\s+(\S+)\s+h1:/);
    if (match) {
      const name = match[1];
      const version = match[2];
      const key = `${name}@${version}`;
      
      // Avoid duplicates (go.sum lists each dep twice - once with /go.mod suffix)
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      
      dependencies.push({
        name,
        version: cleanVersion(version),
        versionSpec: version,
        ecosystem: 'go',
        file: filePath,
        isDev: false,
        isPinned: true, // go.sum versions are always pinned
      });
    }
  }
  
  return dependencies;
}

function parseGemfileLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');
  let inSpecsSection = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Check for section headers
    if (trimmed === 'GEM') {
      continue;
    }
    
    if (trimmed === 'specs:') {
      inSpecsSection = true;
      continue;
    }
    
    if (trimmed === 'DEPENDENCIES' || trimmed.startsWith('DEPENDENCIES')) {
      inSpecsSection = false;
      continue;
    }
    
    // End of specs section
    if (inSpecsSection && (trimmed === '' || trimmed.startsWith('PLATFORMS') || trimmed.startsWith('BUNDLED WITH'))) {
      inSpecsSection = false;
      continue;
    }
    
    // Parse gem specs
    if (inSpecsSection) {
      // Parse format:    gem_name (version)
      const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*\(([0-9][^)]*)\)/);
      if (match) {
        const name = match[1];
        const version = match[2];
        
        dependencies.push({
          name,
          version: cleanVersion(version),
          versionSpec: version,
          ecosystem: 'ruby',
          file: filePath,
          isDev: false,
          isPinned: true,
        });
      }
    }
  }
  
  return dependencies;
}
