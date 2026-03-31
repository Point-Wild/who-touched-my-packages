import { readFile } from 'node:fs/promises';
import type { Dependency, DependencyFile } from './types.js';

export async function parseDependencies(files: DependencyFile[]): Promise<Dependency[]> {
  const dependencies: Dependency[] = [];
  
  for (const file of files) {
    try {
      const content = await readFile(file.path, 'utf-8');
      
      if (file.type === 'package.json') {
        dependencies.push(...parsePackageJson(content, file.path));
      } else if (file.type === 'package-lock.json') {
        dependencies.push(...parsePackageLockJson(content, file.path));
      } else if (file.type === 'yarn.lock') {
        dependencies.push(...parseYarnLock(content, file.path));
      } else if (file.type === 'pnpm-lock.yaml') {
        dependencies.push(...parsePnpmLock(content, file.path));
      } else if (file.type === 'bun.lock') {
        dependencies.push(...parseBunLock(content, file.path));
      } else if (file.type === 'requirements.txt') {
        dependencies.push(...parseRequirementsTxt(content, file.path));
      } else if (file.type === 'poetry.lock') {
        dependencies.push(...parsePoetryLock(content, file.path));
      } else if (file.type === 'Pipfile.lock') {
        dependencies.push(...parsePipfileLock(content, file.path));
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

function parsePackageLockJson(content: string, filePath: string): Dependency[] {
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

function parseYarnLock(content: string, filePath: string): Dependency[] {
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

function parsePnpmLock(content: string, filePath: string): Dependency[] {
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

function parseBunLock(content: string, filePath: string): Dependency[] {
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

function parsePoetryLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  
  try {
    // Poetry.lock is a TOML file format
    const lines = content.split('\n');
    let inPackage = false;
    let currentPackage: { name?: string; version?: string; category?: string } | null = null;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Start of a new package entry: [[package]]
      if (trimmed === '[[package]]') {
        // Save previous package
        if (currentPackage?.name && currentPackage?.version) {
          const key = `${currentPackage.name}@${currentPackage.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            dependencies.push({
              name: currentPackage.name,
              version: currentPackage.version,
              versionSpec: currentPackage.version,
              ecosystem: 'pypi',
              file: filePath,
              isDev: currentPackage.category === 'dev',
              isPinned: true, // Poetry.lock versions are always pinned
            });
          }
        }
        currentPackage = {};
        inPackage = true;
        continue;
      }
      
      if (!inPackage || !currentPackage) continue;
      
      // Parse name
      const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
      if (nameMatch) {
        currentPackage.name = nameMatch[1];
      }
      
      // Parse version
      const versionMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
      if (versionMatch) {
        currentPackage.version = versionMatch[1];
      }
      
      // Parse category (dev vs main)
      const categoryMatch = trimmed.match(/^category\s*=\s*"([^"]+)"/);
      if (categoryMatch) {
        currentPackage.category = categoryMatch[1];
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
          ecosystem: 'pypi',
          file: filePath,
          isDev: currentPackage.category === 'dev',
          isPinned: true,
        });
      }
    }
  } catch (error) {
    // Skip on parse error
  }
  
  return dependencies;
}

function parsePipfileLock(content: string, filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  
  try {
    const lockfile = JSON.parse(content);
    
    // Parse default (production) dependencies
    if (lockfile.default) {
      for (const [name, pkg] of Object.entries(lockfile.default)) {
        if (!pkg || typeof pkg !== 'object') continue;
        
        const pkgData = pkg as Record<string, unknown>;
        const version = (pkgData.version as string) || '';
        
        if (version) {
          // Version is typically "==1.0.0" format, clean it up
          const cleanVersion = version.replace(/^==/, '');
          
          dependencies.push({
            name,
            version: cleanVersion,
            versionSpec: version,
            ecosystem: 'pypi',
            file: filePath,
            isDev: false,
            isPinned: true, // Pipfile.lock versions are always pinned
          });
        }
      }
    }
    
    // Parse develop (dev) dependencies
    if (lockfile.develop) {
      for (const [name, pkg] of Object.entries(lockfile.develop)) {
        if (!pkg || typeof pkg !== 'object') continue;
        
        const pkgData = pkg as Record<string, unknown>;
        const version = (pkgData.version as string) || '';
        
        if (version) {
          // Version is typically "==1.0.0" format, clean it up
          const cleanVersion = version.replace(/^==/, '');
          
          dependencies.push({
            name,
            version: cleanVersion,
            versionSpec: version,
            ecosystem: 'pypi',
            file: filePath,
            isDev: true,
            isPinned: true,
          });
        }
      }
    }
  } catch (error) {
    // Invalid JSON, skip
  }
  
  return dependencies;
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
