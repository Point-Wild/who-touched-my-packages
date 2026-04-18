import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import {
  registryFetchRaw,
  registryFetchJson,
  registryFetchText,
  NPM_REGISTRY_CACHE,
  PYPI_REGISTRY_CACHE,
  CRATES_REGISTRY_CACHE,
  GO_PROXY_CACHE,
  RUBYGEMS_CACHE,
} from './registry-cache.js';

const REGISTRY_CACHE = NPM_REGISTRY_CACHE;

async function fetchPackageFromRegistry(name: string, versionSpec: string): Promise<any | null> {
  const cacheKey = `${name}@${versionSpec}`;
  if (REGISTRY_CACHE.has(cacheKey)) {
    return REGISTRY_CACHE.get(cacheKey);
  }

  try {
    const normalizedVersion = versionSpec.replace(/^[^\d]*/, '') || 'latest';
    const url = `https://registry.npmjs.org/${name}/${normalizedVersion}`;

    let result = await registryFetchRaw(url, { headers: { 'Accept': 'application/json' } });

    if (!result.ok && normalizedVersion !== 'latest') {
      const latestUrl = `https://registry.npmjs.org/${name}/latest`;
      result = await registryFetchRaw(latestUrl, { headers: { 'Accept': 'application/json' } });
    }

    if (!result.ok) return null;

    REGISTRY_CACHE.set(cacheKey, result.data);
    return result.data;
  } catch (error) {
    return null;
  }
}

async function fetchPypiPackageFromRegistry(name: string, versionSpec: string): Promise<any | null> {
  const cacheKey = `${name}@${versionSpec}`;
  if (PYPI_REGISTRY_CACHE.has(cacheKey)) {
    return PYPI_REGISTRY_CACHE.get(cacheKey);
  }

  try {
    const normalizedVersion = versionSpec.replace(/^[>=<~!^]+/, '').trim() || 'latest';
    const url = normalizedVersion === 'latest'
      ? `https://pypi.org/pypi/${name}/json`
      : `https://pypi.org/pypi/${name}/${normalizedVersion}/json`;

    let result = await registryFetchRaw(url, { headers: { 'Accept': 'application/json' } });

    if (!result.ok && normalizedVersion !== 'latest') {
      const latestUrl = `https://pypi.org/pypi/${name}/json`;
      result = await registryFetchRaw(latestUrl, { headers: { 'Accept': 'application/json' } });
    }

    if (!result.ok) return null;

    PYPI_REGISTRY_CACHE.set(cacheKey, result.data);
    return result.data;
  } catch (error) {
    return null;
  }
}

export interface DependencyNode {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';
  file: string;
  isDev?: boolean;
  dependencies: DependencyNode[];
  parent?: string;
  depth: number;
  paths: string[][];
}

export interface DependencyTree {
  roots: DependencyNode[];
  allNodes: Map<string, DependencyNode>;
  edges: Array<{ source: string; target: string; type: 'dependency' | 'dev' }>;
  unresolved: Array<{ name: string; versionSpec: string; ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby'; file: string; isDev?: boolean; reason: 'not_found' | 'registry_unavailable' | 'no_access' | 'invalid_spec' }>;
}

const MAX_DEPTH = 10;
const resolvedCache = new Map<string, any>();

async function findPackageJson(packageName: string, startPath: string): Promise<string | null> {
  let currentPath = dirname(startPath);
  
  for (let i = 0; i < 10; i++) {
    const nodeModulesPath = join(currentPath, 'node_modules', packageName, 'package.json');
    if (existsSync(nodeModulesPath)) {
      return nodeModulesPath;
    }
    
    const parentPath = dirname(currentPath);
    if (parentPath === currentPath) break;
    currentPath = parentPath;
  }
  
  return null;
}

async function resolveNpmDependency(
  name: string,
  versionSpec: string,
  parentFile: string,
  isDev: boolean,
  depth: number,
  visited: Set<string>,
  currentPath: string[],
  tree: DependencyTree
): Promise<DependencyNode | null> {
  if (depth >= MAX_DEPTH) return null;
  
  const nodeKey = `${name}@${versionSpec}`;
  if (visited.has(nodeKey)) {
    return null;
  }
  
  visited.add(nodeKey);
  
  // Try to find package locally first
  const packageJsonPath = await findPackageJson(name, parentFile);
  
  let pkg: any = null;
  let resolvedVersion = versionSpec.replace(/^[\^~>=<]+/, '');
  let sourceFile = packageJsonPath || parentFile;
  
  if (packageJsonPath) {
    // Package found locally - read from node_modules
    try {
      const content = await readFile(packageJsonPath, 'utf-8');
      pkg = JSON.parse(content);
      resolvedVersion = pkg.version || resolvedVersion;
      sourceFile = packageJsonPath;
    } catch (error) {
      // Fall through to registry fetch
    }
  }
  
  // If not found locally or failed to read, fetch from registry
  if (!pkg) {
    pkg = await fetchPackageFromRegistry(name, versionSpec);
    if (pkg) {
      resolvedVersion = pkg.version || resolvedVersion;
    }
  }
  
  // If still no package data, track as unresolved
  if (!pkg) {
    tree.unresolved.push({
      name,
      versionSpec,
      ecosystem: 'npm',
      file: parentFile,
      isDev,
      reason: 'not_found',
    });
    return null;
  }
  
  const node: DependencyNode = {
    name,
    version: resolvedVersion,
    versionSpec,
    ecosystem: 'npm',
    file: sourceFile,
    isDev,
    dependencies: [],
    depth,
    paths: [[...currentPath, name]],
  };
  
  // Recursively resolve dependencies if we have package data
  if (pkg?.dependencies && depth < MAX_DEPTH - 1) {
    for (const [depName, depVersion] of Object.entries(pkg.dependencies)) {
      const childNode = await resolveNpmDependency(
        depName,
        depVersion as string,
        sourceFile,
        false,
        depth + 1,
        visited,
        [...currentPath, name],
        tree
      );
      if (childNode) {
        node.dependencies.push(childNode);
      }
    }
  }
  
  return node;
}

async function resolvePypiDependency(
  name: string,
  versionSpec: string,
  parentFile: string,
  isDev: boolean,
  depth: number,
  visited: Set<string>,
  currentPath: string[],
  tree: DependencyTree
): Promise<DependencyNode | null> {
  if (depth >= MAX_DEPTH) return null;
  
  const nodeKey = `${name}@${versionSpec}`;
  if (visited.has(nodeKey)) {
    return null;
  }
  
  visited.add(nodeKey);
  
  // Fetch from PyPI registry
  const pkg = await fetchPypiPackageFromRegistry(name, versionSpec);
  let resolvedVersion = versionSpec.replace(/^[>=<~!^]+/, '') || 'latest';
  
  if (pkg?.info?.version) {
    resolvedVersion = pkg.info.version;
  }
  
  // If no package data, track as unresolved
  if (!pkg) {
    tree.unresolved.push({
      name,
      versionSpec,
      ecosystem: 'pypi',
      file: parentFile,
      isDev,
      reason: 'not_found',
    });
    return null;
  }
  
  const node: DependencyNode = {
    name,
    version: resolvedVersion,
    versionSpec,
    ecosystem: 'pypi',
    file: parentFile,
    isDev,
    dependencies: [],
    depth,
    paths: [[...currentPath, name]],
  };
  
  // Recursively resolve dependencies if we have package data
  // PyPI info may have requires_dist array with dependency specs
  if (pkg?.info?.requires_dist && depth < MAX_DEPTH - 1) {
    for (const req of pkg.info.requires_dist) {
      // Parse requirement format like "package-name (>=1.0.0)" or "package-name>=1.0.0"
      const match = req.match(/^([a-zA-Z0-9_.-]+)(?:\s*\(([>=<~!^0-9.]+)\)|([>=<~!^0-9.]+))?/);
      if (match) {
        const depName = match[1];
        const depVersion = match[2] || match[3] || '*';
        
        // Skip optional/extra dependencies marked with ;
        if (req.includes(';')) continue;
        
        const childNode = await resolvePypiDependency(
          depName,
          depVersion,
          parentFile,
          false,
          depth + 1,
          visited,
          [...currentPath, name],
          tree
        );
        if (childNode) {
          node.dependencies.push(childNode);
        }
      }
    }
  }
  
  return node;
}

async function fetchCrateFromRegistry(name: string, versionSpec: string): Promise<any | null> {
  const cacheKey = `${name}@${versionSpec}`;
  if (CRATES_REGISTRY_CACHE.has(cacheKey)) {
    return CRATES_REGISTRY_CACHE.get(cacheKey);
  }

  try {
    const url = `https://crates.io/api/v1/crates/${name}`;
    const headers = {
      'Accept': 'application/json',
      'User-Agent': 'who-touched-my-packages (security scanner)',
    };

    const result = await registryFetchRaw(url, { headers });
    if (!result.ok) return null;

    CRATES_REGISTRY_CACHE.set(cacheKey, result.data);
    return result.data;
  } catch (error) {
    return null;
  }
}

async function fetchCrateDependencies(name: string, version: string): Promise<any[] | null> {
  const cacheKey = `deps:${name}@${version}`;
  if (CRATES_REGISTRY_CACHE.has(cacheKey)) {
    return CRATES_REGISTRY_CACHE.get(cacheKey);
  }

  try {
    const url = `https://crates.io/api/v1/crates/${name}/${version}/dependencies`;
    const headers = {
      'Accept': 'application/json',
      'User-Agent': 'who-touched-my-packages (security scanner)',
    };

    const result = await registryFetchRaw(url, { headers });
    if (!result.ok) return null;

    const dependencies = result.data.dependencies || [];
    CRATES_REGISTRY_CACHE.set(cacheKey, dependencies);
    return dependencies;
  } catch (error) {
    return null;
  }
}

interface CargoDepInfo {
  name: string;
  versionSpec: string;
  isDev?: boolean;
}

function parseCargoTomlForTree(content: string): CargoDepInfo[] {
  const dependencies: CargoDepInfo[] = [];
  const lines = content.split('\n');
  let inDependencies = false;
  let inDevDependencies = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Check for section headers
    if (trimmed.startsWith('[')) {
      const section = trimmed.replace(/\[|\]/g, '').trim();
      inDependencies = section === 'dependencies' || section.endsWith('.dependencies');
      inDevDependencies = section === 'dev-dependencies' || section === 'build-dependencies';
      continue;
    }
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Parse dependency lines
    if (inDependencies || inDevDependencies) {
      // Match simple format: name = "version"
      const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (simpleMatch) {
        dependencies.push({
          name: simpleMatch[1],
          versionSpec: simpleMatch[2],
          isDev: inDevDependencies,
        });
      } else {
        // Match inline table format: name = { version = "1.0" }
        const tableMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{/);
        if (tableMatch) {
          const name = tableMatch[1];
          const versionMatch = trimmed.match(/version\s*=\s*"([^"]+)"/);
          const versionSpec = versionMatch ? versionMatch[1] : '*';
          
          dependencies.push({
            name,
            versionSpec,
            isDev: inDevDependencies,
          });
        }
      }
    }
  }
  
  return dependencies;
}

async function resolveCargoDependency(
  name: string,
  versionSpec: string,
  parentFile: string,
  isDev: boolean,
  depth: number,
  visited: Set<string>,
  currentPath: string[],
  tree: DependencyTree
): Promise<DependencyNode | null> {
  if (depth >= MAX_DEPTH) return null;
  
  const nodeKey = `${name}@${versionSpec}`;
  if (visited.has(nodeKey)) {
    return null;
  }
  
  visited.add(nodeKey);
  
  // Fetch from crates.io registry
  const crate = await fetchCrateFromRegistry(name, versionSpec);
  let resolvedVersion = versionSpec.replace(/^[>=<~!^]+/, '') || 'latest';
  
  if (crate?.crate?.max_version) {
    resolvedVersion = crate.crate.max_version;
  } else if (crate?.crate?.max_stable_version) {
    resolvedVersion = crate.crate.max_stable_version;
  }
  
  // Find specific version in versions array if available
  if (crate?.versions) {
    const targetVersion = resolvedVersion === 'latest' 
      ? crate.versions.find((v: any) => v.num === crate.crate?.max_stable_version || v.num === crate.crate?.max_version)
      : crate.versions.find((v: any) => v.num === resolvedVersion);
    
    if (targetVersion) {
      resolvedVersion = targetVersion.num;
    }
  }
  
  // If no crate data, track as unresolved
  if (!crate) {
    tree.unresolved.push({
      name,
      versionSpec,
      ecosystem: 'cargo',
      file: parentFile,
      isDev,
      reason: 'not_found',
    });
    return null;
  }
  
  const node: DependencyNode = {
    name,
    version: resolvedVersion,
    versionSpec,
    ecosystem: 'cargo',
    file: parentFile,
    isDev,
    dependencies: [],
    depth,
    paths: [[...currentPath, name]],
  };
  
  // Fetch dependencies from separate crates.io endpoint
  if (depth < MAX_DEPTH - 1) {
    const deps = await fetchCrateDependencies(name, resolvedVersion);
    
    if (deps) {
      for (const dep of deps) {
        // Skip optional dependencies and dev-dependencies for tree simplicity
        if (dep.optional || dep.kind === 'dev') continue;
        
        const childNode = await resolveCargoDependency(
          dep.crate_name || dep.crate_id,
          dep.req || '*',
          parentFile,
          dep.kind === 'dev',
          depth + 1,
          new Set(visited),
          [...currentPath, name],
          tree
        );
        if (childNode) {
          node.dependencies.push(childNode);
        }
      }
    }
  }
  
  return node;
}

interface GoDepInfo {
  name: string;
  versionSpec: string;
  isDev?: boolean;
}

/**
 * Escape a Go module path for the module proxy URL.
 * Uppercase letters are encoded as !lowercase per the Go module proxy spec.
 */
function escapeGoModulePath(modulePath: string): string {
  return modulePath
    .replace(/^["']+|["']+$/g, '')  // strip surrounding quotes
    .split('/')
    .map(segment =>
      encodeURIComponent(segment.replace(/[A-Z]/g, match => `!${match.toLowerCase()}`))
    )
    .join('/');
}

function parseGoModForTree(content: string): GoDepInfo[] {
  const dependencies: GoDepInfo[] = [];
  const lines = content.split('\n');
  let inRequire = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    if (trimmed.startsWith('require (')) {
      inRequire = true;
      continue;
    }
    
    if (inRequire && trimmed === ')') {
      inRequire = false;
      continue;
    }
    
    if (!inRequire && trimmed.startsWith('require ')) {
      const reqMatch = trimmed.match(/require\s+(\S+)\s+(\S+)/);
      if (reqMatch) {
        dependencies.push({
          name: reqMatch[1],
          versionSpec: reqMatch[2],
          isDev: trimmed.includes('// indirect'),
        });
      }
      continue;
    }
    
    if (inRequire) {
      const match = trimmed.match(/^(\S+)\s+(\S+)/);
      if (match) {
        dependencies.push({
          name: match[1],
          versionSpec: match[2],
          isDev: trimmed.includes('// indirect'),
        });
      }
    }
  }
  
  return dependencies;
}

async function fetchGoModuleFromProxy(name: string, versionSpec: string): Promise<any | null> {
  const cacheKey = `${name}@${versionSpec}`;
  if (GO_PROXY_CACHE.has(cacheKey)) {
    return GO_PROXY_CACHE.get(cacheKey);
  }

  try {
    const encodedName = escapeGoModulePath(name);
    const version = versionSpec.replace(/^[>=<~!^]+/, '').replace(/^v/, '') || 'latest';
    const url = `https://proxy.golang.org/${encodedName}/@v/v${version}.info`;

    let result = await registryFetchRaw(url, { headers: { 'Accept': 'application/json' } });

    if (!result.ok) {
      const urlNoV = `https://proxy.golang.org/${encodedName}/@v/${version}.info`;
      result = await registryFetchRaw(urlNoV, { headers: { 'Accept': 'application/json' } });
    }

    if (!result.ok) return null;

    GO_PROXY_CACHE.set(cacheKey, result.data);
    return result.data;
  } catch (error) {
    return null;
  }
}

async function resolveGoDependency(
  name: string,
  versionSpec: string,
  parentFile: string,
  isDev: boolean,
  depth: number,
  visited: Set<string>,
  currentPath: string[],
  tree: DependencyTree
): Promise<DependencyNode | null> {
  if (depth >= MAX_DEPTH) return null;
  
  const nodeKey = `${name}@${versionSpec}`;
  if (visited.has(nodeKey)) {
    return null;
  }
  
  visited.add(nodeKey);
  
  // Fetch from Go module proxy
  const module = await fetchGoModuleFromProxy(name, versionSpec);
  let resolvedVersion = versionSpec.replace(/^[>=<~!^]+/, '').replace(/^v/, '') || 'latest';
  
  if (module?.Version) {
    resolvedVersion = module.Version.replace(/^v/, '');
  }
  
  // If no module data, track as unresolved
  if (!module) {
    tree.unresolved.push({
      name,
      versionSpec,
      ecosystem: 'go',
      file: parentFile,
      isDev,
      reason: 'not_found',
    });
    return null;
  }
  
  const node: DependencyNode = {
    name,
    version: resolvedVersion,
    versionSpec,
    ecosystem: 'go',
    file: parentFile,
    isDev,
    dependencies: [],
    depth,
    paths: [[...currentPath, name]],
  };
  
  // Fetch transitive dependencies from the module's go.mod
  if (depth < MAX_DEPTH - 1) {
    const goModContent = await fetchGoModFromProxy(name, resolvedVersion);
    if (goModContent) {
      const transitiveDeps = parseGoModForTree(goModContent);
      
      for (const dep of transitiveDeps) {
        // Skip indirect dependencies to reduce noise
        if (dep.isDev) continue;
        
        const childNode = await resolveGoDependency(
          dep.name,
          dep.versionSpec,
          parentFile,
          dep.isDev || false,
          depth + 1,
          new Set(visited),
          [...currentPath, name],
          tree
        );
        if (childNode) {
          node.dependencies.push(childNode);
        }
      }
    }
  }
  
  return node;
}

async function fetchGoModFromProxy(name: string, version: string): Promise<string | null> {
  try {
    const encodedName = escapeGoModulePath(name);
    const cleanVersion = version.replace(/^v/, '');
    const url = `https://proxy.golang.org/${encodedName}/@v/v${cleanVersion}.mod`;

    let text = await registryFetchText(url);
    if (text === null) {
      const urlNoV = `https://proxy.golang.org/${encodedName}/@v/${cleanVersion}.mod`;
      text = await registryFetchText(urlNoV);
    }
    return text;
  } catch (error) {
    return null;
  }
}

interface RubyDepInfo {
  name: string;
  versionSpec: string;
  isDev?: boolean;
}

function parseGemfileLockForTree(content: string): RubyDepInfo[] {
  const dependencies: RubyDepInfo[] = [];
  const seen = new Set<string>();
  const lines = content.split('\n');
  let inSpecsSection = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
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
    
    if (inSpecsSection && (trimmed === '' || trimmed.startsWith('PLATFORMS') || trimmed.startsWith('BUNDLED WITH'))) {
      inSpecsSection = false;
      continue;
    }
    
    if (inSpecsSection) {
      const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*\(([0-9][^)]*)\)/);
      if (match) {
        const version = match[2].trim().replace(/-[a-z][\w-]*$/, '');
        const key = `${match[1]}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          dependencies.push({
            name: match[1],
            versionSpec: version,
            isDev: false,
          });
        }
      }
    }
  }

  return dependencies;
}

async function fetchGemFromRubygems(name: string, versionSpec: string): Promise<any | null> {
  const cacheKey = `${name}@${versionSpec}`;
  if (RUBYGEMS_CACHE.has(cacheKey)) {
    return RUBYGEMS_CACHE.get(cacheKey);
  }

  try {
    // Version specs from gemspecs can be constraints like ">= 1.0, < 2" or "~> 5.1".
    // Extract the first concrete version number, or fall back to the latest.
    const firstVersion = versionSpec
      .split(',')[0]                    // take first constraint
      .replace(/^[>=<~!^]+/, '')        // strip operators
      .trim();
    const normalizedVersion = (firstVersion && /^\d+\.\d+/.test(firstVersion))
      ? firstVersion
      : 'latest';
    const url = normalizedVersion === 'latest'
      ? `https://rubygems.org/api/v1/gems/${name}.json`
      : `https://rubygems.org/api/v2/rubygems/${name}/versions/${normalizedVersion}.json`;

    let result = await registryFetchRaw(url, { headers: { 'Accept': 'application/json' } });

    // v2 version-specific endpoint can 404 for short versions (e.g. "1.4");
    // fall back to the v1 gems endpoint which returns the latest version.
    if (!result.ok && normalizedVersion !== 'latest') {
      const fallbackUrl = `https://rubygems.org/api/v1/gems/${name}.json`;
      result = await registryFetchRaw(fallbackUrl, { headers: { 'Accept': 'application/json' } });
    }
    if (!result.ok) return null;

    RUBYGEMS_CACHE.set(cacheKey, result.data);
    return result.data;
  } catch (error) {
    return null;
  }
}

async function resolveRubyDependency(
  name: string,
  versionSpec: string,
  parentFile: string,
  isDev: boolean,
  depth: number,
  visited: Set<string>,
  currentPath: string[],
  tree: DependencyTree
): Promise<DependencyNode | null> {
  if (depth >= MAX_DEPTH) return null;
  
  const nodeKey = `${name}@${versionSpec}`;
  if (visited.has(nodeKey)) {
    return null;
  }
  
  visited.add(nodeKey);
  
  const gem = await fetchGemFromRubygems(name, versionSpec);
  let resolvedVersion = versionSpec.replace(/^[>=<~!^]+/, '').trim() || 'latest';
  
  if (gem?.version) {
    resolvedVersion = gem.version;
  }
  
  // If no gem data, track as unresolved
  if (!gem) {
    tree.unresolved.push({
      name,
      versionSpec,
      ecosystem: 'ruby',
      file: parentFile,
      isDev,
      reason: 'not_found',
    });
    return null;
  }
  
  const node: DependencyNode = {
    name,
    version: resolvedVersion,
    versionSpec,
    ecosystem: 'ruby',
    file: parentFile,
    isDev,
    dependencies: [],
    depth,
    paths: [[...currentPath, name]],
  };
  
  if (depth < MAX_DEPTH - 1 && gem?.dependencies) {
    for (const dep of gem.dependencies.runtime || []) {
      const childNode = await resolveRubyDependency(
        dep.name,
        dep.requirements || '*',
        parentFile,
        false,
        depth + 1,
        new Set(visited),
        [...currentPath, name],
        tree
      );
      if (childNode) {
        node.dependencies.push(childNode);
      }
    }
  }
  
  return node;
}

export async function buildDependencyTree(
  rootFile: string,
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby'
): Promise<DependencyTree> {
  const tree: DependencyTree = {
    roots: [],
    allNodes: new Map(),
    edges: [],
    unresolved: [],
  };
  
  if (ecosystem === 'npm') {
    try {
      const content = await readFile(rootFile, 'utf-8');
      const pkg = JSON.parse(content);
      const visited = new Set<string>();
      
      if (pkg.dependencies) {
        for (const [name, version] of Object.entries(pkg.dependencies)) {
          const node = await resolveNpmDependency(
            name,
            version as string,
            rootFile,
            false,
            0,
            visited,
            [],
            tree
          );
          if (node) {
            tree.roots.push(node);
            collectNodesAndEdges(node, tree, null, 'dependency');
          }
        }
      }
      
      if (pkg.devDependencies) {
        for (const [name, version] of Object.entries(pkg.devDependencies)) {
          const node = await resolveNpmDependency(
            name,
            version as string,
            rootFile,
            true,
            0,
            visited,
            [],
            tree
          );
          if (node) {
            tree.roots.push(node);
            collectNodesAndEdges(node, tree, null, 'dev');
          }
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${rootFile}:`, error);
    }
  }
  
  if (ecosystem === 'pypi') {
    try {
      const content = await readFile(rootFile, 'utf-8');
      const lines = content.split('\n');
      const visited = new Set<string>();
      
      for (const line of lines) {
        const trimmed = line.trim();
        
        // Skip empty lines, comments, and option lines
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
          continue;
        }

        const withoutComment = trimmed.split('#')[0].trim();
        if (!withoutComment) continue;

        // Parse package specification: package==1.0.0, package>=1.0.0, package~=1.0.0, package
        const match = withoutComment.match(/^([a-zA-Z0-9_.-]+)([>=<~!]+)?(.+)?/);
        
        if (match) {
          const name = match[1];
          const operator = match[2] || '';
          const version = match[3] || '*';
          const versionSpec = operator + version;
          
          const node = await resolvePypiDependency(
            name,
            versionSpec,
            rootFile,
            false,
            0,
            visited,
            [],
            tree
          );
          if (node) {
            tree.roots.push(node);
            collectNodesAndEdges(node, tree, null, 'dependency');
          }
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${rootFile}:`, error);
    }
  }

  if (ecosystem === 'cargo') {
    try {
      const content = await readFile(rootFile, 'utf-8');
      const visited = new Set<string>();
      const dependencies = parseCargoTomlForTree(content);
      
      for (const dep of dependencies) {
        const node = await resolveCargoDependency(
          dep.name,
          dep.versionSpec,
          rootFile,
          dep.isDev || false,
          0,
          visited,
          [],
          tree
        );
        if (node) {
          tree.roots.push(node);
          collectNodesAndEdges(node, tree, null, dep.isDev ? 'dev' : 'dependency');
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${rootFile}:`, error);
    }
  }

  if (ecosystem === 'go') {
    try {
      const content = await readFile(rootFile, 'utf-8');
      const visited = new Set<string>();
      const dependencies = parseGoModForTree(content);
      
      for (const dep of dependencies) {
        const node = await resolveGoDependency(
          dep.name,
          dep.versionSpec,
          rootFile,
          dep.isDev || false,
          0,
          visited,
          [],
          tree
        );
        if (node) {
          tree.roots.push(node);
          collectNodesAndEdges(node, tree, null, dep.isDev ? 'dev' : 'dependency');
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${rootFile}:`, error);
    }
  }
  
  if (ecosystem === 'ruby') {
    try {
      const content = await readFile(rootFile, 'utf-8');
      const visited = new Set<string>();
      const dependencies = parseGemfileLockForTree(content);
      
      for (const dep of dependencies) {
        const node = await resolveRubyDependency(
          dep.name,
          dep.versionSpec,
          rootFile,
          dep.isDev || false,
          0,
          visited,
          [],
          tree
        );
        if (node) {
          tree.roots.push(node);
          collectNodesAndEdges(node, tree, null, dep.isDev ? 'dev' : 'dependency');
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${rootFile}:`, error);
    }
  }
  
  return tree;
}

function collectNodesAndEdges(
  node: DependencyNode,
  tree: DependencyTree,
  parentId: string | null,
  edgeType: 'dependency' | 'dev'
): void {
  const nodeId = `${node.name}@${node.version}`;
  
  if (tree.allNodes.has(nodeId)) {
    const existingNode = tree.allNodes.get(nodeId)!;
    existingNode.paths.push(...node.paths);
    
    if (parentId) {
      const edgeExists = tree.edges.some(
        e => e.source === parentId && e.target === nodeId
      );
      if (!edgeExists) {
        tree.edges.push({ source: parentId, target: nodeId, type: edgeType });
      }
    }
    return;
  }
  
  tree.allNodes.set(nodeId, node);
  
  if (parentId) {
    tree.edges.push({ source: parentId, target: nodeId, type: edgeType });
  }
  
  for (const child of node.dependencies) {
    collectNodesAndEdges(child, tree, nodeId, 'dependency');
  }
}

export function flattenDependencyTree(tree: DependencyTree): Array<{
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';
  file: string;
  isDev?: boolean;
  depth: number;
  paths: string[][];
}> {
  return Array.from(tree.allNodes.values()).map(node => ({
    name: node.name,
    version: node.version,
    versionSpec: node.versionSpec,
    ecosystem: node.ecosystem,
    file: node.file,
    isDev: node.isDev,
    depth: node.depth,
    paths: node.paths,
  }));
}
