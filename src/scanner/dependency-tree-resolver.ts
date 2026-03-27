import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const REGISTRY_CACHE = new Map<string, any>();
const PYPI_REGISTRY_CACHE = new Map<string, any>();

async function fetchPackageFromRegistry(name: string, versionSpec: string): Promise<any | null> {
  const cacheKey = `${name}@${versionSpec}`;
  if (REGISTRY_CACHE.has(cacheKey)) {
    return REGISTRY_CACHE.get(cacheKey);
  }

  try {
    // Normalize version spec to get a concrete version
    const normalizedVersion = versionSpec.replace(/^[^\d]*/, '') || 'latest';
    const url = `https://registry.npmjs.org/${name}/${normalizedVersion}`;

    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
      // Try with 'latest' tag if specific version fails
      if (normalizedVersion !== 'latest') {
        const latestUrl = `https://registry.npmjs.org/${name}/latest`;
        const latestResponse = await fetch(latestUrl, {
          headers: { 'Accept': 'application/json' },
        });
        if (latestResponse.ok) {
          const data = await latestResponse.json();
          REGISTRY_CACHE.set(cacheKey, data);
          return data;
        }
      }
      return null;
    }

    const data = await response.json();
    REGISTRY_CACHE.set(cacheKey, data);
    return data;
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
    // Normalize version spec to get a concrete version
    const normalizedVersion = versionSpec.replace(/^[>=<~!^]+/, '') || 'latest';
    const url = normalizedVersion === 'latest'
      ? `https://pypi.org/pypi/${name}/json`
      : `https://pypi.org/pypi/${name}/${normalizedVersion}/json`;

    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
      // Try with latest if specific version fails
      if (normalizedVersion !== 'latest') {
        const latestUrl = `https://pypi.org/pypi/${name}/json`;
        const latestResponse = await fetch(latestUrl, {
          headers: { 'Accept': 'application/json' },
        });
        if (latestResponse.ok) {
          const data = await latestResponse.json();
          PYPI_REGISTRY_CACHE.set(cacheKey, data);
          return data;
        }
      }
      return null;
    }

    const data = await response.json();
    PYPI_REGISTRY_CACHE.set(cacheKey, data);
    return data;
  } catch (error) {
    return null;
  }
}

export interface DependencyNode {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
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
}

const MAX_DEPTH = 10;
const resolvedCache = new Map<string, any>();

const CRATES_REGISTRY_CACHE = new Map<string, any>();
const GO_PROXY_CACHE = new Map<string, any>();

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
  currentPath: string[]
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
        [...currentPath, name]
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
  currentPath: string[]
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
          [...currentPath, name]
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
    // Normalize version spec to get a concrete version
    const normalizedVersion = versionSpec.replace(/^[>=<~!^]+/, '') || 'latest';
    const url = `https://crates.io/api/v1/crates/${name}`;

    const response = await fetch(url, {
      headers: { 
        'Accept': 'application/json',
        'User-Agent': 'who-touched-my-deps (security scanner)'
      },
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    CRATES_REGISTRY_CACHE.set(cacheKey, data);
    return data;
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
    const response = await fetch(url, {
      headers: { 
        'Accept': 'application/json',
        'User-Agent': 'who-touched-my-deps (security scanner)'
      },
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as { dependencies?: any[] };
    const dependencies = data.dependencies || [];
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
  currentPath: string[]
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
          [...currentPath, name]
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
    // Go module proxy URL format
    const encodedName = name.replace(/\//g, '%2F');
    const version = versionSpec.replace(/^[>=<~!^]+/, '').replace(/^v/, '') || 'latest';
    const url = `https://proxy.golang.org/${encodedName}/@v/v${version}.info`;

    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
      // Try without v prefix
      const urlNoV = `https://proxy.golang.org/${encodedName}/@v/${version}.info`;
      const responseNoV = await fetch(urlNoV, {
        headers: { 'Accept': 'application/json' },
      });
      
      if (!responseNoV.ok) {
        return null;
      }
      
      const data = await responseNoV.json();
      GO_PROXY_CACHE.set(cacheKey, data);
      return data;
    }

    const data = await response.json();
    GO_PROXY_CACHE.set(cacheKey, data);
    return data;
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
  currentPath: string[]
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
          [...currentPath, name]
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
    const encodedName = name.replace(/\//g, '%2F');
    const cleanVersion = version.replace(/^v/, '');
    // Try to fetch go.mod from the module proxy
    const url = `https://proxy.golang.org/${encodedName}/@v/v${cleanVersion}.mod`;
    
    const response = await fetch(url);
    if (!response.ok) {
      // Try without v prefix
      const urlNoV = `https://proxy.golang.org/${encodedName}/@v/${cleanVersion}.mod`;
      const responseNoV = await fetch(urlNoV);
      if (!responseNoV.ok) {
        return null;
      }
      return await responseNoV.text();
    }
    return await response.text();
  } catch (error) {
    return null;
  }
}

export async function buildDependencyTree(
  rootFile: string,
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go'
): Promise<DependencyTree> {
  const tree: DependencyTree = {
    roots: [],
    allNodes: new Map(),
    edges: [],
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
            []
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
            []
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
        
        // Parse package specification: package==1.0.0, package>=1.0.0, package~=1.0.0, package
        const match = trimmed.match(/^([a-zA-Z0-9_.-]+)([>=<~!]+)?(.+)?/);
        
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
            []
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
          []
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
          []
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
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
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
