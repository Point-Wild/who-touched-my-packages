import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const REGISTRY_CACHE = new Map<string, any>();

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

export interface DependencyNode {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi';
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

export async function buildDependencyTree(
  rootFile: string,
  ecosystem: 'npm' | 'pypi'
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
  ecosystem: 'npm' | 'pypi';
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
