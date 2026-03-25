import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { existsSync } from 'node:fs';

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

const MAX_DEPTH = 5;
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
  
  const packageJsonPath = await findPackageJson(name, parentFile);
  if (!packageJsonPath) {
    return {
      name,
      version: versionSpec.replace(/^[\^~>=<]+/, ''),
      versionSpec,
      ecosystem: 'npm',
      file: parentFile,
      isDev,
      dependencies: [],
      depth,
      paths: [[...currentPath, name]],
    };
  }
  
  try {
    const content = await readFile(packageJsonPath, 'utf-8');
    const pkg = JSON.parse(content);
    const version = pkg.version || versionSpec.replace(/^[\^~>=<]+/, '');
    
    const node: DependencyNode = {
      name,
      version,
      versionSpec,
      ecosystem: 'npm',
      file: packageJsonPath,
      isDev,
      dependencies: [],
      depth,
      paths: [[...currentPath, name]],
    };
    
    if (pkg.dependencies && depth < MAX_DEPTH - 1) {
      for (const [depName, depVersion] of Object.entries(pkg.dependencies)) {
        const childNode = await resolveNpmDependency(
          depName,
          depVersion as string,
          packageJsonPath,
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
  } catch (error) {
    return {
      name,
      version: versionSpec.replace(/^[\^~>=<]+/, ''),
      versionSpec,
      ecosystem: 'npm',
      file: parentFile,
      isDev,
      dependencies: [],
      depth,
      paths: [[...currentPath, name]],
    };
  }
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
