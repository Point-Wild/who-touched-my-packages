export interface DependencyFile {
  path: string;
  type: 'package.json' | 'requirements.txt' | 'Cargo.toml' | 'Cargo.lock' | 'go.mod' | 'go.sum';
  relativePath: string;
}

export interface Dependency {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go';
  file: string;
  isDev?: boolean;
  isPinned?: boolean;
  depth?: number;
  paths?: string[][];
  provenance?: boolean;
}

export interface DependencyEdge {
  source: string;
  target: string;
  type: 'dependency' | 'dev';
}

export interface ScanResult {
  files: DependencyFile[];
  dependencies: Dependency[];
  dependencyEdges?: DependencyEdge[];
  scanPath: string;
  timestamp: Date;
}
