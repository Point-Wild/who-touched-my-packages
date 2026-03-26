export interface DependencyFile {
  path: string;
  type: 'package.json' | 'requirements.txt';
  relativePath: string;
}

export interface Dependency {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi';
  file: string;
  isDev?: boolean;
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
