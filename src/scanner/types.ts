export interface DependencyFile {
  path: string;
  type: 'package.json' | 'requirements.txt' | 'Cargo.toml' | 'Cargo.lock' | 'go.mod' | 'go.sum' | 'Gemfile.lock';
  relativePath: string;
}

export interface Dependency {
  name: string;
  version: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cratesio' | 'golang' | 'ruby';
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

export interface UnresolvedDependency {
  name: string;
  versionSpec: string;
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby';
  file: string;
  isDev?: boolean;
  reason: 'not_found' | 'registry_unavailable' | 'no_access' | 'invalid_spec';
}

export interface ScanResult {
  files: DependencyFile[];
  dependencies: Dependency[];
  dependencyEdges?: DependencyEdge[];
  unresolvedDependencies?: UnresolvedDependency[];
  scanPath: string;
  timestamp: Date;
}
