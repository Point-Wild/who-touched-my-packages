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
}

export interface ScanResult {
  files: DependencyFile[];
  dependencies: Dependency[];
  scanPath: string;
  timestamp: Date;
}
