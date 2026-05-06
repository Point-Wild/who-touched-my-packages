import type { Dependency, DependencyFile } from '../types.js';

export * from './npm.js';
export * from './python.js';
export * from './rust.js';
export * from './go.js';
export * from './ruby.js';

import { parsePackageJson, parsePackageLockJson, parseYarnLock, parsePnpmLock, parseBunLock } from './npm.js';
import { parseRequirementsTxt } from './python.js';
import { parseCargoToml, parseCargoLock } from './rust.js';
import { parseGoMod, parseGoSum } from './go.js';
import { parseGemfile, parseGemfileLock } from './ruby.js';

export function parseDependencies(file: DependencyFile & { content?: string }): Dependency[] {
  const { type, content, path } = file;
  
  if (!content) return [];
  
  switch (type) {
    case 'package.json':
      return parsePackageJson(content, path);
    case 'package-lock.json':
      return parsePackageLockJson(content, path);
    case 'yarn.lock':
      return parseYarnLock(content, path);
    case 'pnpm-lock.yaml':
      return parsePnpmLock(content, path);
    case 'bun.lock':
      return parseBunLock(content, path);
    case 'requirements.txt':
      return parseRequirementsTxt(content, path);
    case 'Cargo.toml':
      return parseCargoToml(content, path);
    case 'Cargo.lock':
      return parseCargoLock(content, path);
    case 'go.mod':
      return parseGoMod(content, path);
    case 'go.sum':
      return parseGoSum(content, path);
    case 'Gemfile':
      return parseGemfile(content, path);
    case 'Gemfile.lock':
      return parseGemfileLock(content, path);
    default:
      return [];
  }
}
