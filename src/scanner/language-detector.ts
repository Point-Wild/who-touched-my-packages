import { readdir, stat } from 'node:fs/promises';
import { join, extname, relative } from 'node:path';
import type { LanguageStats } from '../ui/html-report/types.js';

const IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'coverage',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  'target',
  'vendor',
  '.next',
  '.nuxt',
  'out',
  '.cache',
  '.parcel-cache',
]);

const LANGUAGE_EXTENSIONS: Record<string, string> = {
  '.js': 'JavaScript',
  '.jsx': 'JavaScript',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.py': 'Python',
  '.pyw': 'Python',
  '.cs': 'C#',
  '.rs': 'Rust',
  '.go': 'Go',
  '.java': 'Java',
  '.kt': 'Kotlin',
  '.kts': 'Kotlin',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.swift': 'Swift',
  '.c': 'C',
  '.cpp': 'C++',
  '.cc': 'C++',
  '.cxx': 'C++',
  '.h': 'C/C++',
  '.hpp': 'C++',
  '.m': 'Objective-C',
  '.mm': 'Objective-C++',
  '.scala': 'Scala',
  '.clj': 'Clojure',
  '.ex': 'Elixir',
  '.exs': 'Elixir',
  '.erl': 'Erlang',
  '.hrl': 'Erlang',
  '.dart': 'Dart',
  '.lua': 'Lua',
  '.r': 'R',
  '.R': 'R',
  '.jl': 'Julia',
  '.vim': 'Vimscript',
  '.sh': 'Shell',
  '.bash': 'Shell',
  '.zsh': 'Shell',
  '.fish': 'Shell',
  '.ps1': 'PowerShell',
  '.psm1': 'PowerShell',
  '.sql': 'SQL',
  '.pl': 'Perl',
  '.pm': 'Perl',
  '.zig': 'Zig',
  '.nim': 'Nim',
  '.cr': 'Crystal',
  '.v': 'V',
  '.vb': 'Visual Basic',
  '.fs': 'F#',
  '.fsx': 'F#',
  '.ml': 'OCaml',
  '.mli': 'OCaml',
  '.hs': 'Haskell',
  '.elm': 'Elm',
  '.vue': 'Vue',
  '.svelte': 'Svelte',
};

export async function detectLanguages(
  rootPath: string,
  excludePatterns: string[] = []
): Promise<LanguageStats[]> {
  const languageCounts = new Map<string, number>();
  let totalFiles = 0;

  async function walk(currentPath: string): Promise<void> {
    try {
      const entries = await readdir(currentPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(currentPath, entry.name);

        if (entry.isDirectory()) {
          if (IGNORE_DIRS.has(entry.name)) {
            continue;
          }

          const relPath = relative(rootPath, fullPath);
          if (excludePatterns.some(pattern => relPath.includes(pattern))) {
            continue;
          }

          await walk(fullPath);
        } else if (entry.isFile()) {
          const ext = extname(entry.name).toLowerCase();
          const language = LANGUAGE_EXTENSIONS[ext];

          if (language) {
            languageCounts.set(language, (languageCounts.get(language) || 0) + 1);
            totalFiles++;
          }
        }
      }
    } catch (error) {
      // Silently skip directories we can't read
    }
  }

  await walk(rootPath);

  if (totalFiles === 0) {
    return [];
  }

  const stats: LanguageStats[] = Array.from(languageCounts.entries())
    .map(([language, fileCount]) => ({
      language,
      fileCount,
      percentage: (fileCount / totalFiles) * 100,
    }))
    .sort((a, b) => b.fileCount - a.fileCount);

  return stats;
}
