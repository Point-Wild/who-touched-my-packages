import * as monaco from 'monaco-editor';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Dependency, FinalReport } from '../types';

interface PinningTabProps {
  data: FinalReport;
}

interface FileData {
  path: string;
  content: string;
  language: string;
  nonPinnedLines: number[];
  nonPinnedCount: number;
}

export function PinningTab({ data }: PinningTabProps) {
  const reportData = data.reportData;
  const [selectedFile, setSelectedFile] = useState<FileData | null>(null);
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const fileGroups = useMemo(() => {
    const groups = new Map<string, Dependency[]>();

    reportData.dependencies.forEach(dep => {
      const spec = dep.versionSpec;
      let isNonPinned = false;

      if (dep.ecosystem === 'pypi') {
        isNonPinned = !spec.startsWith('==') || spec.includes('>=') || spec.includes('>') || spec.includes('~=') || spec === '*';
      }

      if (isNonPinned) {
        if (!groups.has(dep.file)) {
          groups.set(dep.file, []);
        }
        groups.get(dep.file)!.push(dep);
      }
    });

    return groups;
  }, [reportData.dependencies]);

  useEffect(() => {
    if (fileGroups.size > 0 && !selectedFile) {
      const firstFile = Array.from(fileGroups.keys())[0];
      loadFile(firstFile);
    }
  }, [fileGroups]);

  useEffect(() => {
    if (containerRef.current && selectedFile) {
      if (editorRef.current) {
        editorRef.current.dispose();
      }

      const editor = monaco.editor.create(containerRef.current, {
        value: selectedFile.content,
        language: selectedFile.language,
        theme: 'vs-dark',
        readOnly: true,
        automaticLayout: true,
        minimap: { enabled: true },
        scrollBeyondLastLine: false,
        fontSize: 14,
        lineNumbers: 'on',
        renderWhitespace: 'selection',
      });

      editorRef.current = editor;

      const decorations = selectedFile.nonPinnedLines.map(lineNum => ({
        range: new monaco.Range(lineNum, 1, lineNum, 1000),
        options: {
          isWholeLine: true,
          className: 'non-pinned-line',
          glyphMarginClassName: 'non-pinned-glyph',
          linesDecorationsClassName: 'non-pinned-decoration',
          overviewRuler: {
            color: 'rgba(245, 158, 11, 0.8)',
            position: monaco.editor.OverviewRulerLane.Full
          },
          minimap: {
            color: 'rgba(245, 158, 11, 0.8)',
            position: monaco.editor.MinimapPosition.Inline
          }
        }
      }));

      editor.deltaDecorations([], decorations);
    }

    return () => {
      if (editorRef.current) {
        editorRef.current.dispose();
        editorRef.current = null;
      }
    };
  }, [selectedFile]);

  const loadFile = async (filePath: string) => {
    try {
      const response = await fetch(`/api/file?path=${encodeURIComponent(filePath)}`);
      let content = '';

      if (!response.ok) {
        content = `# Unable to load file: ${filePath}\n# File may not be accessible\n\n`;
        content += '# Non-pinned dependencies in this file:\n';
        const deps = fileGroups.get(filePath) || [];
        deps.forEach(dep => {
          content += `# - ${dep.name}: ${dep.versionSpec}\n`;
        });
      } else {
        content = await response.text();
      }

      const language = filePath.endsWith('.json') ? 'json' : 'plaintext';
      const deps = fileGroups.get(filePath) || [];
      const nonPinnedLines: number[] = [];

      const lines = content.split('\n');
      deps.forEach(dep => {
        lines.forEach((line, idx) => {
          if (line.includes(dep.name) && line.includes(dep.versionSpec)) {
            nonPinnedLines.push(idx + 1);
          }
        });
      });

      setSelectedFile({
        path: filePath,
        content,
        language,
        nonPinnedLines,
        nonPinnedCount: deps.length
      });
    } catch (error) {
      const deps = fileGroups.get(filePath) || [];
      let content = `# Unable to load file: ${filePath}\n# Error: ${error instanceof Error ? error.message : 'Unknown error'}\n\n`;
      content += '# Non-pinned dependencies in this file:\n';
      deps.forEach(dep => {
        content += `# - ${dep.name}: ${dep.versionSpec}\n`;
      });

      setSelectedFile({
        path: filePath,
        content,
        language: 'plaintext',
        nonPinnedLines: [],
        nonPinnedCount: deps.length
      });
    }
  };

  if (fileGroups.size === 0) {
    return (
      <div className="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <h2>All Dependencies Pinned!</h2>
        <p>All your dependencies are using pinned versions. Great job!</p>
      </div>
    );
  }

  return (
    <>

      <div style={{
        background: 'var(--bg-secondary)',
        padding: '1.5rem',
        borderRadius: '12px',
        border: '1px solid var(--border)',
        marginTop: '1.5rem'
      }}>
        <h3 style={{ marginBottom: '1rem' }}>💡 Best Practices for preventing Supply Chain attacks</h3>
        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
          <li><strong>CI/CD & Installation:</strong> Use CI commands (e.g., <code>npm ci</code>) over <code>npm install</code> in all CI/CD workflows. Developers should use CI commands with a "firewall" tool such as <a href="https://socket.dev" target="_blank" rel="noopener">socket.dev</a> to block malicious packages</li>
          <li><strong>Lock files:</strong> Use package-lock.json or poetry.lock for additional version locking</li>
          <li><strong>Dependency Review:</strong> Regularly review dependencies for security vulnerabilities and update them promptly</li>
          <li><strong>Vetted Dependencies:</strong> Only use dependencies from trusted sources and maintain a vetted list of approved packages</li>
          <li><strong>Never implicitly trust:</strong> Never fully trust your dependency providers</li>
          <li><strong>Use a Firewall:</strong> Use a firewall tool such as <a href="https://socket.dev" target="_blank" rel="noopener">socket.dev</a> to block malicious packages</li>
          <li><strong>Use a trusted registry:</strong> Use a trusted registry such as <a href="https://jfrog.com/artifactory/" target="_blank" rel="noopener">JFrog Artifactory</a> to block malicious packages</li>
        </ul>
        <p>
          While it may seem like the clear solution, dependency pinning <strong>still leaves you vulnerable</strong> to supply chain attacks if your dependency providers are compromised. Pinning dependencies only impacts the top level of your dependency tree, not the transitive dependencies of those dependencies. 
          The best solution involves a combination of the above practices, with a focus on ensuring that all dependencies are vetted and monitored for security vulnerabilities.
        </p>
      </div>
    </>
  );
}
