import { useState, useMemo, useEffect, useRef } from 'react';
import * as monaco from 'monaco-editor';
import type { ReportData, Dependency } from '../types';

interface PinningTabProps {
  data: ReportData;
}

interface FileData {
  path: string;
  content: string;
  language: string;
  nonPinnedLines: number[];
  nonPinnedCount: number;
}

export function PinningTab({ data }: PinningTabProps) {
  const [selectedFile, setSelectedFile] = useState<FileData | null>(null);
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const fileGroups = useMemo(() => {
    const groups = new Map<string, Dependency[]>();

    data.dependencies.forEach(dep => {
      const spec = dep.versionSpec;
      let isNonPinned = false;

      if (dep.ecosystem === 'npm') {
        isNonPinned = spec.startsWith('^') || spec.startsWith('~') || spec.includes('*') || spec.includes('x') || spec.includes('X') || spec === 'latest';
      } else if (dep.ecosystem === 'pypi') {
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
  }, [data.dependencies]);

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
      <div style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ marginBottom: '1rem' }}>Select a file to view pinning issues:</h3>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {Array.from(fileGroups.entries()).map(([filePath, deps]) => (
            <button
              key={filePath}
              onClick={() => loadFile(filePath)}
              style={{
                padding: '0.75rem 1rem',
                background: selectedFile?.path === filePath ? 'var(--accent-amber)' : 'var(--bg-secondary)',
                border: `1px solid ${selectedFile?.path === filePath ? 'var(--accent-amber)' : 'var(--border)'}`,
                borderRadius: '8px',
                color: selectedFile?.path === filePath ? 'white' : 'var(--text-primary)',
                cursor: 'pointer',
                fontSize: '0.875rem',
                fontFamily: 'monospace',
                transition: 'all 0.2s',
              }}
            >
              {filePath.split('/').pop()} ({deps.length})
            </button>
          ))}
        </div>
      </div>

      {selectedFile && (
        <div className="editor-container">
          <div className="editor-header">
            <div className="editor-title">{selectedFile.path}</div>
            <div className="editor-badge">
              {selectedFile.nonPinnedCount} non-pinned {selectedFile.nonPinnedCount === 1 ? 'dependency' : 'dependencies'}
            </div>
          </div>
          <div className="monaco-editor-wrapper" ref={containerRef}></div>
        </div>
      )}

      <div style={{
        background: 'var(--bg-secondary)',
        padding: '1.5rem',
        borderRadius: '12px',
        border: '1px solid var(--border)',
        marginTop: '1.5rem'
      }}>
        <h3 style={{ marginBottom: '1rem' }}>💡 Best Practices for Pinning Dependencies</h3>
        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
          <li><strong>npm/package.json:</strong> Use exact versions (e.g., <code>"1.2.3"</code>) instead of ranges (<code>"^1.2.3"</code> or <code>"~1.2.3"</code>)</li>
          <li><strong>Python/requirements.txt:</strong> Use <code>==</code> for exact versions (e.g., <code>package==1.2.3</code>) instead of <code>&gt;=</code> or <code>~=</code></li>
          <li><strong>Why pin?</strong> Pinned versions ensure reproducible builds and prevent unexpected breaking changes</li>
          <li><strong>Lock files:</strong> Use package-lock.json or poetry.lock for additional version locking</li>
        </ul>
      </div>
    </>
  );
}
