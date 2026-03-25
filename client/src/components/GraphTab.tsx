import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReportData } from '../types';
import { GraphView } from './graph/GraphView';

interface GraphTabProps {
  data: ReportData;
}

interface GraphNode {
  id: string;
  name: string;
  version: string;
  ecosystem: 'npm' | 'pypi';
  file: string;
  isDev?: boolean;
  isVulnerable?: boolean;
  isRoot?: boolean;
}

interface GraphEdge {
  source: string;
  target: string;
  type: 'dependency' | 'dev';
}

export function GraphTab({ data }: GraphTabProps) {
  const [layoutedGraph, setLayoutedGraph] = useState<{ nodes: any[]; edges: any[] } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string>('all');
  const [fitViewSignal, setFitViewSignal] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(prev => !prev);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isFullscreen) {
        setIsFullscreen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isFullscreen]);

  const vulnerablePackages = useMemo(() => {
    return new Set(data.auditResult.vulnerabilities.map(v => v.packageName));
  }, [data]);

  const packageFiles = useMemo(() => {
    const files = new Set(data.dependencies.map(d => d.file));
    return Array.from(files).sort();
  }, [data.dependencies]);

  const { nodes, edges } = useMemo(() => {
    const filteredDeps = selectedFile === 'all' 
      ? data.dependencies 
      : data.dependencies.filter(d => d.file === selectedFile);

    const nodeMap = new Map<string, GraphNode>();
    const edgeList: GraphEdge[] = [];

    filteredDeps.forEach(dep => {
      const nodeId = `${dep.name}@${dep.version}`;
      
      if (!nodeMap.has(nodeId)) {
        const isRoot = dep.depth === 0 || dep.depth === undefined;
        nodeMap.set(nodeId, {
          id: nodeId,
          name: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          file: dep.file,
          isDev: dep.isDev,
          isVulnerable: vulnerablePackages.has(dep.name),
          isRoot,
        });
      }
    });

    if (data.dependencyEdges) {
      const nodeIds = new Set(nodeMap.keys());
      
      data.dependencyEdges.forEach(edge => {
        if (nodeIds.has(edge.source) && nodeIds.has(edge.target)) {
          edgeList.push({
            source: edge.source,
            target: edge.target,
            type: edge.type,
          });
        }
      });
    }

    const nodes = Array.from(nodeMap.values());

    return { nodes, edges: edgeList };
  }, [data.dependencies, data.dependencyEdges, selectedFile, vulnerablePackages]);

  useEffect(() => {
    if (nodes.length === 0) {
      setLayoutedGraph({ nodes: [], edges: [] });
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setError(null);

    const worker = new Worker(
      new URL('./graph/layout.worker.ts', import.meta.url),
      { type: 'module' }
    );

    const handleMessage = (e: MessageEvent) => {
      const data = e.data;
      if (data.type === 'success') {
        setLayoutedGraph({ nodes: data.nodes, edges: data.edges });
        setIsLoading(false);
        // Trigger fitView after nodes are set and rendered
        requestAnimationFrame(() => {
          setTimeout(() => setFitViewSignal(s => s + 1), 300);
        });
      } else if (data.type === 'error') {
        setError(data.error);
        setIsLoading(false);
      }
    };

    const handleError = (e: ErrorEvent) => {
      setError(e.message);
      setIsLoading(false);
    };

    worker.addEventListener('message', handleMessage);
    worker.addEventListener('error', handleError);

    worker.postMessage({ nodes, validEdges: edges });

    return () => {
      worker.removeEventListener('message', handleMessage);
      worker.removeEventListener('error', handleError);
      worker.terminate();
    };
  }, [nodes, edges]);

  if (data.dependencies.length === 0) {
    return (
      <div className="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2" />
        </svg>
        <h2>No Dependencies</h2>
        <p>No dependencies found to visualize.</p>
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: isFullscreen ? '100vh' : '600px',
      gap: '1rem',
      position: isFullscreen ? 'fixed' : 'relative',
      top: isFullscreen ? '0' : 'auto',
      left: isFullscreen ? '0' : 'auto',
      right: isFullscreen ? '0' : 'auto',
      bottom: isFullscreen ? '0' : 'auto',
      zIndex: isFullscreen ? 9999 : 'auto',
      background: isFullscreen ? 'var(--bg-primary)' : 'transparent',
      padding: isFullscreen ? '1rem' : '0',
    }}>
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <label style={{ color: 'var(--text-secondary)', fontSize: '14px', fontWeight: 600 }}>
          Filter by file:
        </label>
        <select
          value={selectedFile}
          onChange={(e) => setSelectedFile(e.target.value)}
          style={{
            padding: '0.5rem',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            color: 'var(--text-primary)',
            fontSize: '14px',
            minWidth: '300px',
          }}
        >
          <option value="all">All Files ({data.dependencies.length} dependencies)</option>
          {packageFiles.map(file => {
            const count = data.dependencies.filter(d => d.file === file).length;
            return (
              <option key={file} value={file}>
                {file} ({count} dependencies)
              </option>
            );
          })}
        </select>
      </div>

      {error && (
        <div style={{
          padding: '1rem',
          background: 'rgba(220, 38, 38, 0.1)',
          border: '1px solid var(--critical)',
          borderRadius: '8px',
          color: 'var(--critical)',
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {isLoading ? (
        <div style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--bg-secondary)',
          borderRadius: '12px',
          position: 'relative',
        }}>
          <button
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit fullscreen (Esc)" : "Enter fullscreen"}
            style={{
              position: 'absolute',
              top: '12px',
              right: '12px',
              zIndex: 10,
              padding: '8px 12px',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              fontSize: '14px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            {isFullscreen ? '⛶ Exit' : '⛶ Fullscreen'}
          </button>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '18px', marginBottom: '8px' }}>⚙️ Computing layout...</div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
              Processing {nodes.length} packages
            </div>
          </div>
        </div>
      ) : layoutedGraph && layoutedGraph.nodes.length > 0 ? (
        <div style={{
          flex: 1,
          background: 'var(--bg-secondary)',
          borderRadius: '12px',
          overflow: 'hidden',
          position: 'relative',
        }}>
          <button
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit fullscreen (Esc)" : "Enter fullscreen"}
            style={{
              position: 'absolute',
              top: '12px',
              right: '12px',
              zIndex: 10,
              padding: '8px 12px',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              fontSize: '14px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            {isFullscreen ? '⛶ Exit' : '⛶ Fullscreen'}
          </button>
          <GraphView
            nodes={layoutedGraph.nodes}
            edges={layoutedGraph.edges}
            fitViewSignal={fitViewSignal}
          />
        </div>
      ) : (
        <div className="empty-state">
          <h2>No Dependencies to Display</h2>
          <p>Select a different file or check your filters.</p>
        </div>
      )}

      <div style={{
        padding: '1rem',
        background: 'var(--bg-secondary)',
        borderRadius: '8px',
        fontSize: '13px',
        color: 'var(--text-secondary)',
      }}>
        <div style={{ marginBottom: '8px', fontWeight: 600 }}>Legend:</div>
        <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: 'var(--accent-emerald)' }} />
            <span>Root Package</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: 'var(--accent-blue)' }} />
            <span>Dependency</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: 'var(--critical)' }} />
            <span>Vulnerable</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '24px', height: '2px', background: '#60a5fa', borderStyle: 'dashed' }} />
            <span>Dev Dependency</span>
          </div>
        </div>
      </div>
    </div>
  );
}
