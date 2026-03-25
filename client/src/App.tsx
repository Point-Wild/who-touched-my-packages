import { useEffect, useState } from 'react';
import { DependenciesTab } from './components/DependenciesTab';
import { GraphTab } from './components/GraphTab';
import { OverviewTab } from './components/OverviewTab';
import { PinningTab } from './components/PinningTab';
import { VulnerabilitiesTab } from './components/VulnerabilitiesTab';
import type { ReportData } from './types';

export function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [data, setData] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/data')
      .then(res => res.json())
      .then(data => {
        setData(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const getRepoName = () => {
    if (!data?.repositoryUrl) return null;
    try {
      const url = data.repositoryUrl;
      const githubPattern = /github\.com[:/]([^/]+\/[^/]+?)(\.git)?$/;
      const match = url.match(githubPattern);
      if (match) return match[1];

      const parts = url.split('/');
      const lastPart = parts[parts.length - 1];
      return lastPart.replace('.git', '');
    } catch {
      return null;
    }
  };

  if (loading) {
    return (
      <div className="container">
        <div className="empty-state">
          <h2>Loading report...</h2>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="container">
        <div className="empty-state">
          <h2>Error loading report</h2>
          <p>{error || 'Failed to load report data'}</p>
        </div>
      </div>
    );
  }

  const repoName = getRepoName();

  return (
    <div className="container">
      <div className="header">
        <h1>🛡️ Who Touched My Packages?{repoName ? ` - ${repoName}` : ''}</h1>
        <div className="subtitle">
          Security Audit Report • {new Date(data.auditResult.timestamp).toLocaleString()}
        </div>
        <div className="subtitle" style={{ marginTop: '0.5rem' }}>
          {data.repositoryUrl ? (
            <>Repository: <a href={data.repositoryUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-blue)' }}>{data.repositoryUrl}</a></>
          ) : (
            <>Scan Path: {data.scanPath}</>
          )}
        </div>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button
          className={`tab ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveTab('vulnerabilities')}
        >
          🔍 Vulnerabilities
        </button>
        <button
          className={`tab ${activeTab === 'dependencies' ? 'active' : ''}`}
          onClick={() => setActiveTab('dependencies')}
        >
          📦 Dependencies
        </button>
        <button
          className={`tab ${activeTab === 'pinning' ? 'active' : ''}`}
          onClick={() => setActiveTab('pinning')}
        >
          📌 Pinning Issues
        </button>
        <button
          className={`tab ${activeTab === 'graph' ? 'active' : ''}`}
          onClick={() => setActiveTab('graph')}
        >
          🕸️ Graph
        </button>
      </div>

      <div className={`tab-content ${activeTab === 'overview' ? 'active' : ''}`}>
        <OverviewTab data={data} onNavigateToPinning={() => setActiveTab('pinning')} />
      </div>

      <div className={`tab-content ${activeTab === 'vulnerabilities' ? 'active' : ''}`}>
        <VulnerabilitiesTab data={data} />
      </div>

      <div className={`tab-content ${activeTab === 'dependencies' ? 'active' : ''}`}>
        <DependenciesTab data={data} />
      </div>

      <div className={`tab-content ${activeTab === 'pinning' ? 'active' : ''}`}>
        <PinningTab data={data} />
      </div>

      <div className={`tab-content ${activeTab === 'graph' ? 'active' : ''}`}>
        <GraphTab data={data} />
      </div>
    </div>
  );
}
