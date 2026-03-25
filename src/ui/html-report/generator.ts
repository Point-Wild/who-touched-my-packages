import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ReportData } from './types.js';

export async function generateHtmlReport(data: ReportData): Promise<string> {
  const reportDir = join(tmpdir(), 'who-touched-my-deps-reports');
  mkdirSync(reportDir, { recursive: true });
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportPath = join(reportDir, `report-${timestamp}.html`);
  
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Who Touched My Deps - Security Report</title>
  <script crossorigin src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/@babel/standalone@7.23.5/babel.min.js"></script>
  <style>
    :root {
      --bg-primary: #0a0a0f;
      --bg-secondary: #13131a;
      --bg-tertiary: #1a1a24;
      --text-primary: #e4e4e7;
      --text-secondary: #a1a1aa;
      --text-muted: #71717a;
      --border: #27272a;
      --accent-blue: #3b82f6;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --accent-purple: #a855f7;
      --critical: #dc2626;
      --high: #ea580c;
      --medium: #f59e0b;
      --low: #84cc16;
      --unknown: #71717a;
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
    }
    
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem;
    }
    
    .header {
      text-align: center;
      margin-bottom: 3rem;
      padding: 2rem;
      background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    
    .header h1 {
      font-size: 2.5rem;
      margin-bottom: 0.5rem;
      background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    .header .subtitle {
      color: var(--text-secondary);
      font-size: 1rem;
    }
    
    .tabs {
      display: flex;
      gap: 1rem;
      margin-bottom: 2rem;
      border-bottom: 2px solid var(--border);
      padding-bottom: 0;
    }
    
    .tab {
      padding: 1rem 2rem;
      background: none;
      border: none;
      color: var(--text-secondary);
      cursor: pointer;
      font-size: 1rem;
      font-weight: 500;
      border-bottom: 3px solid transparent;
      transition: all 0.2s;
      position: relative;
      bottom: -2px;
    }
    
    .tab:hover {
      color: var(--text-primary);
    }
    
    .tab.active {
      color: var(--accent-blue);
      border-bottom-color: var(--accent-blue);
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    
    .stat-card {
      background: var(--bg-secondary);
      padding: 1.5rem;
      border-radius: 12px;
      border: 1px solid var(--border);
      transition: transform 0.2s, border-color 0.2s;
    }
    
    .stat-card:hover {
      transform: translateY(-2px);
      border-color: var(--accent-blue);
    }
    
    .stat-card .label {
      color: var(--text-secondary);
      font-size: 0.875rem;
      margin-bottom: 0.5rem;
    }
    
    .stat-card .value {
      font-size: 2rem;
      font-weight: 700;
    }
    
    .stat-card.critical .value { color: var(--critical); }
    .stat-card.high .value { color: var(--high); }
    .stat-card.medium .value { color: var(--medium); }
    .stat-card.low .value { color: var(--low); }
    .stat-card.unknown .value { color: var(--unknown); }
    
    .chart-container {
      background: var(--bg-secondary);
      padding: 2rem;
      border-radius: 12px;
      border: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    
    .table-container {
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
      overflow: hidden;
    }
    
    .table-wrapper {
      overflow-x: auto;
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
    }
    
    thead {
      background: var(--bg-tertiary);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    
    th {
      padding: 1rem;
      text-align: left;
      font-weight: 600;
      color: var(--text-primary);
      border-bottom: 2px solid var(--border);
    }
    
    td {
      padding: 1rem;
      border-bottom: 1px solid var(--border);
    }
    
    tr:hover {
      background: var(--bg-tertiary);
    }
    
    .severity-badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    
    .severity-badge.critical { background: var(--critical); color: white; }
    .severity-badge.high { background: var(--high); color: white; }
    .severity-badge.medium { background: var(--medium); color: white; }
    .severity-badge.low { background: var(--low); color: white; }
    .severity-badge.unknown { background: var(--unknown); color: white; }
    
    .vscode-link {
      color: var(--accent-blue);
      text-decoration: none;
      font-family: monospace;
      font-size: 0.875rem;
    }
    
    .vscode-link:hover {
      text-decoration: underline;
    }
    
    .cve-link {
      color: var(--accent-purple);
      text-decoration: none;
      font-weight: 500;
    }
    
    .cve-link:hover {
      text-decoration: underline;
    }
    
    .graph-container {
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
      height: 800px;
      position: relative;
    }
    
    .react-flow__node {
      background: var(--bg-tertiary);
      border: 2px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      color: var(--text-primary);
      font-size: 12px;
    }
    
    .react-flow__node.vulnerable {
      border-color: var(--critical);
      background: rgba(220, 38, 38, 0.1);
    }
    
    .react-flow__edge-path {
      stroke: var(--text-muted);
      stroke-width: 2;
    }
    
    .react-flow__controls {
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
    }
    
    .react-flow__controls button {
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border);
      color: var(--text-primary);
    }
    
    .react-flow__controls button:hover {
      background: var(--bg-tertiary);
    }
    
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      color: var(--text-secondary);
    }
    
    .empty-state svg {
      width: 64px;
      height: 64px;
      margin-bottom: 1rem;
      opacity: 0.5;
    }
    
    .simple-bar-chart {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      padding: 1rem 0;
    }
    
    .bar-item {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    
    .bar-label {
      min-width: 100px;
      font-weight: 600;
    }
    
    .bar-container {
      flex: 1;
      height: 30px;
      background: var(--bg-tertiary);
      border-radius: 6px;
      overflow: hidden;
      position: relative;
    }
    
    .bar-fill {
      height: 100%;
      border-radius: 6px;
      transition: width 0.3s ease;
      display: flex;
      align-items: center;
      padding: 0 0.5rem;
      font-size: 0.875rem;
      font-weight: 600;
    }
    
    .bar-value {
      min-width: 50px;
      text-align: right;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useMemo, useCallback, useEffect } = React;
    
    const REPORT_DATA = ${JSON.stringify(data, null, 2)};
    
    function App() {
      const [activeTab, setActiveTab] = useState('overview');
      
      const getRepoName = () => {
        if (!REPORT_DATA.repositoryUrl) return null;
        try {
          const url = REPORT_DATA.repositoryUrl;
          const githubPattern = new RegExp('github\\\\.com[:/]([^/]+/[^/]+?)(\\\\.git)?$');
          const match = url.match(githubPattern);
          if (match) return match[1];
          
          const parts = url.split('/');
          const lastPart = parts[parts.length - 1];
          return lastPart.replace('.git', '');
        } catch {
          return null;
        }
      };
      
      const repoName = getRepoName();
      
      return (
        <div className="container">
          <div className="header">
            <h1>🛡️ Who Touched My Deps?{repoName ? \` - \${repoName}\` : ''}</h1>
            <div className="subtitle">
              Security Audit Report • {new Date(REPORT_DATA.auditResult.timestamp).toLocaleString()}
            </div>
            <div className="subtitle" style={{ marginTop: '0.5rem' }}>
              {REPORT_DATA.repositoryUrl ? (
                <>Repository: <a href={REPORT_DATA.repositoryUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-blue)' }}>{REPORT_DATA.repositoryUrl}</a></>
              ) : (
                <>Scan Path: {REPORT_DATA.scanPath}</>
              )}
            </div>
          </div>
          
          <div className="tabs">
            <button 
              className={\`tab \${activeTab === 'overview' ? 'active' : ''}\`}
              onClick={() => setActiveTab('overview')}
            >
              📊 Overview
            </button>
            <button 
              className={\`tab \${activeTab === 'vulnerabilities' ? 'active' : ''}\`}
              onClick={() => setActiveTab('vulnerabilities')}
            >
              🔍 Vulnerabilities
            </button>
            <button 
              className={\`tab \${activeTab === 'dependencies' ? 'active' : ''}\`}
              onClick={() => setActiveTab('dependencies')}
            >
              � Dependencies
            </button>
          </div>
          
          <div className={\`tab-content \${activeTab === 'overview' ? 'active' : ''}\`}>
            <OverviewTab data={REPORT_DATA} />
          </div>
          
          <div className={\`tab-content \${activeTab === 'vulnerabilities' ? 'active' : ''}\`}>
            <VulnerabilitiesTab data={REPORT_DATA} />
          </div>
          
          <div className={\`tab-content \${activeTab === 'dependencies' ? 'active' : ''}\`}>
            <GraphTab data={REPORT_DATA} />
          </div>
        </div>
      );
    }
    
    function OverviewTab({ data }) {
      const { summary } = data.auditResult;
      
      const pieData = [
        { name: 'Critical', value: summary.critical, color: 'var(--critical)' },
        { name: 'High', value: summary.high, color: 'var(--high)' },
        { name: 'Medium', value: summary.medium, color: 'var(--medium)' },
        { name: 'Low', value: summary.low, color: 'var(--low)' },
        { name: 'Unknown', value: summary.unknown, color: 'var(--unknown)' },
      ].filter(item => item.value > 0);
      
      const barData = [
        { severity: 'Critical', count: summary.critical },
        { severity: 'High', count: summary.high },
        { severity: 'Medium', count: summary.medium },
        { severity: 'Low', count: summary.low },
        { severity: 'Unknown', count: summary.unknown },
      ];
      
      return (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="label">Total Vulnerabilities</div>
              <div className="value">{summary.total}</div>
            </div>
            <div className="stat-card critical">
              <div className="label">Critical</div>
              <div className="value">{summary.critical}</div>
            </div>
            <div className="stat-card high">
              <div className="label">High</div>
              <div className="value">{summary.high}</div>
            </div>
            <div className="stat-card medium">
              <div className="label">Medium</div>
              <div className="value">{summary.medium}</div>
            </div>
            <div className="stat-card low">
              <div className="label">Low</div>
              <div className="value">{summary.low}</div>
            </div>
            <div className="stat-card">
              <div className="label">Scanned Packages</div>
              <div className="value">{data.auditResult.scannedPackages}</div>
            </div>
          </div>
          
          {summary.total > 0 ? (
            <div className="chart-container" style={{ marginBottom: '2rem' }}>
              <h3 style={{ marginBottom: '1rem' }}>Vulnerabilities by Severity</h3>
              <div className="simple-bar-chart">
                <div className="bar-item">
                  <div className="bar-label" style={{ color: 'var(--critical)' }}>Critical</div>
                  <div className="bar-container">
                    <div className="bar-fill" style={{ 
                      width: \`\${summary.total > 0 ? (summary.critical / summary.total * 100) : 0}%\`,
                      background: 'var(--critical)'
                    }}>
                      {summary.critical > 0 && summary.critical}
                    </div>
                  </div>
                  <div className="bar-value">{summary.critical}</div>
                </div>
                
                <div className="bar-item">
                  <div className="bar-label" style={{ color: 'var(--high)' }}>High</div>
                  <div className="bar-container">
                    <div className="bar-fill" style={{ 
                      width: \`\${summary.total > 0 ? (summary.high / summary.total * 100) : 0}%\`,
                      background: 'var(--high)'
                    }}>
                      {summary.high > 0 && summary.high}
                    </div>
                  </div>
                  <div className="bar-value">{summary.high}</div>
                </div>
                
                <div className="bar-item">
                  <div className="bar-label" style={{ color: 'var(--medium)' }}>Medium</div>
                  <div className="bar-container">
                    <div className="bar-fill" style={{ 
                      width: \`\${summary.total > 0 ? (summary.medium / summary.total * 100) : 0}%\`,
                      background: 'var(--medium)'
                    }}>
                      {summary.medium > 0 && summary.medium}
                    </div>
                  </div>
                  <div className="bar-value">{summary.medium}</div>
                </div>
                
                <div className="bar-item">
                  <div className="bar-label" style={{ color: 'var(--low)' }}>Low</div>
                  <div className="bar-container">
                    <div className="bar-fill" style={{ 
                      width: \`\${summary.total > 0 ? (summary.low / summary.total * 100) : 0}%\`,
                      background: 'var(--low)'
                    }}>
                      {summary.low > 0 && summary.low}
                    </div>
                  </div>
                  <div className="bar-value">{summary.low}</div>
                </div>
                
                <div className="bar-item">
                  <div className="bar-label" style={{ color: 'var(--unknown)' }}>Unknown</div>
                  <div className="bar-container">
                    <div className="bar-fill" style={{ 
                      width: \`\${summary.total > 0 ? (summary.unknown / summary.total * 100) : 0}%\`,
                      background: 'var(--unknown)'
                    }}>
                      {summary.unknown > 0 && summary.unknown}
                    </div>
                  </div>
                  <div className="bar-value">{summary.unknown}</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h2>All Clear!</h2>
              <p>No vulnerabilities detected in your dependencies.</p>
            </div>
          )}
        </>
      );
    }
    
    function VulnerabilitiesTab({ data }) {
      const [searchTerm, setSearchTerm] = useState('');
      const [severityFilter, setSeverityFilter] = useState('all');
      
      const vulnerabilitiesWithPaths = useMemo(() => {
        return data.auditResult.vulnerabilities.map(vuln => {
          const filePaths = data.dependencies
            .filter(dep => dep.name === vuln.packageName)
            .map(dep => dep.file);
          return { ...vuln, filePaths: [...new Set(filePaths)] };
        });
      }, [data]);
      
      const filteredVulns = useMemo(() => {
        return vulnerabilitiesWithPaths.filter(vuln => {
          const matchesSearch = searchTerm === '' || 
            vuln.packageName.toLowerCase().includes(searchTerm.toLowerCase()) ||
            vuln.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
            vuln.title.toLowerCase().includes(searchTerm.toLowerCase());
          
          const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter;
          
          return matchesSearch && matchesSeverity;
        });
      }, [vulnerabilitiesWithPaths, searchTerm, severityFilter]);
      
      if (data.auditResult.vulnerabilities.length === 0) {
        return (
          <div className="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2>No Vulnerabilities Found</h2>
            <p>Your dependencies are secure!</p>
          </div>
        );
      }
      
      return (
        <>
          <div style={{ marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                flex: 1,
                padding: '0.75rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'var(--text-primary)',
                fontSize: '1rem'
              }}
            />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{
                padding: '0.75rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'var(--text-primary)',
                fontSize: '1rem'
              }}
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="UNKNOWN">Unknown</option>
            </select>
          </div>
          
          <div className="table-container">
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>ID</th>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Title & References</th>
                    <th>CVSS</th>
                    <th>File Paths</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredVulns.map((vuln, idx) => (
                    <tr key={idx}>
                      <td>
                        <span className={\`severity-badge \${vuln.severity.toLowerCase()}\`}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td>
                        <code style={{ fontSize: '0.875rem' }}>{vuln.id}</code>
                      </td>
                      <td>
                        <strong>{vuln.packageName}</strong>
                      </td>
                      <td>
                        <code style={{ fontSize: '0.875rem' }}>{vuln.packageVersion}</code>
                      </td>
                      <td>
                        <div style={{ marginBottom: '0.5rem' }}>{vuln.title}</div>
                        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                          {vuln.references.map((ref, i) => (
                            <a 
                              key={i}
                              href={ref}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="cve-link"
                            >
                              {ref.includes('cve.org') ? 'CVE' : 
                               ref.includes('github.com') ? 'GitHub' : 
                               ref.includes('nvd.nist.gov') ? 'NVD' : 'Link'}
                            </a>
                          ))}
                        </div>
                      </td>
                      <td>
                        {vuln.cvss ? (
                          <span style={{ fontWeight: 600 }}>{vuln.cvss.toFixed(1)}</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                        )}
                      </td>
                      <td>
                        {vuln.filePaths.map((path, i) => (
                          <div key={i}>
                            <a 
                              href={\`vscode://file\${path}\`}
                              className="vscode-link"
                            >
                              {path}
                            </a>
                          </div>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          
          <div style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Showing {filteredVulns.length} of {vulnerabilitiesWithPaths.length} vulnerabilities
          </div>
        </>
      );
    }
    
    function GraphTab({ data }) {
      const [searchTerm, setSearchTerm] = useState('');
      const [showVulnerableOnly, setShowVulnerableOnly] = useState(false);
      
      const vulnerablePackages = useMemo(() => {
        return new Set(data.auditResult.vulnerabilities.map(v => v.packageName));
      }, [data]);
      
      const vulnerabilitySeverityMap = useMemo(() => {
        const map = new Map();
        data.auditResult.vulnerabilities.forEach(vuln => {
          const existing = map.get(vuln.packageName);
          const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
          const currentOrder = severityOrder[vuln.severity] ?? 5;
          const existingOrder = existing ? (severityOrder[existing] ?? 5) : 999;
          
          if (currentOrder < existingOrder) {
            map.set(vuln.packageName, vuln.severity);
          }
        });
        return map;
      }, [data]);
      
      const filteredDeps = useMemo(() => {
        const filtered = data.dependencies.filter(dep => {
          const matchesSearch = searchTerm === '' || 
            dep.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            dep.version.includes(searchTerm);
          
          const matchesVulnFilter = !showVulnerableOnly || vulnerablePackages.has(dep.name);
          
          return matchesSearch && matchesVulnFilter;
        });
        
        // Sort by vulnerability status and severity
        return filtered.sort((a, b) => {
          const aVuln = vulnerablePackages.has(a.name);
          const bVuln = vulnerablePackages.has(b.name);
          
          // Vulnerable packages first
          if (aVuln && !bVuln) return -1;
          if (!aVuln && bVuln) return 1;
          
          // If both vulnerable, sort by severity
          if (aVuln && bVuln) {
            const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
            const aSeverity = vulnerabilitySeverityMap.get(a.name);
            const bSeverity = vulnerabilitySeverityMap.get(b.name);
            const aOrder = severityOrder[aSeverity] ?? 5;
            const bOrder = severityOrder[bSeverity] ?? 5;
            
            if (aOrder !== bOrder) return aOrder - bOrder;
          }
          
          // Otherwise sort alphabetically by name
          return a.name.localeCompare(b.name);
        });
      }, [data.dependencies, searchTerm, showVulnerableOnly, vulnerablePackages, vulnerabilitySeverityMap]);
      
      if (data.dependencies.length === 0) {
        return (
          <div className="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2" />
            </svg>
            <h2>No Dependencies</h2>
            <p>No dependencies found.</p>
          </div>
        );
      }
      
      return (
        <>
          <div style={{ marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search dependencies..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                flex: 1,
                padding: '0.75rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'var(--text-primary)',
                fontSize: '1rem'
              }}
            />
            <label style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              fontSize: '13px', color: 'var(--text-secondary)',
              cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
            }}>
              <input
                type="checkbox"
                checked={showVulnerableOnly}
                onChange={e => setShowVulnerableOnly(e.target.checked)}
                style={{ accentColor: 'var(--accent-rose)', width: '14px', height: '14px', cursor: 'pointer' }}
              />
              Vulnerable only
            </label>
          </div>
          
          <div className="table-container">
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Package Name</th>
                    <th>Version</th>
                    <th>Ecosystem</th>
                    <th>File Path</th>
                    <th>Type</th>
                    <th>Links</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDeps.map((dep, idx) => {
                    const isVulnerable = vulnerablePackages.has(dep.name);
                    return (
                      <tr key={idx} style={{ background: isVulnerable ? 'rgba(220, 38, 38, 0.1)' : undefined }}>
                        <td>
                          {isVulnerable ? (
                            <span style={{ color: 'var(--critical)', fontWeight: 600 }}>⚠️ Vulnerable</span>
                          ) : (
                            <span style={{ color: 'var(--low)' }}>✓ Safe</span>
                          )}
                        </td>
                        <td><strong>{dep.name}</strong></td>
                        <td><code style={{ fontSize: '0.875rem' }}>{dep.version}</code></td>
                        <td><span className="severity-badge" style={{ background: dep.ecosystem === 'npm' ? 'var(--accent-blue)' : 'var(--accent-emerald)' }}>{dep.ecosystem}</span></td>
                        <td>
                          <a 
                            href={\`vscode://file\${dep.file}\`}
                            className="vscode-link"
                          >
                            {dep.file}
                          </a>
                        </td>
                        <td>{dep.isDev ? 'Dev' : 'Production'}</td>
                        <td>
                          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                            {dep.ecosystem === 'npm' ? (
                              <>
                                <a 
                                  href={\`https://www.npmjs.com/package/\${dep.name}\`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="cve-link"
                                  title="View on npm"
                                >
                                  npm
                                </a>
                                <a 
                                  href={\`https://socket.dev/npm/package/\${dep.name}\`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="cve-link"
                                  title="View on Socket.dev"
                                >
                                  Socket
                                </a>
                              </>
                            ) : dep.ecosystem === 'pypi' ? (
                              <a 
                                href={\`https://pypi.org/project/\${dep.name}\`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="cve-link"
                                title="View on PyPI"
                              >
                                PyPI
                              </a>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          
          <div style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Showing {filteredDeps.length} of {data.dependencies.length} dependencies
          </div>
        </>
      );
    }
    
    const root = ReactDOM.createRoot(document.getElementById('root'));
    root.render(<App />);
  </script>
</body>
</html>`;
  
  writeFileSync(reportPath, html, 'utf-8');
  return reportPath;
}
