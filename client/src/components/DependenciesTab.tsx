import { useMemo, useState } from 'react';
import type { ReportData } from '../types';
import { ExportButton } from './ExportButton';

interface DependenciesTabProps {
  data: ReportData;
}

export function DependenciesTab({ data }: DependenciesTabProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [showVulnerableOnly, setShowVulnerableOnly] = useState(false);
  const [showNoProvenanceOnly, setShowNoProvenanceOnly] = useState(false);

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
      const matchesProvenanceFilter = !showNoProvenanceOnly || dep.provenance === false;

      return matchesSearch && matchesVulnFilter && matchesProvenanceFilter;
    });

    return filtered.sort((a, b) => {
      const aVuln = vulnerablePackages.has(a.name);
      const bVuln = vulnerablePackages.has(b.name);

      if (aVuln && !bVuln) return -1;
      if (!aVuln && bVuln) return 1;

      if (aVuln && bVuln) {
        const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
        const aSeverity = vulnerabilitySeverityMap.get(a.name);
        const bSeverity = vulnerabilitySeverityMap.get(b.name);
        const aOrder = severityOrder[aSeverity as keyof typeof severityOrder] ?? 5;
        const bOrder = severityOrder[bSeverity as keyof typeof severityOrder] ?? 5;

        if (aOrder !== bOrder) return aOrder - bOrder;
      }

      return a.name.localeCompare(b.name);
    });
  }, [data.dependencies, searchTerm, showVulnerableOnly, showNoProvenanceOnly, vulnerablePackages, vulnerabilitySeverityMap]);

  const depsForExport = useMemo(() => {
    return filteredDeps.map(dep => ({
      ...dep,
      isVulnerable: vulnerablePackages.has(dep.name),
      maxSeverity: vulnerabilitySeverityMap.get(dep.name) || 'N/A',
      provenanceStatus: dep.provenance === true ? 'Verified' : dep.provenance === false ? 'Missing' : 'Unknown',
    }));
  }, [filteredDeps, vulnerablePackages, vulnerabilitySeverityMap]);

  const csvHeaders = [
    { key: 'name' as const, label: 'Package Name' },
    { key: 'version' as const, label: 'Version' },
    { key: 'ecosystem' as const, label: 'Ecosystem' },
    { key: 'file' as const, label: 'File Path' },
    { key: 'isDev' as const, label: 'Type' },
    { key: 'isVulnerable' as const, label: 'Vulnerable' },
    { key: 'maxSeverity' as const, label: 'Max Severity' },
    { key: 'provenanceStatus' as const, label: 'Provenance' },
  ];

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
          className="search-input"
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
            style={{ accentColor: 'var(--accent-blue)', width: '14px', height: '14px', cursor: 'pointer' }}
          />
          Vulnerable only
        </label>
        <label style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          fontSize: '13px', color: 'var(--text-secondary)',
          cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
        }}>
          <input
            type="checkbox"
            checked={showNoProvenanceOnly}
            onChange={e => setShowNoProvenanceOnly(e.target.checked)}
            style={{ accentColor: 'var(--accent-blue)', width: '14px', height: '14px', cursor: 'pointer' }}
          />
          No provenance only
        </label>
        <ExportButton
          data={depsForExport}
          filename="dependencies"
          csvHeaders={csvHeaders}
        />
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
                <th>Provenance</th>
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
                        href={`vscode://file${dep.file}`}
                        className="vscode-link"
                      >
                        {dep.file}
                      </a>
                    </td>
                    <td>{dep.isDev ? 'Dev' : 'Production'}</td>
                    <td>
                      {dep.provenance === true ? (
                        <span style={{ color: 'var(--low)' }}>✓ Verified</span>
                      ) : dep.provenance === false ? (
                        <span style={{ color: 'var(--high)', fontWeight: 600 }}>⚠️ Missing</span>
                      ) : (
                        <span style={{ color: 'var(--text-secondary)' }}>Unknown</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        {dep.ecosystem === 'npm' ? (
                          <>
                            <a
                              href={`https://www.npmjs.com/package/${dep.name}/v/${dep.version}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="cve-link"
                              title="View on npm"
                            >
                              npm
                            </a>
                            <a
                              href={`https://socket.dev/npm/package/${dep.name}/version/${dep.version}`}
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
                            href={`https://pypi.org/project/${dep.name}/${dep.version}/`}
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
