import { useState, useMemo } from 'react';
import type { ReportData, VulnerabilityWithPath } from '../types';

interface VulnerabilitiesTabProps {
  data: ReportData;
}

export function VulnerabilitiesTab({ data }: VulnerabilitiesTabProps) {
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
                    <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
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
                          href={`vscode://file${path}`}
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
