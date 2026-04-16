import { useMemo, useState } from 'react';
import type { FinalReport } from '../types';
import { ExportButton } from './ExportButton';

interface VulnerabilitiesTabProps {
  data: FinalReport;
}

interface TabFinding {
  id: string;
  packageName: string;
  packageVersion: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  title: string;
  references: string[];
  cvss?: number;
  source: string;
  files: string[];
  packagePublishedAt?: string;
  packageAgeDays?: number;
}

function formatPackageAge(days?: number): string {
  if (days == null || !Number.isFinite(days) || days < 0) return 'Unknown';
  if (days < 1) return 'today';
  if (days < 30) return `${days}d`;
  if (days < 365) return `${Math.floor(days / 30)}mo`;
  const years = days / 365;
  return years < 10 ? `${years.toFixed(1)}y` : `${Math.floor(years)}y`;
}

export function VulnerabilitiesTab({ data }: VulnerabilitiesTabProps) {
  const reportData = data.reportData;
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const toRelativePath = (path: string): string => {
    if (!path) return path;

    if (path.startsWith(reportData.scanPath)) {
      const relativePath = path.slice(reportData.scanPath.length).replace(/^\/+/, '');
      return relativePath || '.';
    }

    return path;
  };

  const vulnerabilitiesWithPaths = useMemo(() => {
    const staticFindings: TabFinding[] = reportData.auditResult.vulnerabilities.map(vuln => {
      const files = reportData.dependencies
        .filter(dep => dep.name === vuln.packageName)
        .map(dep => toRelativePath(dep.file));
      return { ...vuln, files: [...new Set(files)] };
    });

    const supplyChainFindings: TabFinding[] = (data.supplyChainReport?.findings ?? []).map(finding => ({
      id: finding.category,
      packageName: finding.packageName,
      packageVersion: finding.packageVersion,
      severity: finding.severity,
      title: finding.title,
      references: [],
      source: 'LLM',
      files: finding.filePath ? [toRelativePath(finding.filePath)] : [],
    }));

    return [...staticFindings, ...supplyChainFindings];
  }, [data.supplyChainReport?.findings, reportData]);

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

  const csvHeaders = [
    { key: 'severity' as const, label: 'Severity' },
    { key: 'id' as const, label: 'ID' },
    { key: 'source' as const, label: 'Source' },
    { key: 'packageName' as const, label: 'Package' },
    { key: 'packageVersion' as const, label: 'Version' },
    { key: 'title' as const, label: 'Title' },
    { key: 'cvss' as const, label: 'CVSS' },
    { key: 'files' as const, label: 'File' },
    { key: 'packageAgeDays' as const, label: 'Package Age (days)' },
    { key: 'packagePublishedAt' as const, label: 'Package Published' },
    { key: 'references' as const, label: 'References' },
  ];

  if (vulnerabilitiesWithPaths.length === 0) {
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
          className="search-input"
        />
        <div className="select-wrapper">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Severities&nbsp;&nbsp;&nbsp;</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>
        <ExportButton
          data={filteredVulns}
          filename="vulnerabilities"
          csvHeaders={csvHeaders}
        />
      </div>

      <div className="table-container">
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>ID</th>
                <th>Source</th>
                <th>Package</th>
                <th>Version</th>
                <th>Title & References</th>
                <th>CVSS</th>
                <th>File</th>
                <th>Package Age</th>
              </tr>
            </thead>
            <tbody>
              {filteredVulns.map((vuln, idx) => (
                <tr key={idx} className={`row-${vuln.severity.toLowerCase()}`}>
                  <td>
                    <span className={`severity-badge ${vuln.severity.toLowerCase()}`}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.875rem' }}>{vuln.id}</code>
                  </td>
                  <td>
                    <span className="source-badge">{vuln.source}</span>
                  </td>
                  <td>
                    <strong>{vuln.packageName}</strong>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.875rem' }}>{vuln.packageVersion}</code>
                  </td>
                  <td>
                    <div style={{ marginBottom: '0.2rem' }}>{vuln.title}</div>
                    <div style={{ display: 'flex', gap: '0', flexWrap: 'wrap' }}>
                      {vuln.references.map((ref, i) => {
                        const getLabel = () => {
                          if (ref.includes('cve.org')) return 'CVE';
                          if (ref.includes('github.com')) return 'GitHub';
                          if (ref.includes('nvd.nist.gov')) return 'NVD';
                          return 'Link';
                        };
                        const getIdentifier = () => {
                          try {
                            const url = new URL(ref);
                            const pathParts = url.pathname.split('/').filter(Boolean);
                            if (ref.includes('github.com/advisories/')) {
                              return pathParts[pathParts.indexOf('advisories') + 1]?.slice(0, 12);
                            }
                            if (ref.includes('cve.org')) {
                              return pathParts.find(p => p.startsWith('CVE-'));
                            }
                            if (ref.includes('nvd.nist.gov')) {
                              return pathParts.find(p => p.startsWith('CVE-'));
                            }
                            return url.hostname.replace(/^www\./, '');
                          } catch {
                            return null;
                          }
                        };
                        const label = getLabel();
                        const identifier = getIdentifier();
                        const displayLabel = identifier ? `${label} · ${identifier}` : label;
                        return (
                          <a
                            key={i}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="cve-link"
                            title={ref}
                          >
                            {displayLabel}
                          </a>
                        );
                      })}
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
                    {vuln.files.length > 0 ? (
                      <span
                        style={{
                          color: 'var(--text-secondary)',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {vuln.files.join(', ')}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                    )}
                  </td>
                  <td>
                    {vuln.packageAgeDays != null ? (
                      <span
                        title={vuln.packagePublishedAt ? `Published ${vuln.packagePublishedAt}` : undefined}
                        style={{ whiteSpace: 'nowrap' }}
                      >
                        {formatPackageAge(vuln.packageAgeDays)}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>Unknown</span>
                    )}
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
