import { useMemo } from 'react';
import type { ReportData } from '../types';

interface OverviewTabProps {
  data: ReportData;
  onNavigateToPinning: () => void;
}

export function OverviewTab({ data, onNavigateToPinning }: OverviewTabProps) {
  const { summary } = data.auditResult;

  const nonPinnedDeps = useMemo(() => {
    return data.dependencies.filter(dep => {
      const spec = dep.versionSpec;
      if (dep.ecosystem === 'npm') {
        return spec.startsWith('^') || spec.startsWith('~') || spec.includes('*') || spec.includes('x') || spec.includes('X') || spec === 'latest';
      }
      if (dep.ecosystem === 'pypi') {
        return !spec.startsWith('==') || spec.includes('>=') || spec.includes('>') || spec.includes('~=') || spec === '*';
      }
      return false;
    });
  }, [data.dependencies]);

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

      {nonPinnedDeps.length > 0 && (
        <div className="warning-card" onClick={onNavigateToPinning}>
          <div className="warning-header">
            <div className="warning-icon">⚠️</div>
            <div className="warning-title">Non-Pinned Dependencies Detected</div>
          </div>
          <div className="warning-description">
            Found {nonPinnedDeps.length} {nonPinnedDeps.length === 1 ? 'dependency' : 'dependencies'} with non-pinned versions.
            Click here to view and fix pinning issues in your dependency files.
          </div>
        </div>
      )}

      {summary.total > 0 ? (
        <div className="chart-container" style={{ marginBottom: '2rem' }}>
          <h3 style={{ marginBottom: '1rem' }}>Vulnerabilities by Severity</h3>
          <div className="simple-bar-chart">
            <div className="bar-item">
              <div className="bar-label" style={{ color: 'var(--critical)' }}>Critical</div>
              <div className="bar-container">
                <div className="bar-fill" style={{
                  width: `${summary.total > 0 ? (summary.critical / summary.total * 100) : 0}%`,
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
                  width: `${summary.total > 0 ? (summary.high / summary.total * 100) : 0}%`,
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
                  width: `${summary.total > 0 ? (summary.medium / summary.total * 100) : 0}%`,
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
                  width: `${summary.total > 0 ? (summary.low / summary.total * 100) : 0}%`,
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
                  width: `${summary.total > 0 ? (summary.unknown / summary.total * 100) : 0}%`,
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
