import { useMemo } from 'react';
import type { ReportData } from '../types';
import Donut from './donut/Donut';

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

  const vulnerablePackages = useMemo(() => {
    return new Set(data.auditResult.vulnerabilities.map(v => v.packageName));
  }, [data]);

  const vulnerableDependencies = data.dependencies.filter(dep => vulnerablePackages.has(dep.name)).length;
  const nonVulnerableDependencies = data.dependencies.length - vulnerableDependencies;
  return (
    <>
      <div className="stats-grid">
        <div className="stat-card paper">
          <div className="label">Total Vulnerabilities</div>
          <div className="value">{summary.total}</div>
        </div>
        <div className="stat-card critical paper">
          <div className="label">Critical</div>
          <div className="value">{summary.critical}</div>
        </div>
        <div className="stat-card high paper">
          <div className="label">High</div>
          <div className="value">{summary.high}</div>
        </div>
        <div className="stat-card medium paper">
          <div className="label">Medium</div>
          <div className="value">{summary.medium}</div>
        </div>
        <div className="stat-card low paper">
          <div className="label">Low</div>
          <div className="value">{summary.low}</div>
        </div>
        <div className="stat-card paper">
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

      {summary.total > 0 && (
        <div className="chart-container-group">
          <div className="chart-container paper" style={{ marginBottom: '2rem' }}>
            <h3 style={{ marginBottom: '1rem' }}>Vulnerabilities by Severity</h3>
            {summary.total > 0 ?
              <Donut
                  data={[
                      { label: `Critical`, count: summary.critical, key: 'critical' },
                      { label: `High`, count: summary.high, key: 'high' },
                      { label: `Medium`, count: summary.medium, key: 'medium' },
                      { label: `Low`, count: summary.low, key: 'low' },
                      { label: `Unknown`, count: summary.unknown, key: 'unknown' },
                  ]}
                  total={summary.total}
                  totalLabel="Total Findings"
              />
            : <div className="empty-state">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <h2>All Clear!</h2>
                <p>No vulnerabilities detected in your dependencies.</p>
              </div>}
          </div>
          <div className="chart-container paper" style={{ marginBottom: '2rem' }}>
            <h3 style={{ marginBottom: '1rem' }}>Dependencies</h3>
            <Donut
                data={[
                  { label: `Vulnerable`, count: vulnerableDependencies, key: 'vulnerable' },
                  { label: `Safe`, count: nonVulnerableDependencies, key: 'safe' },
                ]}
                colors={[
                  '#a82424',
                  '#10b981'
                ]}
                total={data.dependencies.length}
                totalLabel="Total Packages"
            />
          </div>
          <div className="chart-container paper" style={{ marginBottom: '2rem' }}>
            <h3 style={{ marginBottom: '1rem' }}>Languages Detected</h3>
            <Donut
                data={
                  data.languageStats?.map((lang) => {
                    return {
                      label: `${lang.language}`,
                      count: lang.fileCount,
                      key: lang.language,
                    }
                  }) ?? []
              }
              colors={[
                '#4A7FFFff',
                '#10b981',
                '#a855f7',
                '#f59e0b',
                '#f43f5e',
              ]}
              total={data.languageStats?.reduce((sum, lang) => sum + lang.fileCount, 0) ?? 0}
              totalLabel="Total Files"
            />
          </div>
        </div>
      )}

      {/*summary.total > 0 ? (
        <div className="chart-container paper" style={{ marginBottom: '2rem' }}>
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
        <div className="empty-state paper">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h2>All Clear!</h2>
          <p>No vulnerabilities detected in your dependencies.</p>
        </div>
      )*/}

      {/* data.languageStats && data.languageStats.length > 0 && (
        <div className="chart-container paper">
          <h3 style={{ marginBottom: '1rem' }}>🌐 Languages Detected</h3>
          <div className="simple-bar-chart">
            {data.languageStats.map((lang, idx) => {
              const colors = [
                '#4A7FFFff',
                '#10b981',
                '#a855f7',
                '#f59e0b',
                '#f43f5e',
              ];
              const color = colors[idx % colors.length];

              return (
                <div key={idx} className="bar-item">
                  <div className="bar-label" style={{ color }}>{lang.language}</div>
                  <div className="bar-container">
                    <div className="bar-fill" style={{
                      width: `${lang.percentage}%`,
                      background: color
                    }}>
                      {lang.fileCount > 0 && lang.fileCount}
                    </div>
                  </div>
                  <div className="bar-value">{lang.percentage.toFixed(1)}%</div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Total files analyzed: {data.languageStats.reduce((sum, lang) => sum + lang.fileCount, 0)}
          </div>
        </div>
      ) */}
    </>
  );
}
