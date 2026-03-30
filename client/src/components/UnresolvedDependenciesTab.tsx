import type { ReportData, UnresolvedDependency } from '../types';

interface UnresolvedDependenciesTabProps {
  data: ReportData;
}

const reasonDescriptions: Record<UnresolvedDependency['reason'], string> = {
  not_found: 'Package not found in registry',
  registry_unavailable: 'Registry service unavailable',
  no_access: 'No access to private registry',
  invalid_spec: 'Invalid version specification',
};

const reasonFootnotes = [
  'Dependencies may fail to resolve for several reasons:',
  '• The package name may be incorrect or the package may not exist in the registry',
  '• The version specification may be invalid or unsatisfiable',
  '• The registry or package repository may be temporarily unavailable',
  '• Private packages may require authentication that was not provided',
  '• Network connectivity issues may prevent access to the registry',
];

export function UnresolvedDependenciesTab({ data }: UnresolvedDependenciesTabProps) {
  const unresolved = data.unresolvedDependencies || [];

  if (unresolved.length === 0) {
    return (
      <div className="tab-panel">
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <h3>All Dependencies Resolved</h3>
          <p>All dependencies were successfully resolved during the scan.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="tab-panel">
      <div className="section-header">
        <h2>⚠️ Unresolved Dependencies ({unresolved.length})</h2>
        <p className="section-description">
          The following dependencies could not be resolved during the scan.
        </p>
      </div>

      <div className="dependencies-list">
        {unresolved.map((dep, index) => (
          <div key={`${dep.name}-${index}`} className="dependency-card unresolved">
            <div className="dependency-header">
              <span className="package-name">{dep.name}</span>
              <span className="version-spec">{dep.versionSpec}</span>
              <span className={`ecosystem-badge ${dep.ecosystem}`}>{dep.ecosystem}</span>
              {dep.isDev && <span className="dev-badge">dev</span>}
            </div>
            <div className="dependency-details">
              <div className="detail-row">
                <span className="detail-label">File:</span>
                <span className="detail-value">{dep.file}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Reason:</span>
                <span className="detail-value reason">{reasonDescriptions[dep.reason]}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="footnote-section">
        <h4>Why dependencies may not resolve:</h4>
        <ul className="footnote-list">
          {reasonFootnotes.slice(1).map((note, index) => (
            <li key={index}>{note.replace(/^•\s*/, '')}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
