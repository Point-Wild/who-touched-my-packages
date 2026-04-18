import type { FinalReport } from '../types';

interface PinningTabProps {
  data: FinalReport;
}

export function PinningTab({}: PinningTabProps) {
  return (
    <>
      <div style={{
        background: 'var(--bg-secondary)',
        padding: '1.5rem',
        borderRadius: '12px',
        border: '1px solid var(--border)',
        marginTop: '1.5rem'
      }}>
        <h3 style={{ marginBottom: '1rem' }}>💡 Best Practices for preventing Supply Chain attacks</h3>
        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
          <li><strong>CI/CD & Installation:</strong> Use CI commands (e.g., <code>npm ci</code>) over <code>npm install</code> in all CI/CD workflows.</li>
          <li><strong>Lock files:</strong> Use package-lock.json or poetry.lock for additional version locking</li>
          <li><strong>Dependency Review:</strong> Regularly review dependencies for security vulnerabilities and update them promptly</li>
          <li><strong>Vetted Dependencies:</strong> Only use dependencies from trusted sources and maintain a vetted list of approved packages</li>
          <li><strong>Never implicitly trust:</strong> Never fully trust your dependency providers</li>
        </ul>
        <p>
          While it may seem like the clear solution, dependency pinning <strong>still leaves you vulnerable</strong> to supply chain attacks if your dependency providers are compromised. Pinning dependencies only impacts the top level of your dependency tree, not the transitive dependencies of those dependencies. 
          The best solution involves a combination of the above practices, with a focus on ensuring that all dependencies are vetted and monitored for security vulnerabilities.
        </p>
      </div>
    </>
  );
}
