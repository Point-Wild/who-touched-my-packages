import type { Dependency } from '../../scanner/types.js';
import type { Vulnerability } from '../types.js';
import { DataSource } from './base.js';

interface OSVQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

interface OSVVulnerability {
  id: string;
  summary: string;
  details: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  published?: string;
}

interface OSVResponse {
  results: Array<{
    vulns?: OSVVulnerability[];
  }>;
}

export class OSVDataSource extends DataSource {
  name = 'OSV';
  private apiUrl = 'https://api.osv.dev/v1/querybatch';
  
  async checkVulnerabilities(dependencies: Dependency[]): Promise<Vulnerability[]> {
    if (dependencies.length === 0) {
      return [];
    }
    
    const queries: OSVQuery[] = dependencies.map(dep => ({
      package: {
        name: dep.name,
        ecosystem: this.mapEcosystem(dep.ecosystem),
      },
      version: dep.version !== '*' ? dep.version : undefined,
    }));
    
    try {
      const response = await this.fetchWithRetry(this.apiUrl, {
        method: 'POST',
        body: JSON.stringify({ queries }),
      });
      
      if (!response.ok) {
        return [];
      }
      
      const data = await response.json() as OSVResponse;
      const vulnerabilities: Vulnerability[] = [];
      
      for (let i = 0; i < data.results.length; i++) {
        const result = data.results[i];
        const dep = dependencies[i];
        
        if (result.vulns) {
          for (const vuln of result.vulns) {
            if (!vuln.severity || vuln.severity.length === 0) {
              const detailedVuln = await this.fetchVulnerabilityDetails(vuln.id);
              if (detailedVuln) {
                vulnerabilities.push(this.transformVulnerability(detailedVuln, dep));
              } else {
                vulnerabilities.push(this.transformVulnerability(vuln, dep));
              }
            } else {
              vulnerabilities.push(this.transformVulnerability(vuln, dep));
            }
          }
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      return [];
    }
  }

  private mapEcosystem(ecosystem: Dependency['ecosystem']): string {
    switch (ecosystem) {
      case 'npm':
        return 'npm';
      case 'pypi':
        return 'PyPI';
      case 'cratesio':
        return 'crates.io';
      case 'golang':
        return 'Go';
      case 'ruby':
        return 'RubyGems';
    }
  }
  
  private async fetchVulnerabilityDetails(vulnId: string): Promise<OSVVulnerability | null> {
    try {
      const response = await this.fetchWithRetry(`https://api.osv.dev/v1/vulns/${vulnId}`);
      if (!response.ok) {
        return null;
      }
      return await response.json() as OSVVulnerability;
    } catch (error) {
      return null;
    }
  }
  
  private transformVulnerability(
    vuln: OSVVulnerability,
    dep: Dependency
  ): Vulnerability {
    const severity = this.extractSeverity(vuln);
    const cvss = this.extractCVSS(vuln);
    const fixedVersions = this.extractFixedVersions(vuln);
    const affectedVersions = this.extractAffectedVersions(vuln);
    
    return {
      id: vuln.id,
      packageName: dep.name,
      packageVersion: dep.version,
      ecosystem: dep.ecosystem,
      severity,
      title: vuln.summary || vuln.id,
      description: vuln.details || vuln.summary || 'No description available',
      cvss,
      references: vuln.references?.map(ref => ref.url) || [],
      affectedVersions,
      fixedVersions,
      publishedDate: vuln.published,
      source: 'OSV',
    };
  }
  
  private extractSeverity(vuln: OSVVulnerability): Vulnerability['severity'] {
    if (!vuln.severity || vuln.severity.length === 0) {
      return 'UNKNOWN';
    }
    
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3') {
        const score = this.parseCVSSScore(sev.score);
        if (score === undefined) continue;
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        return 'LOW';
      }
    }
    
    return 'UNKNOWN';
  }
  
  private extractCVSS(vuln: OSVVulnerability): number | undefined {
    if (!vuln.severity) return undefined;
    
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3') {
        return this.parseCVSSScore(sev.score);
      }
    }
    
    return undefined;
  }
  
  private parseCVSSScore(cvssString: string): number | undefined {
    if (!cvssString.startsWith('CVSS:3.')) {
      const numericScore = parseFloat(cvssString.split('/')[0]);
      return isNaN(numericScore) ? undefined : numericScore;
    }
    
    const metrics = cvssString.split('/').slice(1);
    const metricMap: Record<string, string> = {};
    
    for (const metric of metrics) {
      const [key, value] = metric.split(':');
      metricMap[key] = value;
    }
    
    const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metricMap.AV] || 0;
    const ac = { L: 0.77, H: 0.44 }[metricMap.AC] || 0;
    const ui = { N: 0.85, R: 0.62 }[metricMap.UI] || 0;
    const scope = metricMap.S || 'U';
    
    let pr: number;
    if (scope === 'U') {
      pr = { N: 0.85, L: 0.62, H: 0.27 }[metricMap.PR] || 0;
    } else {
      pr = { N: 0.85, L: 0.68, H: 0.50 }[metricMap.PR] || 0;
    }
    
    const c = { N: 0, L: 0.22, H: 0.56 }[metricMap.C] || 0;
    const i = { N: 0, L: 0.22, H: 0.56 }[metricMap.I] || 0;
    const a = { N: 0, L: 0.22, H: 0.56 }[metricMap.A] || 0;
    
    const iscBase = 1 - ((1 - c) * (1 - i) * (1 - a));
    const exploitability = 8.22 * av * ac * pr * ui;
    
    let impact: number;
    if (scope === 'U') {
      impact = 6.42 * iscBase;
    } else {
      impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    }
    
    let baseScore: number;
    if (impact <= 0) {
      baseScore = 0;
    } else if (scope === 'U') {
      baseScore = Math.min(impact + exploitability, 10);
    } else {
      baseScore = Math.min(1.08 * (impact + exploitability), 10);
    }
    
    return Math.round(Math.ceil(baseScore * 10) / 10 * 10) / 10;
  }
  
  private extractFixedVersions(vuln: OSVVulnerability): string | undefined {
    if (!vuln.affected) return undefined;
    
    const fixedVersions = new Set<string>();
    
    for (const affected of vuln.affected) {
      if (affected.ranges) {
        for (const range of affected.ranges) {
          for (const event of range.events) {
            if (event.fixed) {
              fixedVersions.add(event.fixed);
            }
          }
        }
      }
    }
    
    return fixedVersions.size > 0 ? Array.from(fixedVersions).join(', ') : undefined;
  }
  
  private extractAffectedVersions(vuln: OSVVulnerability): string {
    if (!vuln.affected) return 'Unknown';
    
    const ranges: string[] = [];
    
    for (const affected of vuln.affected) {
      if (affected.ranges) {
        for (const range of affected.ranges) {
          let rangeStr = '';
          for (const event of range.events) {
            if (event.introduced) {
              rangeStr = `>=${event.introduced}`;
            }
            if (event.fixed) {
              rangeStr += ` <${event.fixed}`;
            }
          }
          if (rangeStr) ranges.push(rangeStr);
        }
      }
      if (affected.versions) {
        ranges.push(affected.versions.join(', '));
      }
    }
    
    return ranges.length > 0 ? ranges.join(', ') : 'Unknown';
  }
}
