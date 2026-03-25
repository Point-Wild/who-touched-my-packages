import { DataSource } from './base.js';
import type { Dependency } from '../../scanner/types.js';
import type { Vulnerability } from '../types.js';

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
        ecosystem: dep.ecosystem === 'npm' ? 'npm' : 'PyPI',
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
      
      const data: OSVResponse = await response.json();
      const vulnerabilities: Vulnerability[] = [];
      
      for (let i = 0; i < data.results.length; i++) {
        const result = data.results[i];
        const dep = dependencies[i];
        
        if (result.vulns) {
          for (const vuln of result.vulns) {
            vulnerabilities.push(this.transformVulnerability(vuln, dep));
          }
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      return [];
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
        const score = parseFloat(sev.score.split('/')[0]);
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
        return parseFloat(sev.score.split('/')[0]);
      }
    }
    
    return undefined;
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
