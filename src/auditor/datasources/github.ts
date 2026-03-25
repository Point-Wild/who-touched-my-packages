import { DataSource } from './base.js';
import type { Dependency } from '../../scanner/types.js';
import type { Vulnerability } from '../types.js';

interface GitHubAdvisory {
  id: string;
  ghsaId: string;
  summary: string;
  description: string;
  severity: string;
  cvss?: {
    score: number;
    vectorString: string;
  };
  cwes?: {
    nodes: Array<{
      cweId: string;
      name: string;
    }>;
  };
  references?: Array<{
    url: string;
  }>;
  publishedAt: string;
  vulnerabilities: {
    nodes: Array<{
      package: {
        name: string;
        ecosystem: string;
      };
      vulnerableVersionRange: string;
      firstPatchedVersion?: {
        identifier: string;
      };
    }>;
  };
}

interface GitHubResponse {
  data?: {
    securityVulnerabilities: {
      nodes: Array<{
        advisory: GitHubAdvisory;
      }>;
    };
  };
  errors?: Array<{
    message: string;
  }>;
}

export class GitHubDataSource extends DataSource {
  name = 'GitHub';
  private apiUrl = 'https://api.github.com/graphql';
  private token?: string;
  
  constructor() {
    super();
    this.token = process.env.GITHUB_TOKEN;
  }
  
  async checkVulnerabilities(dependencies: Dependency[]): Promise<Vulnerability[]> {
    if (dependencies.length === 0) {
      return [];
    }
    
    const vulnerabilities: Vulnerability[] = [];
    
    const npmDeps = dependencies.filter(d => d.ecosystem === 'npm');
    const pypiDeps = dependencies.filter(d => d.ecosystem === 'pypi');
    
    if (npmDeps.length > 0) {
      const npmVulns = await this.queryEcosystem(npmDeps, 'NPM');
      vulnerabilities.push(...npmVulns);
    }
    
    if (pypiDeps.length > 0) {
      const pypiVulns = await this.queryEcosystem(pypiDeps, 'PIP');
      vulnerabilities.push(...pypiVulns);
    }
    
    return vulnerabilities;
  }
  
  private async queryEcosystem(
    dependencies: Dependency[],
    ecosystem: 'NPM' | 'PIP'
  ): Promise<Vulnerability[]> {
    const packageNames = dependencies.map(d => d.name);
    const batchSize = 10;
    const vulnerabilities: Vulnerability[] = [];
    
    for (let i = 0; i < packageNames.length; i += batchSize) {
      const batch = packageNames.slice(i, i + batchSize);
      const batchVulns = await this.queryBatch(batch, ecosystem, dependencies);
      vulnerabilities.push(...batchVulns);
    }
    
    return vulnerabilities;
  }
  
  private async queryBatch(
    packageNames: string[],
    ecosystem: 'NPM' | 'PIP',
    dependencies: Dependency[]
  ): Promise<Vulnerability[]> {
    const query = `
      query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
        securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package) {
          nodes {
            advisory {
              id
              ghsaId
              summary
              description
              severity
              cvss {
                score
                vectorString
              }
              cwes(first: 10) {
                nodes {
                  cweId
                  name
                }
              }
              references {
                url
              }
              publishedAt
              vulnerabilities(first: 10) {
                nodes {
                  package {
                    name
                    ecosystem
                  }
                  vulnerableVersionRange
                  firstPatchedVersion {
                    identifier
                  }
                }
              }
            }
          }
        }
      }
    `;
    
    const vulnerabilities: Vulnerability[] = [];
    
    for (const packageName of packageNames) {
      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };
        
        if (this.token) {
          headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        const response = await this.fetchWithRetry(this.apiUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            query,
            variables: {
              ecosystem,
              package: packageName,
            },
          }),
        });
        
        if (!response.ok) {
          continue;
        }
        
        const data: GitHubResponse = await response.json();
        
        if (data.errors) {
          continue;
        }
        
        if (data.data?.securityVulnerabilities?.nodes) {
          const dep = dependencies.find(d => d.name === packageName);
          if (!dep) continue;
          
          for (const node of data.data.securityVulnerabilities.nodes) {
            vulnerabilities.push(this.transformVulnerability(node.advisory, dep));
          }
        }
      } catch (error) {
        continue;
      }
    }
    
    return vulnerabilities;
  }
  
  private transformVulnerability(
    advisory: GitHubAdvisory,
    dep: Dependency
  ): Vulnerability {
    const vuln = advisory.vulnerabilities.nodes.find(
      v => v.package.name === dep.name
    );
    
    return {
      id: advisory.ghsaId,
      packageName: dep.name,
      packageVersion: dep.version,
      ecosystem: dep.ecosystem,
      severity: this.normalizeSeverity(advisory.severity),
      title: advisory.summary,
      description: advisory.description,
      cvss: advisory.cvss?.score,
      cwe: advisory.cwes?.nodes.map(cwe => cwe.cweId),
      references: advisory.references?.map(ref => ref.url) || [],
      affectedVersions: vuln?.vulnerableVersionRange || 'Unknown',
      fixedVersions: vuln?.firstPatchedVersion?.identifier,
      publishedDate: advisory.publishedAt,
      source: 'GitHub',
    };
  }
}
