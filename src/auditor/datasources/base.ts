import type { Dependency } from '../../scanner/types.js';
import type { Vulnerability } from '../types.js';

export abstract class DataSource {
  abstract name: string;
  
  abstract checkVulnerabilities(
    dependencies: Dependency[]
  ): Promise<Vulnerability[]>;
  
  protected async fetchWithRetry(
    url: string,
    options: RequestInit = {},
    retries = 3
  ): Promise<Response> {
    for (let i = 0; i < retries; i++) {
      try {
        const response = await fetch(url, {
          ...options,
          headers: {
            'Content-Type': 'application/json',
            ...options.headers,
          },
        });
        
        if (response.ok) {
          return response;
        }
        
        if (response.status === 429 && i < retries - 1) {
          const retryAfter = response.headers.get('Retry-After');
          const delay = retryAfter ? parseInt(retryAfter) * 1000 : 1000 * (i + 1);
          await this.sleep(delay);
          continue;
        }
        
        if (response.status >= 500 && i < retries - 1) {
          await this.sleep(1000 * (i + 1));
          continue;
        }
        
        return response;
      } catch (error) {
        if (i === retries - 1) {
          throw error;
        }
        await this.sleep(1000 * (i + 1));
      }
    }
    
    throw new Error('Max retries exceeded');
  }
  
  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  protected normalizeSeverity(severity: string): Vulnerability['severity'] {
    const normalized = severity.toUpperCase();
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
      return normalized as Vulnerability['severity'];
    }
    return 'UNKNOWN';
  }
}
