export interface Config {
  scanPath: string;
  excludePatterns: string[];
  severityFilter?: string;
  failOnSeverity?: string;
  json: boolean;
  verbose: boolean;
}

export const defaultConfig: Partial<Config> = {
  excludePatterns: [],
  json: false,
  verbose: false,
};

export function shouldFailOnSeverity(
  summary: { critical: number; high: number; medium: number; low: number },
  failOnSeverity?: string
): boolean {
  if (!failOnSeverity) {
    return false;
  }
  
  const severity = failOnSeverity.toUpperCase();
  
  switch (severity) {
    case 'CRITICAL':
      return summary.critical > 0;
    case 'HIGH':
      return summary.critical > 0 || summary.high > 0;
    case 'MEDIUM':
      return summary.critical > 0 || summary.high > 0 || summary.medium > 0;
    case 'LOW':
      return summary.critical > 0 || summary.high > 0 || summary.medium > 0 || summary.low > 0;
    default:
      return false;
  }
}
