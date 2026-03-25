import pc from 'picocolors';
import { env } from 'node:process';

export interface Theme {
  critical: (text: string) => string;
  high: (text: string) => string;
  medium: (text: string) => string;
  low: (text: string) => string;
  success: (text: string) => string;
  info: (text: string) => string;
  dim: (text: string) => string;
  bold: (text: string) => string;
  underline: (text: string) => string;
}

function detectColorMode(): 'light' | 'dark' {
  const colorTerm = env.COLORTERM;
  const term = env.TERM;
  
  if (colorTerm === 'truecolor' || colorTerm === '24bit') {
    return 'dark';
  }
  
  if (term?.includes('256color')) {
    return 'dark';
  }
  
  if (env.TERM_PROGRAM === 'Apple_Terminal') {
    return 'light';
  }
  
  return 'dark';
}

export function createTheme(): Theme {
  const mode = detectColorMode();
  
  return {
    critical: (text: string) => pc.red(pc.bold(text)),
    high: (text: string) => pc.yellow(pc.bold(text)),
    medium: (text: string) => pc.yellow(text),
    low: (text: string) => pc.blue(text),
    success: (text: string) => pc.green(text),
    info: (text: string) => pc.cyan(text),
    dim: (text: string) => pc.dim(text),
    bold: (text: string) => pc.bold(text),
    underline: (text: string) => pc.underline(text),
  };
}

export const theme = createTheme();

export function getSeverityColor(severity: string): (text: string) => string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return theme.critical;
    case 'HIGH':
      return theme.high;
    case 'MEDIUM':
      return theme.medium;
    case 'LOW':
      return theme.low;
    default:
      return theme.dim;
  }
}

export const icons = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  success: '✅',
  warning: '⚠️',
  info: 'ℹ️',
  package: '📦',
  file: '📄',
  search: '🔍',
  shield: '🛡️',
};
