import { env } from 'node:process';
import pc from 'picocolors';

let disableColors = false;

export function setColorEnabled(enabled: boolean): void {
  disableColors = !enabled;
}

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
  
  // Return no-op functions when colors are disabled
  if (disableColors) {
    return {
      critical: (text: string) => text,
      high: (text: string) => text,
      medium: (text: string) => text,
      low: (text: string) => text,
      success: (text: string) => text,
      info: (text: string) => text,
      dim: (text: string) => text,
      bold: (text: string) => text,
      underline: (text: string) => text,
    };
  }
  
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

export let theme = createTheme();

export function recreateTheme(): void {
  theme = createTheme();
}

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

function supportsHyperlinks(): boolean {
  if (disableColors) return false;
  
  const term = env.TERM_PROGRAM;
  const termVersion = env.TERM_PROGRAM_VERSION;
  
  if (term === 'iTerm.app') {
    return true;
  }
  
  if (term === 'WezTerm') {
    return true;
  }
  
  if (term === 'vscode') {
    return true;
  }
  
  if (env.TERM?.includes('kitty')) {
    return true;
  }
  
  if (env.VTE_VERSION) {
    const version = parseInt(env.VTE_VERSION, 10);
    return version >= 5000;
  }
  
  return false;
}

export function hexToAnsi(color: string): string {
  if (color.startsWith('#')) {
    const r = parseInt(color.slice(1, 3), 16);
    const g = parseInt(color.slice(3, 5), 16);
    const b = parseInt(color.slice(5, 7), 16);

    if (!isNaN(r) && !isNaN(g) && !isNaN(b)) {
      return `\x1b[38;2;${r};${g};${b}m`;
    } else {
      return `\x1b[34m`;
    }
  }
  
  return ``;
}

export function createHyperlink(url: string, text: string, color?: string): string {
  if (disableColors) {
    return `${text} (${url})`;
  }
  
  const supportsLinks = supportsHyperlinks();
  
  let formattedText = text;

  if (color) {
    formattedText = hexToAnsi(color) + text + "\x1b[0m";
  }
  
  if (supportsLinks) {
    return `\x1b]8;;${url}\x1b\\${formattedText}\x1b]8;;\x1b\\`;
  } else {
    return `${formattedText} (${url})`;
  }
}

