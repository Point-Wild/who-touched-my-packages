import { theme } from '../ui/theme.js';

export class Logger {
  private verbose: boolean;
  
  constructor(verbose = false) {
    this.verbose = verbose;
  }
  
  info(message: string): void {
    console.log(theme.info(message));
  }
  
  success(message: string): void {
    console.log(theme.success(message));
  }
  
  error(message: string): void {
    console.error(theme.critical(`Error: ${message}`));
  }
  
  debug(message: string): void {
    if (this.verbose) {
      console.log(theme.dim(`[DEBUG] ${message}`));
    }
  }
  
  warn(message: string): void {
    console.warn(theme.medium(`Warning: ${message}`));
  }
}
