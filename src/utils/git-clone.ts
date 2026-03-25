import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export interface CloneOptions {
  repoUrl: string;
  branch?: string;
}

export interface CloneResult {
  path: string;
  cleanup: () => Promise<void>;
}

export async function cloneRepository(options: CloneOptions): Promise<CloneResult> {
  const tempDir = await mkdtemp(join(tmpdir(), 'wtmd-'));
  
  try {
    const cloneArgs = ['clone'];
    
    if (options.branch) {
      cloneArgs.push('--branch', options.branch);
    }
    
    cloneArgs.push('--depth', '1');
    cloneArgs.push(options.repoUrl);
    cloneArgs.push(tempDir);
    
    const command = `git ${cloneArgs.join(' ')}`;
    
    await execAsync(command, {
      maxBuffer: 10 * 1024 * 1024,
    });
    
    return {
      path: tempDir,
      cleanup: async () => {
        await rm(tempDir, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(tempDir, { recursive: true, force: true });
    throw new Error(`Failed to clone repository: ${error instanceof Error ? error.message : String(error)}`);
  }
}
