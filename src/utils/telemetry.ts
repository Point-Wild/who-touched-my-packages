import * as clack from '@clack/prompts';
import os from 'node:os';
import { WTMP_TELEMETRY_SERVER } from './consts.js';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface TelemetryPayload {
  email: string;
  os: string;
  platform: string;
  arch: string;
  cpus: number;
  memory: number;
  ci_environment?: string;
  timestamp: string;
  version: string;
}

function detectCIEnvironment(): string | undefined {
  if (process.env.GITHUB_ACTIONS) return 'github-actions';
  if (process.env.JENKINS_URL || process.env.JENKINS_HOME) return 'jenkins';
  if (process.env.GITLAB_CI) return 'gitlab-ci';
  if (process.env.CIRCLECI) return 'circleci';
  if (process.env.TRAVIS) return 'travis';
  if (process.env.DRONE) return 'drone';
  if (process.env.BUILDKITE) return 'buildkite';
  if (process.env.TEAMCITY_VERSION) return 'teamcity';
  if (process.env.CI) return 'generic';
  return undefined;
}

export interface SystemTelemetryPayload {
  os: string;
  platform: string;
  arch: string;
  cpus: number;
  memory: number;
  ci_environment?: string;
  timestamp: string;
  version: string;
}

export interface UserTelemetryPayload {
  email: string;
}

interface WtmpCache {
  email?: string;
}

const WTMP_CACHE_PATH = join(homedir(), '.wtmp');

async function readCachedEmail(): Promise<string | null> {
  try {
    const content = await readFile(WTMP_CACHE_PATH, 'utf-8');
    const cache: WtmpCache = JSON.parse(content);
    if (cache.email && typeof cache.email === 'string') {
      return cache.email;
    }
  } catch {
    // File doesn't exist, is corrupted, or has invalid JSON - ignore and return null
  }
  return null;
}

async function cacheEmail(email: string): Promise<void> {
  try {
    const cache: WtmpCache = { email };
    await writeFile(WTMP_CACHE_PATH, JSON.stringify(cache, null, 2), 'utf-8');
  } catch {
    // Failed to write cache - ignore and continue
  }
}

export function collectSystemTelemetry(version: string): SystemTelemetryPayload {
  const totalMemoryGB = Math.round(os.totalmem() / 1024 / 1024 / 1024);

  return {
    os: os.type(),
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    memory: totalMemoryGB,
    ci_environment: detectCIEnvironment(),
    timestamp: new Date().toISOString(),
    version,
  };
}

export async function collectEmail(isCI: boolean): Promise<string> {
  if (isCI) {
    return 'ci@automated.run';
  }

  // Try to read cached email first
  const cachedEmail = await readCachedEmail();
  if (cachedEmail) {
    return cachedEmail;
  }

  const result = await clack.text({
    message: 'Your email will be used for product analytics and to send you updates and offers regarding Threat Point in accordance with our privacy policy at https://www.pointwild.com/legal/privacy-policy.\nEnter email address (required): ',
    validate(value) {
      if (!value) return 'Email is required';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Please enter a valid email address';
    },
  });

  if (clack.isCancel(result)) {
    console.error('Email is required to use this tool. Use --ci for CI environments.');
    process.exit(1);
  }

  // Cache the email for future use
  await cacheEmail(result);

  return result;
}

export async function collectTelemetry(version: string, isCI: boolean): Promise<TelemetryPayload | null> {
  const email = await collectEmail(isCI);
  const systemTelemetry = collectSystemTelemetry(version);

  return {
    email,
    ...systemTelemetry,
  };
}

export async function submitUserTelemetry(payload: UserTelemetryPayload, run_id: string): Promise<void> {
  const serverUrl = process.env.WTMP_TELEMETRY_SERVER ?? WTMP_TELEMETRY_SERVER;
  const url = `${serverUrl}sql`;

  const query = `UPDATE telemetry:u'${run_id}' MERGE { email: '${escapeString(payload.email)}' }`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Accept': 'application/json',
      'surreal-ns': 'wtmp',
      'surreal-db': 'main'
    },
    body: query,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => 'Unknown error');
    throw new Error(`Telemetry submission failed: ${response.status} ${response.statusText} - ${text}`);
  }
}

export async function submitSystemTelemetry(payload: SystemTelemetryPayload, run_id: string): Promise<void> {
  const serverUrl = process.env.WTMP_TELEMETRY_SERVER ?? WTMP_TELEMETRY_SERVER;
  const url = `${serverUrl}sql`;

  const query = `CREATE telemetry:u'${run_id}' SET os = '${escapeString(payload.os)}', platform = '${escapeString(payload.platform)}', arch = '${escapeString(payload.arch)}', cpus = ${payload.cpus}, memory = ${payload.memory}, ci_environment = ${payload.ci_environment ? `'${escapeString(payload.ci_environment)}'` : 'NONE'}, version = '${escapeString(payload.version)}'`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Accept': 'application/json',
      'surreal-ns': 'wtmp',
      'surreal-db': 'main'
    },
    body: query,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => 'Unknown error');
    throw new Error(`Telemetry submission failed: ${response.status} ${response.statusText} - ${text}`);
  }
}

function escapeString(str: string): string {
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
