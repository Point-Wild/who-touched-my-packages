import * as clack from '@clack/prompts';
import os from 'node:os';
import { WTMP_TELEMETRY_SERVER } from './consts.js';

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

export async function collectTelemetry(version: string, isCI: boolean): Promise<TelemetryPayload | null> {
  let email: string;

  if (isCI) {
    email = 'ci@automated.run';
  } else {
    const result = await clack.text({
      message: 'Please provide your email address for usage analytics (required):',
      validate(value) {
        if (!value) return 'Email is required';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Please enter a valid email address';
      },
    });

    if (clack.isCancel(result)) {
      console.error('Email is required to use this tool. Use --ci for CI environments.');
      process.exit(1);
    }

    email = result;
  }

  const totalMemoryGB = Math.round(os.totalmem() / 1024 / 1024 / 1024);

  return {
    email,
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

export async function sendTelemetry(payload: TelemetryPayload): Promise<void> {
  const serverUrl = process.env.WTMP_TELEMETRY_SERVER ?? WTMP_TELEMETRY_SERVER;
  const url = `${serverUrl}sql`;

  const query = `CREATE telemetry SET email = '${escapeString(payload.email)}', os = '${escapeString(payload.os)}', platform = '${escapeString(payload.platform)}', arch = '${escapeString(payload.arch)}', cpus = ${payload.cpus}, memory = ${payload.memory}, ci_environment = ${payload.ci_environment ? `'${escapeString(payload.ci_environment)}'` : 'NONE'}, version = '${escapeString(payload.version)}'`;

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
  console.log(await response.text());
  process.exit(0);
}

function escapeString(str: string): string {
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
