/**
 * Registry-level risk signals: typosquatting, dependency confusion, maintainer
 * takeover, publish anomalies, and provenance gaps.
 *
 * All computations are deterministic and require no additional network calls
 * beyond what the registry clients already make.
 */

import type { RegistrySignals } from '../types.js';

// ── Top npm packages commonly typosquatted ────────────────────────────────────
const TOP_NPM = [
  'lodash', 'express', 'react', 'axios', 'commander', 'chalk', 'moment',
  'uuid', 'dotenv', 'typescript', 'webpack', 'jest', 'eslint', 'prettier',
  'next', 'vue', 'angular', 'svelte', 'vite', 'rollup', 'esbuild', 'turbo',
  'parcel', 'yargs', 'minimist', 'meow', 'inquirer', 'prompts', 'ora',
  'figures', 'semver', 'glob', 'rimraf', 'mkdirp', 'fs-extra', 'cross-env',
  'debug', 'winston', 'pino', 'morgan', 'nodemon', 'ts-node', 'tsx',
  'zod', 'joi', 'yup', 'ajv', 'class-validator', 'reflect-metadata',
  'sequelize', 'mongoose', 'typeorm', 'knex', 'pg', 'mysql2', 'sqlite3',
  'redis', 'ioredis', 'bull', 'bullmq', 'amqplib',
  'fastify', 'koa', 'hapi', 'feathers', 'socket.io', 'ws',
  'got', 'node-fetch', 'undici', 'superagent',
  'passport', 'jsonwebtoken', 'bcrypt', 'argon2',
  'lodash', 'ramda', 'immer', 'rxjs', 'date-fns', 'dayjs',
  'mocha', 'chai', 'sinon', 'nock', 'supertest', 'vitest',
  'husky', 'lint-staged', 'commitlint',
  'react-dom', 'react-router', 'redux', 'zustand', 'mobx', 'jotai', 'recoil',
  'tailwindcss', 'styled-components', 'emotion', 'sass',
  'graphql', 'apollo-server', 'type-graphql',
  'prisma', 'drizzle-orm', 'kysely',
  'sharp', 'jimp', 'multer', 'formidable',
  'helmet', 'cors', 'body-parser', 'cookie-parser',
  'cheerio', 'puppeteer', 'playwright', 'selenium-webdriver',
  'aws-sdk', 'firebase', 'supabase',
  'babel-core', 'autoprefixer', 'postcss', 'cssnano',
  'lodash-es', 'date-fns', 'luxon',
];

// ── Top PyPI packages commonly typosquatted ───────────────────────────────────
const TOP_PYPI = [
  'requests', 'numpy', 'pandas', 'flask', 'django', 'setuptools',
  'pip', 'wheel', 'six', 'certifi', 'urllib3', 'charset-normalizer',
  'idna', 'attrs', 'packaging', 'pyparsing', 'toml', 'pyyaml', 'click',
  'fastapi', 'uvicorn', 'starlette', 'pydantic', 'sqlalchemy', 'alembic',
  'pytest', 'hypothesis', 'black', 'flake8', 'mypy', 'pylint', 'isort',
  'boto3', 'botocore', 'awscli',
  'scikit-learn', 'tensorflow', 'torch', 'keras', 'xgboost', 'lightgbm',
  'matplotlib', 'seaborn', 'plotly', 'bokeh', 'pillow', 'opencv-python',
  'cryptography', 'paramiko', 'fabric', 'ansible', 'celery', 'redis',
  'psycopg2', 'pymongo', 'motor', 'sqlmodel', 'tortoise-orm',
  'aiohttp', 'httpx', 'websockets', 'grpcio', 'protobuf',
  'jinja2', 'markupsafe', 'werkzeug', 'wtforms', 'marshmallow',
  'arrow', 'pendulum', 'python-dateutil', 'pytz', 'humanize',
  'rich', 'typer', 'loguru', 'tqdm', 'more-itertools',
  'pytest-django', 'pytest-asyncio', 'pytest-cov', 'coverage',
  'scrapy', 'beautifulsoup4', 'lxml', 'html5lib',
  'google-cloud-storage', 'azure-storage-blob',
  'openai', 'anthropic', 'langchain', 'transformers',
  'sympy', 'scipy', 'statsmodels',
  'pydantic-settings', 'python-dotenv', 'dynaconf',
];

/**
 * Compute the Levenshtein edit distance between two strings.
 */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  // Use two-row rolling array for O(min(m,n)) space
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  let curr = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/**
 * Check if a package name is a likely typosquat of a well-known package.
 * Returns the candidate it resembles, or null if no match.
 */
export function computeTyposquatCandidate(
  name: string,
  ecosystem: 'npm' | 'pypi' | 'cargo' | 'go' | 'ruby'
): string | null {
  const list = ecosystem === 'npm'
    ? TOP_NPM
    : ecosystem === 'pypi'
      ? TOP_PYPI
      : [];
  // For scoped npm packages (@org/pkg), compare only the local part
  const normalized = name.startsWith('@')
    ? (name.split('/')[1] ?? name)
    : name;
  const lower = normalized.toLowerCase();

  let closest: string | null = null;
  let minDist = Infinity;

  for (const known of list) {
    if (known === lower) return null; // exact match = not a typosquat
    const dist = levenshtein(lower, known.toLowerCase());
    if (dist > 0 && dist <= 2 && dist < minDist) {
      minDist = dist;
      closest = known;
    }
  }
  return closest;
}

/**
 * Detect dependency confusion risk: internal-looking package name published
 * publicly. These almost always indicate an attack or accidental exposure.
 */
export function isDependencyConfusion(name: string): boolean {
  return /^@[^/]+\/(internal|private|corp|shared|local)[/-]|^(internal|private|corp)-/i.test(name);
}

/**
 * Aggregate individual registry signals into a 0–10 risk score.
 * Higher = more suspicious metadata-level signals.
 */
export function computeRegistryRiskScore(
  signals: Omit<RegistrySignals, 'riskScore'>
): number {
  let score = 0;
  if (signals.maintainerChangedInLatestRelease) score += 3;
  if (signals.packageAgeDays < 30) score += 2;
  if (signals.publishedDaysAgo < 3) score += 1;
  if (signals.typosquatCandidate !== null) score += 3;
  if (signals.isDependencyConfusion) score += 3;
  if (!signals.hasProvenance && signals.packageAgeDays > 365) score += 1;
  return Math.min(score, 10);
}
