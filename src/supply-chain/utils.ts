import { PROVIDERS, DEFAULT_PROVIDER, inferProvider, type LLMProvider } from './llm/models.js';

/**
 * Resolve the LLM API key from (in priority order):
 * 1. options.apiKey passed directly
 * 2. Provider-specific env var (ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, OPENROUTER_API_KEY)
 *
 * The provider is auto-inferred from the model name when not specified explicitly.
 */
export function resolveApiKey(optionsKey?: string, provider?: LLMProvider, model?: string): string {
  if (optionsKey) return optionsKey;

  const resolved = provider ?? (model ? inferProvider(model) : undefined) ?? DEFAULT_PROVIDER;
  const config = PROVIDERS[resolved];
  const envKey = process.env[config.envVar];
  if (envKey) return envKey;

  throw new Error(
    `No API key found for ${config.name}. Set one of:\n` +
    `  1. Pass apiKey in options\n` +
    `  2. Set ${config.envVar} environment variable\n\n` +
    `All supported providers and their env vars:\n` +
    Object.entries(PROVIDERS).map(([id, c]) => `  • ${id}: ${c.envVar}`).join('\n')
  );
}

/**
 * Simple concurrency limiter for parallel async operations.
 */
export async function pMap<T, R>(
  items: T[],
  fn: (item: T, index: number) => Promise<R>,
  concurrency: number
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await fn(items[index], index);
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    () => worker()
  );
  await Promise.all(workers);
  return results;
}

/**
 * Generate a stable key for a dependency in metadata/source maps.
 */
export function depKey(ecosystem: string, name: string): string {
  return `${ecosystem}:${name}`;
}

/**
 * Extract JSON from an LLM response that may contain markdown fences or extra text.
 */
export function extractJSON(text: string): unknown {
  // Try to find JSON array first
  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    try { return JSON.parse(arrayMatch[0]); } catch { /* fall through */ }
  }
  // Try JSON object
  const objMatch = text.match(/\{[\s\S]*\}/);
  if (objMatch) {
    try { return JSON.parse(objMatch[0]); } catch { /* fall through */ }
  }
  return null;
}
