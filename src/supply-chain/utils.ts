/**
 * Resolve the LLM API key from (in priority order):
 * 1. options.apiKey passed directly
 * 2. ANTHROPIC_API_KEY env var
 */
export function resolveApiKey(optionsKey?: string): string {
  if (optionsKey) return optionsKey;

  const envKey = process.env.ANTHROPIC_API_KEY;
  if (envKey) return envKey;

  throw new Error(
    'No API key found. Set one of:\n' +
    '  1. Pass apiKey in options\n' +
    '  2. Set ANTHROPIC_API_KEY environment variable'
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
