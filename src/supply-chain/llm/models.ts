/**
 * Supported LLM providers and their default/known-good models.
 *
 * To add a new provider, add an entry here and a corresponding case in client.ts.
 * To add a new model, add it to the relevant provider's `models` array.
 */

export type LLMProvider = 'anthropic' | 'openai' | 'gemini' | 'openrouter';

export interface ProviderConfig {
  /** Display name shown in help text and errors. */
  name: string;
  /** Environment variable holding the API key. */
  envVar: string;
  /** Known-good model identifiers for this provider (first entry is the default). */
  models: string[];
}

export const PROVIDERS: Record<LLMProvider, ProviderConfig> = {
  anthropic: {
    name: 'Anthropic',
    envVar: 'ANTHROPIC_API_KEY',
    models: [
      'claude-sonnet-4-6',
      'claude-haiku-4-5-20251001',
      'claude-opus-4-6',
    ],
  },
  openai: {
    name: 'OpenAI',
    envVar: 'OPENAI_API_KEY',
    models: [
      'gpt-5.3-codex',
      'gpt-5.4',
      'gpt-5.4-mini',
      'gpt-5.2',
      'gpt-4.1',
      'gpt-4.1-mini',
      'o3',
      'o4-mini',
    ],
  },
  gemini: {
    name: 'Gemini',
    envVar: 'GOOGLE_API_KEY',
    models: [
      'gemini-2.5-pro',
      'gemini-2.5-flash',
      'gemini-2.5-flash-lite',
      'gemini-3.1-pro-preview',
    ],
  },
  openrouter: {
    name: 'OpenRouter',
    envVar: 'OPENROUTER_API_KEY',
    models: [
      'openai/gpt-5.3-codex',
      'anthropic/claude-sonnet-4-5',
      'openai/gpt-5.4',
      'openai/gpt-5.4-mini',
      'openai/gpt-5.2',
      'google/gemini-2.5-pro',
    ],
  },
};

export const DEFAULT_PROVIDER: LLMProvider = 'anthropic';
export const DEFAULT_MODEL = PROVIDERS[DEFAULT_PROVIDER].models[0];
export const DEFAULT_CONCURRENCY = 8;

/**
 * Infer the LLM provider from a model name.
 *
 * Rules:
 * 1. If the model starts with "google/" (e.g. "google/gemini-2.5-pro"), assume Gemini.
 * 2. If the model contains a "/" (e.g. "anthropic/claude-sonnet-4-5"), assume OpenRouter.
 * 3. If it starts with "claude", assume Anthropic.
 * 4. If it starts with "gpt" or "o1" or "o3" or "o4-mini", assume OpenAI.
 * 5. If it starts with "gemini", assume Gemini.
 * 6. Otherwise return undefined (caller should require an explicit --llm-provider).
 */
export function inferProvider(model: string): LLMProvider | undefined {
  if (model.startsWith('google/')) return 'gemini';
  if (model.includes('/')) return 'openrouter';
  if (model.startsWith('claude')) return 'anthropic';
  if (/^(gpt|o[134]-|o[134]$)/.test(model)) return 'openai';
  if (model.startsWith('gemini')) return 'gemini';
  return undefined;
}

/**
 * Resolve the model to use given an optional explicit model and provider.
 *
 * - If a model is explicitly provided, return it as-is.
 * - If only a provider is given, return that provider's default model (first in its list).
 * - If neither is given, return the global DEFAULT_MODEL.
 */
export function resolveModel(model?: string, provider?: LLMProvider): string {
  if (model) return model;
  if (provider) return PROVIDERS[provider].models[0];
  return DEFAULT_MODEL;
}

/**
 * Check whether a model string is in the known-good list for its provider.
 * Returns a warning message if not, or undefined if it matches.
 */
export function validateModel(model: string, provider: LLMProvider): string | undefined {
  const config = PROVIDERS[provider];
  const known = config.models;

  if (known.some(m => model.startsWith(m) || m.startsWith(model))) {
    return undefined; // close enough match (allows version suffixes)
  }

  return (
    `Unknown model "${model}" for ${config.name}. ` +
    `Known models: ${known.join(', ')}. ` +
    `The request will still be sent — if this is a valid model identifier it will work.`
  );
}
