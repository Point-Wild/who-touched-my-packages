import { ChatAnthropic } from '@langchain/anthropic';
import { ChatOpenAI } from '@langchain/openai';
import { ChatGoogleGenerativeAI } from '@langchain/google-genai';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { StructuredToolInterface } from '@langchain/core/tools';
import { PROVIDERS, DEFAULT_PROVIDER, inferProvider, validateModel, type LLMProvider } from './models.js';

export interface LLMClientOptions {
  apiKey?: string;
  model: string;
  provider?: LLMProvider;
}

/**
 * Create a LangChain chat model instance.
 *
 * Provider resolution order:
 * 1. Explicit `provider` option
 * 2. Auto-inferred from model name (e.g. "claude-*" -> anthropic, "gpt-*" -> openai, "gemini-*" -> gemini, contains "/" -> openrouter)
 * 3. Falls back to DEFAULT_PROVIDER ("anthropic")
 *
 * To add a new provider, add an entry in models.ts and a case here.
 */
export function createChatModel(options: LLMClientOptions): BaseChatModel {
  const { model } = options;
  const provider = options.provider ?? inferProvider(model) ?? DEFAULT_PROVIDER;

  // Warn (but don't block) on unrecognized model names
  const warning = validateModel(model, provider);
  if (warning) {
    console.warn(`⚠ ${warning}`);
  }

  // Resolve API key: explicit option > provider-specific env var
  const config = PROVIDERS[provider];
  const apiKey = options.apiKey ?? process.env[config.envVar] ?? '';

  switch (provider) {
    case 'anthropic':
      return new ChatAnthropic({
        model,
        apiKey,
        maxTokens: 8192,
        temperature: 0,
      });
    case 'gemini':
      return new ChatGoogleGenerativeAI({
        model: model.replace(/^google\//, ''),  // strip "google/" prefix if present
        apiKey,
        maxOutputTokens: 8192,
        temperature: 0,
      });
    case 'openrouter':
      return new ChatOpenAI({
        model,
        apiKey,
        temperature: 0,
        maxTokens: 8192,
        configuration: {
          baseURL: 'https://openrouter.ai/api/v1',
        },
      });
    case 'openai':
      return new ChatOpenAI({
        model,
        apiKey,
        temperature: 0,
        maxTokens: 8192,
      });
    default:
      throw new Error(
        `Unsupported LLM provider: ${provider}. ` +
        `Supported: ${Object.keys(PROVIDERS).join(', ')}`
      );
  }
}

/**
 * Bind tools to a chat model and return a runnable that supports tool calling.
 */
export function bindTools(chatModel: BaseChatModel, tools: StructuredToolInterface[]) {
  return chatModel.bindTools!(tools);
}
