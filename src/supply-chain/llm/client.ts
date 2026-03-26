import { ChatAnthropic } from '@langchain/anthropic';
import { ChatOpenAI } from '@langchain/openai';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';
import type { StructuredToolInterface } from '@langchain/core/tools';

export interface LLMClientOptions {
  apiKey?: string;
  model: string;
  provider?: 'anthropic' | 'openrouter' | 'openai';
}

/**
 * Create a LangChain chat model instance.
 * Uses the generic BaseChatModel interface so the rest of the codebase is provider-agnostic.
 * To add a new provider, add a case here — no other files need to change.
 */
export function createChatModel(options: LLMClientOptions): BaseChatModel {
  const { model, provider = 'anthropic' } = options;
  // Resolve API key: explicit option > provider-specific env var > generic fallback
  const apiKey = options.apiKey
    ?? (provider === 'openrouter' ? process.env.OPENROUTER_API_KEY : undefined)
    ?? (provider === 'anthropic'  ? process.env.ANTHROPIC_API_KEY  : undefined)
    ?? (provider === 'openai'     ? process.env.OPENAI_API_KEY     : undefined)
    ?? '';


  switch (provider) {
    case 'anthropic':
      return new ChatAnthropic({
        model,
        apiKey,
        maxTokens: 8192,
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
      throw new Error(`Unsupported LLM provider: ${provider}. Supported: anthropic, openrouter, openai`);
  }
}

/**
 * Bind tools to a chat model and return a runnable that supports tool calling.
 */
export function bindTools(chatModel: BaseChatModel, tools: StructuredToolInterface[]) {
  return chatModel.bindTools!(tools);
}
