import assert from 'node:assert/strict';
import { resolveApiKey } from './src/supply-chain/utils.js';
import { resolveModel } from './src/supply-chain/llm/models.js';
import type { LLMProvider } from './src/supply-chain/llm/models.js';

interface TestLLMOptions {
  provider?: LLMProvider;
  model: string;
  apiKey: string;
}

function isLLMProvider(value: string): value is LLMProvider {
  return value === 'anthropic' || value === 'openai' || value === 'gemini' || value === 'openrouter';
}

export function parseTestLLMOptions(testFileName: string): TestLLMOptions {
  let provider: LLMProvider | undefined;
  let model: string | undefined;
  let positionalProvider: string | undefined;
  let positionalModel: string | undefined;

  for (let index = 2; index < process.argv.length; index++) {
    const arg = process.argv[index];

    if (arg === '--llm-provider') {
      const value = process.argv[index + 1];
      assert(value, `Missing value for --llm-provider in ${testFileName}`);
      assert(isLLMProvider(value), `Unsupported --llm-provider "${value}" in ${testFileName}`);
      provider = value;
      index++;
      continue;
    }

    if (arg === '--supply-chain-model') {
      const value = process.argv[index + 1];
      assert(value, `Missing value for --supply-chain-model in ${testFileName}`);
      model = value;
      index++;
      continue;
    }

    if (!arg.startsWith('-')) {
      if (!positionalProvider) {
        positionalProvider = arg;
      } else if (!positionalModel) {
        positionalModel = arg;
      }
    }
  }

  const envProvider = process.env.npm_config_llm_provider;
  const envModel = process.env.npm_config_supply_chain_model;

  if (!provider && envProvider && envProvider !== 'true') {
    assert(isLLMProvider(envProvider), `Unsupported npm_config_llm_provider "${envProvider}" in ${testFileName}`);
    provider = envProvider;
  }

  if (!model && envModel && envModel !== 'true') {
    model = envModel;
  }

  if (!provider && positionalProvider) {
    assert(isLLMProvider(positionalProvider), `Unsupported --llm-provider "${positionalProvider}" in ${testFileName}`);
    provider = positionalProvider;
  }

  if (!model && positionalModel) {
    model = positionalModel;
  }

  const resolvedModel = resolveModel(model, provider);
  const apiKey = resolveApiKey(undefined, provider, resolvedModel);

  return {
    provider,
    model: resolvedModel,
    apiKey,
  };
}
