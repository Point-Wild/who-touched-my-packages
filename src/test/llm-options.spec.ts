import type { LLMProvider } from '../supply-chain/llm/models.js';
import { resolveModel } from '../supply-chain/llm/models.js';
import { resolveApiKey } from '../supply-chain/utils.js';

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
      if (!value) throw new Error(`Missing value for --llm-provider in ${testFileName}`);
      if (!isLLMProvider(value)) throw new Error(`Unsupported --llm-provider "${value}" in ${testFileName}`);
      provider = value;
      index++;
      continue;
    }

    if (arg === '--supply-chain-model') {
      const value = process.argv[index + 1];
      if (!value) throw new Error(`Missing value for --supply-chain-model in ${testFileName}`);
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
    if (!isLLMProvider(envProvider)) throw new Error(`Unsupported npm_config_llm_provider "${envProvider}" in ${testFileName}`);
    provider = envProvider;
  }

  if (!model && envModel && envModel !== 'true') {
    model = envModel;
  }

  if (!provider && positionalProvider) {
    if (!isLLMProvider(positionalProvider)) throw new Error(`Unsupported --llm-provider "${positionalProvider}" in ${testFileName}`);
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
