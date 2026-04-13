import { spawnSync } from 'node:child_process';

const suites = {
  static: [
    ['npm', 'run', 'typecheck'],
    ['npm', 'run', 'test:cve:npm'],
    ['npm', 'run', 'test:cve:python'],
    ['npm', 'run', 'test:cve:go'],
    ['npm', 'run', 'test:cve:rust'],
    ['npm', 'run', 'test:cve:ruby'],
  ],
  llm: [
    ['bun', 'tests/llm-npm-package.test.ts'],
    ['bun', 'tests/llm-python-package.test.ts'],
    ['bun', 'tests/llm-go-package.test.ts'],
    ['bun', 'tests/llm-rust-package.test.ts'],
    ['bun', 'tests/llm-ruby-package.test.ts'],
  ],
};

function normalizeForwardedArgs(args) {
  const normalized = [];
  let llmProvider = process.env.npm_config_llm_provider;
  let supplyChainModel = process.env.npm_config_supply_chain_model;

  if (llmProvider === 'true') {
    llmProvider = undefined;
  }

  if (supplyChainModel === 'true') {
    supplyChainModel = undefined;
  }

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];

    if (arg === '--llm-provider' || arg === '--supply-chain-model') {
      normalized.push(arg);
      if (index + 1 < args.length) {
        normalized.push(args[index + 1]);
        index++;
      }
      continue;
    }
  }

  if (!normalized.length && args.length === 2 && !args[0].startsWith('-') && !args[1].startsWith('-')) {
    llmProvider ??= args[0];
    supplyChainModel ??= args[1];
  }

  if (llmProvider) {
    normalized.push('--llm-provider', llmProvider);
  }

  if (supplyChainModel) {
    normalized.push('--supply-chain-model', supplyChainModel);
  }

  return normalized;
}

const mode = process.argv[2] === 'llm' || process.argv[2] === 'static' || process.argv[2] === 'all'
  ? process.argv[2]
  : 'all';
const forwardedArgs = normalizeForwardedArgs(process.argv.slice(3));

let commands;
if (mode === 'static') {
  commands = suites.static;
} else if (mode === 'llm') {
  commands = suites.llm.map(command => [...command, ...forwardedArgs]);
} else {
  commands = [
    ...suites.static,
    ...suites.llm.map(command => [...command, ...forwardedArgs]),
  ];
}

for (const command of commands) {
  console.log(`\n> ${command.join(' ')}\n`);
  const result = spawnSync(command[0], command.slice(1), {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
