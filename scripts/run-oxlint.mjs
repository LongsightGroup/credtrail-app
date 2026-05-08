import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';

const lintRoots = ['apps', 'packages'];
const ignoredDirectories = new Set([
  '.astro',
  '.github',
  '.wrangler',
  'coverage',
  'dist',
  'node_modules',
]);

const lintFiles = [];

const collectTsFiles = (directory) => {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (ignoredDirectories.has(entry.name)) {
      continue;
    }

    const entryPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      collectTsFiles(entryPath);
      continue;
    }

    if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx'))) {
      lintFiles.push(entryPath);
    }
  }
};

for (const lintRoot of lintRoots) {
  if (existsSync(lintRoot)) {
    collectTsFiles(lintRoot);
  }
}

if (existsSync('vitest.config.ts')) {
  lintFiles.push('vitest.config.ts');
}

lintFiles.sort();

if (lintFiles.length === 0) {
  console.error('No TypeScript files found for oxlint.');
  process.exit(1);
}

const pnpmCommand = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
const result = spawnSync(
  pnpmCommand,
  ['exec', 'oxlint', ...process.argv.slice(2), ...lintFiles],
  {
    stdio: 'inherit',
  },
);

process.exit(result.status ?? 1);
