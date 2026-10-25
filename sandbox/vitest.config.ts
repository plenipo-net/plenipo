import { defineConfig } from 'vitest/config';

// The end-to-end suite is named *.e2e.ts so that the library's own `npm test` at the repository root,
// which picks up every *.test.ts, never runs it: the sandbox has its own `npm test`.
export default defineConfig({
  test: {
    include: ['test/**/*.e2e.ts'],
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
