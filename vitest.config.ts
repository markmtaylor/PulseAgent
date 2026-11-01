import { defineConfig } from "vitest/config";

/**
 * Tests run against built output, imported by package name, so they exercise the
 * same entrypoints and the same `exports` maps that a consumer would. The root
 * `test` script builds first for that reason.
 *
 * Integration tests start a real chain and real child processes, so they are
 * slower and are given their own timeout. They are not mocked: the point of this
 * milestone is that settlement actually happened.
 */
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Integration tests bind loopback ports and spawn processes; running files
    // sequentially keeps port reservation and process accounting predictable.
    fileParallelism: false,
    reporters: ["default"],
  },
});
