import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    coverage: {
      enabled: true,
      exclude: ["**/*.!(helper|utils).ts"],
      reporter: [["text", { skipFull: false }], "json"],
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
});
