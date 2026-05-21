import jsoncPlugin from "eslint-plugin-jsonc";
import jsoncParser from "jsonc-eslint-parser";

/** @type {import('eslint').Linter.Config[]} */
export default [
  // Rules
  {
    files: ["**/*.json"],
    ignores: ["**/.*.json"],
    languageOptions: {
      parser: jsoncParser,
    },
    plugins: {
      jsonc: jsoncPlugin,
    },
  },
  {
    files: ["**/*.json"],
    ignores: ["tsconfig.json", "tsconfig.*.json", "package.json", "**/.*.json"],
    languageOptions: {
      parser: jsoncParser,
    },
    plugins: {
      jsonc: jsoncPlugin,
    },
    rules: {
      "jsonc/sort-keys": "error",
    },
  },
];
