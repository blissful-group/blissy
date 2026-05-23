import typescript from "@blissy-auth/typescript-config/resolvers";
import pluginJs from "@eslint/js";
import { createTypeScriptImportResolver } from "eslint-import-resolver-typescript";
import importPlugin from "eslint-plugin-import";
import simpleImportSort from "eslint-plugin-simple-import-sort";
import sortDestructureKeys from "eslint-plugin-sort-destructure-keys";
import tseslint from "typescript-eslint";

import rules from "./rules.mjs";

/** @type {import('eslint').Linter.Config[]} */
export default [
  // Standard configuration
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,

  // Settings
  {
    settings: {
      "import/resolver": {
        typescript,
        node: true,
      },
      "import-x/resolver-next": [createTypeScriptImportResolver(typescript)],
    },
  },

  // Ignores
  { ignores: ["node_modules", "dist", "coverage"] },

  // Plugins
  {
    plugins: {
      "simple-import-sort": simpleImportSort,
    },
    rules: {
      "simple-import-sort/imports": "error",
      "simple-import-sort/exports": "error",
    },
  },
  {
    plugins: {
      "sort-destructure-keys": sortDestructureKeys,
    },
    rules: {
      "sort-destructure-keys/sort-destructure-keys": "error",
    },
  },

  // Rules
  ...rules,
];
