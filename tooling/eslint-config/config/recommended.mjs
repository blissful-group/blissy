import eslintConfigPrettier from "eslint-config-prettier";
import eslintPluginPrettier from "eslint-plugin-prettier/recommended";
import globals from "globals";

import base from "./base.mjs";

/** @type {import('eslint').Linter.Config[]} */
export default [
  { languageOptions: { globals: globals.browser } },

  // Base configuration
  ...base,

  // Prettier configuration
  eslintConfigPrettier,
  eslintPluginPrettier,
];
