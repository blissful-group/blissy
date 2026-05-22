import recommended from "@blissy/eslint-config/recommended";

/** @type {import('eslint').Linter.Config[]} */
export default [
  // Files
  { files: ["**/*.{js,mjs,cjs,ts,jsx,tsx}"] },

  // Config
  ...recommended,
];
