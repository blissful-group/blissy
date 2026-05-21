import base from "./config/recommended.mjs";

/** @type {import('eslint').Linter.Config[]} */
export default [
  // Files
  { files: ["**/*.{js,mjs,cjs,ts,jsx,tsx}"] },

  // Config
  ...base,
];
