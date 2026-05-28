import recommended from "@blissy-auth/eslint-config/recommended";

/** @type {import('eslint').Linter.Config[]} */
export default [{ files: ["**/*.{js,mjs,cjs,ts,jsx,tsx}"] }, ...recommended];
