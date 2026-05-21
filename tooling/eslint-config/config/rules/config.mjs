/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ["**/*.config.*"],
    rules: {
      "@typescript-eslint/no-require-imports": "off",
    },
    languageOptions: {
      sourceType: "commonjs",
    },
  },
  {
    files: ["**/*.spec.*", "**/*.e2e.*", "**/test/**/*"],
    rules: {
      "no-empty-pattern": "off",
      "import/no-unresolved": "off",
      "@typescript-eslint/consistent-type-imports": "off",
    },
  },
];
