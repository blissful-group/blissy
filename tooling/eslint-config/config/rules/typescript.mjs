/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ["**/*.ts", "**/*.tsx"],
    rules: {
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-namespace": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", vars: "all" },
      ],
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports" },
      ],
      "@typescript-eslint/no-import-type-side-effects": "error",
      "@typescript-eslint/naming-convention": [
        "error",
        {
          selector: "variableLike",
          format: ["camelCase", "PascalCase", "UPPER_CASE"],
          leadingUnderscore: "allow",
        },
        {
          selector: "variable",
          modifiers: ["destructured"],
          format: ["snake_case", "camelCase", "PascalCase", "UPPER_CASE"],
          leadingUnderscore: "allow",
        },
        {
          selector: "parameter",
          modifiers: ["destructured"],
          format: ["snake_case", "camelCase", "PascalCase", "UPPER_CASE"],
          leadingUnderscore: "allow",
        },
      ],
    },
  },
];
