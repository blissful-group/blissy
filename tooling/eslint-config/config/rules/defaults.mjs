/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    rules: {
      "no-undef": "off",
      eqeqeq: "error",
      "import/no-named-as-default-member": "off",
      "import/no-named-as-default": "off",
      "import/namespace": "off",
      "import/consistent-type-specifier-style": ["error", "prefer-top-level"],
      "no-useless-rename": "error",
      "no-useless-return": "error",
      "no-shadow": "error",
      "object-shorthand": "error",
      "no-console": [
        "warn",
        {
          allow: [
            "error",
            "info",
            "group",
            "groupCollapsed",
            "groupEnd",
            "table",
            "time",
            "timeEnd",
            "warn",
          ],
        },
      ],
    },
  },
];
