import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default [
  {
    ...eslint.configs.recommended,
    languageOptions: {
      globals: {
        ...globals.browser,
      }
    }
  },
  ...tseslint.configs.recommended
];

