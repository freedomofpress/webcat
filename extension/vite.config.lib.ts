import { globSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    minify: false,
    outDir: "dist/lib",
    target: "ES2020",
    ssr: true, // HACK: disable __vitePreload; see https://github.com/vitejs/vite/issues/4016
    rollupOptions: {
      preserveEntrySignatures: "strict",
      input: Object.fromEntries(
        globSync("src/*/**/*.ts")
          .filter((file) => !file.includes("/hooks/"))
          .filter((file) => !file.includes("/mocks/"))
          .concat("src/validator_set.json")
          .map((file) => [
            path.relative(
              "src",
              file.slice(0, file.length - path.extname(file).length),
            ),
            fileURLToPath(new URL(file, import.meta.url)),
          ]),
      ),
      output: {
        entryFileNames: "[name].js",
        format: "es",
      },
    },
  },
});
