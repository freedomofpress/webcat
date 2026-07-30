import path from "path";
import { viteSingleFile } from "vite-plugin-singlefile";
import { defineConfig } from "vitest/config";

const isTesting = process.env.TESTING === "true";

export default defineConfig({
  build: {
    minify: !isTesting,
    outDir: "dist",
    emptyOutDir: false,
    target: "ES2020",
    rollupOptions: {
      input: {
        main: "src/background.ts", // Use regular background.ts
      },
      output: {
        entryFileNames: "bundle.js",
        format: "iife",
      },
    },
  },
  resolve: isTesting
    ? {
        alias: {
          "@freedomofpress/cometbft/dist/lightclient": path.resolve(
            __dirname,
            "./src/mocks/lightclient.mock.ts",
          ),
          "@freedomofpress/ics23/dist/webcat": path.resolve(
            __dirname,
            "./src/mocks/ics23.mock.ts",
          ),
        },
      }
    : {},
  define: {
    __IS_TESTING__: isTesting,
  },
  plugins: [viteSingleFile()],
  test: {
    globals: true,
  },
});
