import path from "path";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const isTesting = process.env.TESTING === "true";

export default defineConfig({
  build: {
    minify: !isTesting,
    outDir: "dist",
    target: "esnext",
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
          "./webcat/db": path.resolve(__dirname, "./src/mocks/db.mock.ts"),
          "./validators": path.resolve(
            __dirname,
            "./src/mocks/validators.mock.ts",
          ),
          "./update": path.resolve(__dirname, "./src/mocks/update.mock.ts"),
        },
      }
    : {},
  plugins: [viteSingleFile()],
  test: {
    globals: true,
  },
});
