import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  build: {
    minify: false,
    outDir: "dist",
    target: "esnext",
    rollupOptions: {
      input: {
        main: "src/background.ts"
      },
      output: {
        entryFileNames: "bundle.js",
        format: "iife"
      },
    },
  },
  plugins: [
    viteSingleFile()
  ],
  test: {
    globals: true
  }
});
