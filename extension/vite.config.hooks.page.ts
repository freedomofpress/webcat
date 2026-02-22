import { resolve } from "path";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist/hooks",
    emptyOutDir: false,
    minify: true,
    target: "esnext",

    rollupOptions: {
      input: {
        page: resolve(__dirname, "src/webcat/hooks/entry-page.ts"),
      },
      output: {
        format: "iife",
        entryFileNames: "[name].js",
        inlineDynamicImports: false,
      },
    },
  },
});
