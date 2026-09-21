import { defineConfig } from "vite";

export default defineConfig({
  build: {
    minify: false,
    rollupOptions: {
      input: "background.js",
      output: { entryFileNames: "background.js", format: "iife" },
    },
  },
});
