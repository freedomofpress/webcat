import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  build: {
    outDir: "dist",
    target: "esnext",
    rollupOptions: {
      input: {
        main: "src/background.ts", // Your main TypeScript entry point
      },
      output: {
        entryFileNames: "bundle.js", // The name of the output file
        format: "iife", // Immediately Invoked Function Expression, ideal for standalone scripts
      },
    },
  },
  plugins: [
    viteSingleFile(),
    //webExtension()
  ],
});
