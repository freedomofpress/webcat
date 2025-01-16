import { defineConfig } from "vite";

export default defineConfig({
  test: {
    environment: "jsdom",  // Use browser-like environment
  },
});
