import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The build goes straight into the VS Code extension's media folder.
// File names are fixed (no hashes) so the extension can reference them with
// asWebviewUri, and everything is one script + one stylesheet (no lazy chunks,
// no inline scripts) so it runs under the webview's strict CSP.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "../extension/media",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: false,
    // One local bundle (~650 KB, ~190 KB gzip) loaded from disk by the webview; splitting buys nothing here.
    chunkSizeWarningLimit: 800,
    rolldownOptions: {
      output: {
        entryFileNames: "assets/index.js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/[name][extname]",
      },
    },
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
