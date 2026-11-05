import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // apps/shared/web imports react from outside this package's node_modules
  // tree; dedupe pins those imports to this app's copy.
  resolve: { dedupe: ["react", "react-dom"] },
  server: {
    // The shared components live in apps/shared/web, outside this root.
    fs: { allow: [".", "../../shared/web"] },
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
    },
  },
});
