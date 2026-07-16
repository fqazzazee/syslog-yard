import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // apps/shared/web imports react from outside this package's node_modules
  // tree; dedupe pins those imports to this app's copy.
  resolve: { dedupe: ["react", "react-dom"] },
  server: {
    proxy: {
      // ws: true lets the /api/ws live tail flow through the dev proxy.
      "/api": { target: "http://localhost:8080", ws: true },
    },
  },
});
