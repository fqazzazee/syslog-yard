import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // ws: true lets the /api/ws live tail flow through the dev proxy.
      "/api": { target: "http://localhost:8080", ws: true },
    },
  },
});
