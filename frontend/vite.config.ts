import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development, API calls are proxied to the PipelineGuard API on :8200.
const proxy = {
  "/api": "http://localhost:8200",
  "/health": "http://localhost:8200",
  "/openapi.json": "http://localhost:8200",
  "/docs": "http://localhost:8200",
};

export default defineConfig({
  plugins: [react()],
  preview: { port: 5175, proxy },
  server: {
    port: 5175,
    proxy: {
      "/api": "http://localhost:8200",
      "/health": "http://localhost:8200",
      "/openapi.json": "http://localhost:8200",
      "/docs": "http://localhost:8200",
    },
  },
});
