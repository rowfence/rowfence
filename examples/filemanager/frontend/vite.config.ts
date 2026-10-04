import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// npm run dev: the backend on :8000 answers /api
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://localhost:8000" } },
});
