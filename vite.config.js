import { defineConfig } from "vite";
import gleam from "vite-gleam";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  root: ".",
  plugins: [gleam(), tailwindcss()],
  build: {
    assetsDir: "",
    emptyOutDir: true,
    manifest: true,
  },
  server: {
    host: true,
    origin: "http://127.0.0.1:8080",
    port: 8001,
    strictPort: true,
  },
});
