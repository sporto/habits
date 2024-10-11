import { defineConfig } from "vite";
import gleam from "vite-gleam";

export default defineConfig({
	root: ".",
	plugins: [gleam()],
	build: {
		assetsDir: "",
		emptyOutDir: true,
		manifest: false,
	},
	server: {
		host: true,
		origin: "http://127.0.0.1:8080",
		port: 8001,
		strictPort: true,
	},
});
