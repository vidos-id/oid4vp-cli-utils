import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [react(), tailwindcss()],
	resolve: {
		conditions: ["development"],
	},
	server: {
		port: 5174,
		proxy: {
			"/api": "http://localhost:3001",
			"/.well-known": "http://localhost:3001",
			"/token": "http://localhost:3001",
			"/nonce": "http://localhost:3001",
			"/credential": "http://localhost:3001",
			"/status-lists": "http://localhost:3001",
			"/api/auth": "http://localhost:3001",
		},
	},
});
