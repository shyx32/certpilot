import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: {
    // 开发时直连后端，生产由 web 容器的 nginx 反代。
    // 后端跑在别的端口时用 CP_API 覆盖，例如 CP_API=http://127.0.0.1:18080
    proxy: {
      "/api": process.env.CP_API ?? "http://localhost:8080",
      "/ws": {
        target: (process.env.CP_API ?? "http://localhost:8080").replace(/^http/, "ws"),
        ws: true,
      },
    },
  },
});
