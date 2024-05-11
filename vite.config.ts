import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import basicSsl from "@vitejs/plugin-basic-ssl";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [preact(), basicSsl()],
  server: {
    proxy: {
      "/test": {
        target: "https://lh.xmit.dev:8443",
        secure: false,
        changeOrigin: true,
      },
    },
  },
});
