import { defineConfig } from "vitest/config";

/** Project Pages need `/<repo>/`; local / preview keep `/`. */
const base = process.env.BASE_PATH || "/";

export default defineConfig({
  root: ".",
  base,
  publicDir: "public",
  server: {
    port: 5173,
    open: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
