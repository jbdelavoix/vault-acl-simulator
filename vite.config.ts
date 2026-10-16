import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/** Project Pages need `/<repo>/`; local / preview / portable zip keep `/`. */
const base = process.env.BASE_PATH || "/";

const root = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  version: string;
};

function gitSha(): string {
  if (process.env.VITE_GIT_SHA?.trim()) return process.env.VITE_GIT_SHA.trim();
  try {
    return execSync("git rev-parse HEAD", { cwd: root, encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

const sha = gitSha();
const shortSha = sha === "unknown" ? "dev" : sha.slice(0, 7);
const githubRepo = process.env.VITE_GITHUB_REPOSITORY?.trim() || "";

export default defineConfig({
  root: ".",
  base,
  publicDir: "public",
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __GIT_SHA__: JSON.stringify(sha),
    __GIT_SHA_SHORT__: JSON.stringify(shortSha),
    __GITHUB_REPOSITORY__: JSON.stringify(githubRepo),
  },
  server: {
    port: 5173,
    open: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
