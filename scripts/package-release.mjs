#!/usr/bin/env node
/**
 * Zip a portable build (dist-portable/) into release/ and write a SHA-256 checksum.
 * Expects dist-portable/ (BASE_PATH=/) to already exist.
 */
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const portable = join(root, "dist-portable");
const outDir = join(root, "release");

function gitSha() {
  if (process.env.VITE_GIT_SHA?.trim()) return process.env.VITE_GIT_SHA.trim();
  try {
    return execSync("git rev-parse HEAD", { cwd: root, encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

if (!existsSync(portable)) {
  console.error("dist-portable/ missing — run a portable vite build first");
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });

const sha = gitSha();
const short = sha === "unknown" ? "dev" : sha.slice(0, 7);
const name = `vault-acl-simu-${short}`;
const zipPath = join(outDir, `${name}.zip`);
const sumPath = join(outDir, `${name}.zip.sha256`);

execSync(`zip -r -q ${JSON.stringify(zipPath)} .`, { cwd: portable, stdio: "inherit" });

const hash = createHash("sha256").update(readFileSync(zipPath)).digest("hex");
writeFileSync(sumPath, `${hash}  ${name}.zip\n`);

const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
writeFileSync(
  join(outDir, "version.json"),
  `${JSON.stringify({ version, sha, shortSha: short, tag: short, zip: `${name}.zip`, sha256: `${name}.zip.sha256` }, null, 2)}\n`,
);

console.log(`release: ${name}.zip`);
console.log(`sha256:  ${hash}`);
