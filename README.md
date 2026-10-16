# Vault ACL Simulator

A [regex101](https://regex101.com)-style web tool for **HashiCorp Vault ACL policies**.

Live site: [jbdelavoix.github.io/vault-acl-simulator](https://jbdelavoix.github.io/vault-acl-simulator/)

- Edit HCL policies and get live **diagnostics** (syntax, invalid capabilities, forbidden `+*`, misplaced `*`, missing `sudo` on root-protected paths, etc.)
- Test Vault **paths / URLs** and see the winning rule plus granted capabilities
- Matching follows Vault rules: `*` (prefix, end of path only), `+` (one segment), deny by default, specificity priority
- **Policy generator** with secrets-engine presets (KV v1/v2, Database, PKI, Transit, …)
- Dark mode via `prefers-color-scheme`
- UI languages: English, French, Spanish, Italian, German

## Quick start

```bash
npm install
npm run dev
```

Production build:

```bash
npm run build
npm run preview
```

Engine / matching tests:

```bash
npm test
```

## Usage

1. Open the **Simulator** tab and paste a policy into **Policy HCL**
2. List paths to test (one per line), e.g. `secret/data/apps/foo` or `/v1/secret/data/apps/foo`
3. Check **Match results** (allow/deny + capabilities) and inline **diagnostics**
4. Optionally filter by capability (`read`, `list`, …) — the URL hash stays in sync for sharing (brotli-compressed `#s=…`)
5. Use the **Generator** tab to build path blocks from a secrets engine + access level
6. Open the **Docs** tab for matching rules, diagnostics, capabilities, and root-protected sys paths

## Project layout

| Path | Role |
|------|------|
| `src/` | Vite app (UI, ACL engine, i18n) |
| `src/engine/` | Parse, lint, match, highlight, generate |
| `src/i18n/` | Locale catalogs (`en`, `fr`, `es`, `it`, `de`) |
| `.github/workflows/` | CI + GitHub Pages deploy |

## Deployment

The site is published with **GitHub Pages** via `.github/workflows/pages.yml`:

- on every push / PR: `npm ci` → `npm test` → Pages build + portable zip → package zip/sha256
- on push to `main` / `master`: deploy `dist/` to GitHub Pages **and** create a GitHub Release tagged with the short commit SHA, attaching `vault-acl-simu-<sha>.zip` + `.sha256`
- PRs still upload the zip/checksum as a workflow artifact (no Release)

The top bar shows `package.json` version · git short SHA (links to the commit). On deployed builds, **zip** / **sha256** link to that Release’s assets for offline use.

Local package:

```bash
BASE_PATH=/ VITE_GIT_SHA=$(git rev-parse HEAD) npx vite build --outDir dist-portable
npm run package:release
```

In the GitHub repo settings, set **Pages → Source** to **GitHub Actions**.

## Notes

Default UI language follows the browser (`en` fallback). Choice is stored in `localStorage` under `vault-acl-lang`.
