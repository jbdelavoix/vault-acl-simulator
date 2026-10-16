import "./style.css";
import { parsePolicy } from "./engine/parse";
import { checkCapability, matchPaths } from "./engine/match";
import type { Capability, Diagnostic, PathMatchResult } from "./engine/types";
import {
  appendToPolicy,
  buildEngineRules,
  buildPolicyHcl,
  ENGINES,
  GENERATOR_CAPABILITIES,
  getEngine,
  getSysEndpoint,
  relevantCapabilitiesForGenerator,
  SYS_ENDPOINT_GROUPS,
  SYS_ENDPOINTS,
  type AccessLevel,
  type EngineId,
  type EngineKind,
  type ResourceMode,
} from "./engine/generate";
import {
  lineSeverities,
  marksFromDiagnostics,
  renderHighlightedSource,
} from "./engine/highlight";
import { decodeState, encodeState } from "./engine/urlState";
import {
  DOC_DIAG_RULES,
  DOC_MATCH_KEYS,
  KNOWN_ENDPOINT_CAPS,
  SYS_ROOT_PATHS,
  VALID_CAPABILITIES,
} from "./engine/docCatalog";
import { findSysEndpointForPath } from "./engine/lint";
import {
  DOC_OMITTED,
  DOC_SITE,
  getEngineDocMeta,
  sysEndpointDocUrl,
  vaultApiDocUrl,
} from "./engine/engineMeta";
import {
  initLocale,
  setLocale,
  getLocale,
  t,
  tp,
  LOCALES,
  type Locale,
} from "./i18n";

const DEFAULT_POLICY = `# Example — edit and watch matching live
path "secret/data/apps/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/apps/payments" {
  capabilities = ["deny"]
}

path "secret/data/+/config" {
  capabilities = ["read"]
}

path "secret/metadata/apps/*" {
  capabilities = ["list", "read"]
}

path "sys/health" {
  capabilities = ["read"]
}
`;

const DEFAULT_PATHS = `# One Vault path / URL per line
secret/data/apps/frontend
secret/data/apps/payments
secret/data/billing/config
secret/data/apps/frontend/db
/v1/secret/metadata/apps/frontend
sys/health
sys/mounts
`;

const CAP_FILTER_OPTIONS: Array<Capability | "any"> = [
  "any",
  "create",
  "read",
  "update",
  "patch",
  "delete",
  "list",
  "sudo",
];

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function badgeHtml(kind: string, label: string): string {
  return `<span class="doc-badge ${kind}">${escapeHtml(label)}</span>`;
}

function apiDocLink(url: string, label?: string): string {
  return `<a class="doc-ext-link" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
    label ?? t("doc.link"),
  )}</a>`;
}


/** Chips for Ent / Legacy / Deprecated / Beta / sudo. */
function renderFlagBadges(flags: {
  enterprise?: boolean;
  legacy?: boolean;
  deprecated?: boolean;
  beta?: boolean;
  root?: boolean;
  minVersion?: string;
}): string {
  const badges: string[] = [];
  if (flags.enterprise) badges.push(badgeHtml("ent", t("doc.badge.ent")));
  if (flags.legacy) badges.push(badgeHtml("legacy", t("doc.badge.legacy")));
  if (flags.deprecated) badges.push(badgeHtml("dep", t("doc.badge.deprecated")));
  if (flags.beta) badges.push(badgeHtml("beta", t("doc.badge.beta")));
  if (flags.root) badges.push(badgeHtml("sudo", t("doc.badge.sudo")));
  if (flags.minVersion)
    badges.push(badgeHtml("min", t("doc.badge.min", { v: flags.minVersion })));
  return badges.length ? `<div class="doc-badges">${badges.join("")}</div>` : "";
}

function i18nKey(key: string): string {
  const value = t(key);
  return value === key ? "" : value;
}

function engineNotesHtml(engineId: EngineId): string {
  // Sys uses the per-endpoint doc under the endpoint select — skip generic notes.
  if (engineId === "sys") return "";

  const items: string[] = [];
  const meta = getEngineDocMeta(engineId);
  if (meta) {
    const role = i18nKey(meta.roleKey);
    if (role) items.push(role);
    for (const noteKey of meta.notes ?? []) {
      const n = i18nKey(noteKey);
      if (n) items.push(n);
    }
  }
  for (const i of [0, 1, 2]) {
    const n = i18nKey(`engine.${engineId}.note${i}`);
    if (n) items.push(n);
  }
  const seen = new Set<string>();
  return items
    .filter((n) => {
      if (seen.has(n)) return false;
      seen.add(n);
      return true;
    })
    .map((n) => `<li>${escapeHtml(n)}</li>`)
    .join("");
}

function formatExplanation(r: PathMatchResult): string {
  if (r.explanation === "none") return t("match.none");
  const rule = r.winningRule;
  const path = rule?.path ?? "";
  const line = rule?.line ?? "";
  if (r.explanation === "deny") return t("match.deny", { path, line });
  const caps = r.capabilities.filter((c) => c !== "deny").join(", ");
  return t("match.allow", { path, line, caps });
}

function formatHelpText(text: string): string {
  return text
    .replace(/\*/g, "<code>*</code>")
    .replace(/\+/g, "<code>+</code>")
    .replace(/data\//g, "<code>data/</code>")
    .replace(/metadata\//g, "<code>metadata/</code>");
}

function applyStaticI18n(root: ParentNode = document): void {
  root.querySelectorAll<HTMLElement>("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n!;
    if (el instanceof HTMLOptionElement) el.label = t(key);
    el.textContent = t(key);
  });
  root.querySelectorAll<HTMLInputElement>("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder!);
  });
  root.querySelectorAll<HTMLElement>("[data-i18n-aria]").forEach((el) => {
    el.setAttribute("aria-label", t(el.dataset.i18nAria!));
  });
}

function syncEditorChrome(
  textarea: HTMLTextAreaElement,
  gutter: HTMLElement,
  backdrop: HTMLElement,
  diags: Diagnostic[],
) {
  const source = textarea.value;
  const sev = lineSeverities(diags);
  const lineCount = source.split("\n").length;
  gutter.innerHTML = Array.from({ length: lineCount }, (_, i) => {
    const n = i + 1;
    const s = sev.get(n);
    return `<span class="ln${s ? ` ${s}` : ""}">${n}</span>`;
  }).join("\n");

  backdrop.innerHTML = renderHighlightedSource(
    source,
    marksFromDiagnostics(source, diags, (d) => t(`diag.${d.code}`, d.params)),
  );
  gutter.scrollTop = textarea.scrollTop;
  backdrop.scrollTop = textarea.scrollTop;
  backdrop.scrollLeft = textarea.scrollLeft;
}

function renderDiagnostics(diags: Diagnostic[]): string {
  if (diags.length === 0) {
    return `<div class="empty">${escapeHtml(t("diag.empty"))}</div>`;
  }
  const order = { error: 0, warning: 1, info: 2 } as const;
  const sorted = [...diags].sort(
    (a, b) =>
      order[a.severity] - order[b.severity] ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.code.localeCompare(b.code),
  );
  return sorted
    .map(
      (d) => `
      <div class="diag ${d.severity}" data-line="${d.line ?? ""}" title="${escapeHtml(t("diag.goto"))}">
        <div class="sev">${d.severity}</div>
        <div>${escapeHtml(t(`diag.${d.code}`, d.params))}</div>
        <div class="loc">${d.line ? `L${d.line}` : ""}${d.path ? ` · ${escapeHtml(d.path)}` : ""}</div>
      </div>`,
    )
    .join("");
}

function renderResults(
  results: PathMatchResult[],
  filterCap: Capability | "any",
): string {
  if (results.length === 0) {
    return `<div class="empty">${escapeHtml(t("result.empty"))}</div>`;
  }

  return results
    .map((r) => {
      const status = r.denied ? "deny" : "allow";
      const capsHtml = (VALID_CAPABILITIES.filter((c) => c !== "deny") as Capability[])
        .map((c) => {
          const has = r.capabilities.includes(c);
          return `<span class="${has ? "hit" : "miss"}">${c}</span>`;
        })
        .join("");

      const candidates =
        r.candidates.length > 0
          ? `<div class="candidates">${escapeHtml(t("result.candidates"))}
              ${r.candidates
                .map((c) => {
                  const isWin = r.winningRule?.path === c.rule.path;
                  const label = c.rule.path;
                  return isWin
                    ? `<strong>${escapeHtml(label)}</strong>`
                    : escapeHtml(label);
                })
                .join(" · ")}
            </div>`
          : "";

      const filterNote =
        filterCap !== "any"
          ? `<div class="explanation">${
              filterCap === "deny"
                ? r.denied
                  ? escapeHtml(t("result.deny_ok"))
                  : escapeHtml(t("result.deny_no"))
                : checkCapability(r, filterCap)
                  ? escapeHtml(t("result.cap_ok", { cap: filterCap }))
                  : escapeHtml(t("result.cap_no", { cap: filterCap }))
            }</div>`
          : "";

      const catalog = findSysEndpointForPath(r.requestPath);
      const pathFlags = catalog
        ? renderFlagBadges({
            enterprise: catalog.enterprise,
            legacy: catalog.legacy,
            deprecated: catalog.deprecated,
            beta: catalog.beta,
            root: catalog.root,
          })
        : "";

      return `
        <article class="result-card ${status}">
          <div class="result-top">
            <div class="result-path">${escapeHtml(r.requestPath)}${pathFlags}</div>
            <span class="badge ${status}">${escapeHtml(t(status === "allow" ? "result.allow" : "result.deny"))}</span>
          </div>
          <div class="caps">${r.denied ? `<span class="deny-cap">deny</span>` : capsHtml}</div>
          <div class="explanation">${escapeHtml(formatExplanation(r))}</div>
          ${filterNote}
          ${candidates}
        </article>`;
    })
    .join("");
}

const EXAMPLES: Record<string, { policy: string; paths: string }> = {
  kv2: {
    policy: DEFAULT_POLICY,
    paths: DEFAULT_PATHS,
  },
  deny: {
    policy: `# Deny wins over broader allow
path "secret/data/apps/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/apps/payments" {
  capabilities = ["deny"]
}

path "secret/data/apps/payments/public" {
  capabilities = ["read"]
}
`,
    paths: `secret/data/apps/frontend
secret/data/apps/payments
secret/data/apps/payments/public
secret/data/other
`,
  },
  sudo: {
    policy: `# Root-protected paths need sudo
path "sys/rotate" {
  capabilities = ["update"]
}

path "sys/seal" {
  capabilities = ["update", "sudo"]
}

path "sys/auth/*" {
  capabilities = ["create", "update", "delete"]
}

path "sys/policies/acl/*" {
  capabilities = ["read", "update"]
}
`,
    paths: `sys/rotate
sys/seal
sys/auth/approle
sys/policies/acl/my-policy
`,
  },
  approle: {
    policy: `# AppRole — login vs role admin
path "auth/approle/login" {
  capabilities = ["create", "update"]
}

path "auth/approle/role" {
  capabilities = ["list"]
}

path "auth/approle/role/my-app" {
  capabilities = ["read"]
}

path "auth/approle/role/my-app/*" {
  capabilities = ["read"]
}

path "auth/approle/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`,
    paths: `auth/approle/login
auth/approle/role
auth/approle/role/my-app
auth/approle/role/my-app/secret-id
auth/approle/role/other-app
`,
  },
  database: {
    policy: `# Database dynamic + static roles
path "database/creds/readonly" {
  capabilities = ["read"]
}

path "database/static-creds/app-user" {
  capabilities = ["read"]
}

path "database/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/config/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/creds/*" {
  capabilities = ["deny"]
}
`,
    paths: `database/creds/readonly
database/creds/admin
database/static-creds/app-user
database/roles/readonly
database/config/my-db
`,
  },
  transit: {
    policy: `# Transit encrypt/decrypt (not key admin)
path "transit/encrypt/payments" {
  capabilities = ["update"]
}

path "transit/decrypt/payments" {
  capabilities = ["update"]
}

path "transit/datakey/plaintext/payments" {
  capabilities = ["update"]
}

path "transit/keys/*" {
  capabilities = ["deny"]
}

path "transit/keys" {
  capabilities = ["list"]
}
`,
    paths: `transit/encrypt/payments
transit/decrypt/payments
transit/datakey/plaintext/payments
transit/keys/payments
transit/keys
transit/encrypt/other
`,
  },
  admin: {
    policy: `# Admin-ish sample
path "sys/policies/acl" {
  capabilities = ["list"]
}

path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "sys/auth/*" {
  capabilities = ["create", "update", "delete", "sudo"]
}

path "sys/auth" {
  capabilities = ["read"]
}

path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
`,
    paths: `sys/policies/acl
sys/policies/acl/my-policy
auth/userpass/users/bob
sys/auth/userpass
secret/hello
`,
  },
  wildcards: {
    policy: `path "secret/+/teamb" {
  capabilities = ["read"]
}

path "secret/+/+/teamb" {
  capabilities = ["read", "list"]
}

path "secret/foo*" {
  capabilities = ["list"]
}

path "secret/foobar" {
  capabilities = ["deny"]
}
`,
    paths: `secret/eng/teamb
secret/eng/ops/teamb
secret/foo
secret/foobar
secret/foobarbaz
`,
  },
  legacy: {
    policy: `# Legacy ACL API (prefer sys/policies/acl)
path "sys/policy" {
  capabilities = ["list"]
}

path "sys/policy/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "sys/policies/acl/*" {
  capabilities = ["read"]
}
`,
    paths: `sys/policy
sys/policy/old-policy
sys/policies/acl/new-policy
`,
  },
};

async function mount() {
  initLocale();

  const buildShaShort = __GIT_SHA_SHORT__;
  const buildSha = __GIT_SHA__;
  const buildVersion = __APP_VERSION__;
  const buildRepo = __GITHUB_REPOSITORY__;
  const buildCommitHref = buildRepo && buildSha !== "unknown"
    ? `https://github.com/${buildRepo}/commit/${buildSha}`
    : "";
  // Offline zip is published as a GitHub Release asset (tag = short SHA).
  const releaseTag = buildShaShort;
  const zipName = `vault-acl-simu-${buildShaShort}.zip`;
  const shaName = `${zipName}.sha256`;
  const releaseBase =
    buildRepo && buildSha !== "unknown"
      ? `https://github.com/${buildRepo}/releases/download/${releaseTag}`
      : "";
  const zipHref = releaseBase ? `${releaseBase}/${zipName}` : "";
  const shaHref = releaseBase ? `${releaseBase}/${shaName}` : "";
  const showDownloads = Boolean(releaseBase);

  const app = document.querySelector<HTMLDivElement>("#app")!;
  app.innerHTML = `
    <header class="topbar">
      <div class="brand">
        <div class="brand-text">
          <h1>Vault ACL Simulator</h1>
          <span data-i18n="app.tagline"></span>
        </div>
        <div class="build-meta" title="${escapeHtml(buildSha)}">
          ${
            buildCommitHref
              ? `<a class="build-sha" href="${escapeHtml(buildCommitHref)}" target="_blank" rel="noopener noreferrer">${escapeHtml(buildVersion)} · ${escapeHtml(buildShaShort)}</a>`
              : `<span class="build-sha">${escapeHtml(buildVersion)} · ${escapeHtml(buildShaShort)}</span>`
          }
          ${
            showDownloads
              ? `<span class="build-sep" aria-hidden="true">·</span>
                 <a class="build-dl" href="${escapeHtml(zipHref)}" data-i18n="app.downloadZip">zip</a>
                 <span class="build-sep" aria-hidden="true">·</span>
                 <a class="build-dl" href="${escapeHtml(shaHref)}" data-i18n="app.downloadSha">sha256</a>`
              : ""
          }
        </div>
      </div>
      <nav class="tabs" role="tablist" aria-label="Navigation">
        <button type="button" class="tab active" role="tab" aria-selected="true" data-tab="sim" data-i18n="tab.sim"></button>
        <button type="button" class="tab" role="tab" aria-selected="false" data-tab="gen" data-i18n="tab.gen"></button>
        <button type="button" class="tab" role="tab" aria-selected="false" data-tab="doc" data-i18n="tab.doc"></button>
      </nav>
      <div class="top-actions">
        <label class="inline-field" id="sim-actions">
          <span class="sr-only" data-i18n="ex.label"></span>
          <select id="ex-select" class="select-like compact-select">
            <option value="" data-i18n="ex.label"></option>
            <option value="kv2" data-i18n="ex.kv"></option>
            <option value="deny" data-i18n="ex.deny"></option>
            <option value="sudo" data-i18n="ex.sudo"></option>
            <option value="approle" data-i18n="ex.approle"></option>
            <option value="database" data-i18n="ex.database"></option>
            <option value="transit" data-i18n="ex.transit"></option>
            <option value="admin" data-i18n="ex.admin"></option>
            <option value="wildcards" data-i18n="ex.wildcards"></option>
            <option value="legacy" data-i18n="ex.legacy"></option>
          </select>
        </label>
        <button type="button" class="primary" id="share-btn" data-i18n="share"></button>
        <label class="inline-field">
          <span class="sr-only" data-i18n="lang.label"></span>
          <select id="lang-select" class="select-like compact-select" aria-labelledby="lang-label"></select>
        </label>
      </div>
    </header>

    <section id="tab-sim" class="tab-panel active">
      <p class="help-hint" id="sim-help"></p>
      <main class="layout">
        <div class="left-stack">
          <section class="panel policy-panel">
            <div class="panel-header">
              <h2 data-i18n="policy.title"></h2>
              <div class="meta" id="policy-meta"></div>
            </div>
            <div class="editor-wrap">
              <div class="line-numbers" id="policy-lines"></div>
              <div class="editor-stack">
                <pre class="editor-backdrop" id="policy-backdrop" aria-hidden="true"></pre>
                <textarea class="editor" id="policy" spellcheck="false" data-i18n-aria="policy.title"></textarea>
              </div>
            </div>
            <div class="policy-inline-diags">
              <div class="diag-list" id="diagnostics"></div>
            </div>
          </section>
        </div>
        <div class="right-stack">
          <section class="panel paths-panel">
            <div class="panel-header">
              <h2 data-i18n="paths.title"></h2>
              <div class="meta" id="paths-meta"></div>
              <label class="inline-field cap-filter">
                <span class="sr-only" data-i18n="filter.cap"></span>
                <select id="cap-filter" class="select-like compact-select"></select>
              </label>
            </div>
            <textarea class="editor" id="paths" spellcheck="false" data-i18n-aria="paths.title"></textarea>
          </section>
          <section class="panel results-panel">
            <div class="panel-header">
              <h2 data-i18n="results.title"></h2>
            </div>
            <div class="results" id="results"></div>
          </section>
        </div>
      </main>
    </section>

    <section id="tab-gen" class="tab-panel" hidden>
      <p class="help-hint" id="gen-help"></p>
      <div class="gen-layout">
        <section class="panel">
          <div class="panel-header">
            <h2 data-i18n="gen.engine"></h2>
            <div class="meta" data-i18n="gen.required"></div>
          </div>
          <div class="generator-body">
            <div class="gen-form">
              <div class="gen-field">
                <span class="gen-field-label" id="gen-engine-label" data-i18n="gen.engine"></span>
                <div class="gen-picker" id="gen-engine"></div>
                <p class="gen-field-desc" id="gen-engine-desc"></p>
              </div>
              <div class="gen-field" id="sys-endpoint-wrap" hidden>
                <span class="gen-field-label" id="gen-sys-endpoint-label" data-i18n="gen.sysEndpoint"></span>
                <div class="gen-picker" id="gen-sys-endpoint"></div>
                <p class="gen-field-desc" id="gen-sys-desc"></p>
              </div>
              <div class="gen-row" id="gen-target-row">
                <div class="gen-field" id="gen-target-wrap">
                  <span class="gen-field-label" id="gen-target-label" data-i18n="gen.target"></span>
                  <div class="seg" id="gen-target" role="radiogroup" aria-labelledby="gen-target-label"></div>
                  <p class="gen-field-desc" id="gen-target-desc"></p>
                </div>
                <div class="gen-field" id="gen-secret-wrap">
                  <label for="gen-secret" id="gen-secret-label"></label>
                  <input type="text" id="gen-secret" autocomplete="off" spellcheck="false" />
                </div>
              </div>
              <div class="gen-row">
                <div class="gen-field" id="gen-mount-wrap">
                  <label for="gen-mount" data-i18n="gen.mount"></label>
                  <input type="text" id="gen-mount" autocomplete="off" spellcheck="false" />
                </div>
                <div class="gen-field" id="gen-scope-wrap">
                  <span class="gen-field-label" id="gen-scope-label" data-i18n="gen.scope"></span>
                  <div class="seg" id="gen-scope" role="radiogroup" aria-labelledby="gen-scope-label"></div>
                  <p class="gen-field-desc" id="gen-scope-desc"></p>
                </div>
              </div>
              <div class="gen-field">
                <span class="gen-field-label" id="gen-access-label" data-i18n="gen.access"></span>
                <div class="seg" id="gen-access" role="radiogroup" aria-labelledby="gen-access-label"></div>
                <p class="gen-field-desc" id="gen-access-desc"></p>
              </div>
              <div class="gen-field" id="custom-caps-wrap" hidden>
                <label data-i18n="gen.caps"></label>
                <div class="cap-checks" id="gen-caps"></div>
              </div>
            </div>
            <ul class="engine-notes" id="engine-notes"></ul>
          </div>
        </section>
        <section class="panel">
          <div class="panel-header">
            <h2 data-i18n="gen.preview"></h2>
            <div class="meta" id="gen-meta"></div>
          </div>
          <div class="generator-body">
            <pre class="gen-preview" id="gen-preview" aria-live="polite"></pre>
            <p class="gen-hint" id="gen-hint"></p>
            <div class="gen-actions">
              <button type="button" class="primary" id="gen-append" data-i18n="gen.append"></button>
              <button type="button" id="gen-replace" data-i18n="gen.replace"></button>
              <button type="button" id="gen-goto-sim" data-i18n="gen.goto"></button>
            </div>
          </div>
        </section>
      </div>
    </section>

    <section id="tab-doc" class="tab-panel" hidden>
      <p class="help-hint" id="doc-help"></p>
      <div class="doc-layout" id="doc-body"></div>
    </section>
  `;

  const policyEl = app.querySelector<HTMLTextAreaElement>("#policy")!;
  const pathsEl = app.querySelector<HTMLTextAreaElement>("#paths")!;
  const linesEl = app.querySelector<HTMLElement>("#policy-lines")!;
  const backdropEl = app.querySelector<HTMLElement>("#policy-backdrop")!;
  const resultsEl = app.querySelector<HTMLElement>("#results")!;
  const diagEl = app.querySelector<HTMLElement>("#diagnostics")!;
  const policyMeta = app.querySelector<HTMLElement>("#policy-meta")!;
  const pathsMeta = app.querySelector<HTMLElement>("#paths-meta")!;
  const capFilter = app.querySelector<HTMLSelectElement>("#cap-filter")!;
  const simActions = app.querySelector<HTMLElement>("#sim-actions")!;
  const langSelect = app.querySelector<HTMLSelectElement>("#lang-select")!;
  const exSelect = app.querySelector<HTMLSelectElement>("#ex-select")!;
  const simHelp = app.querySelector<HTMLElement>("#sim-help")!;
  const genHelpHint = app.querySelector<HTMLElement>("#gen-help")!;
  const docHelp = app.querySelector<HTMLElement>("#doc-help")!;
  const docBody = app.querySelector<HTMLElement>("#doc-body")!;
  const genEngine = app.querySelector<HTMLElement>("#gen-engine")!;
  const genEngineDesc = app.querySelector<HTMLElement>("#gen-engine-desc")!;
  const genSysDesc = app.querySelector<HTMLElement>("#gen-sys-desc")!;
  const genScopeDesc = app.querySelector<HTMLElement>("#gen-scope-desc")!;
  const genAccessDesc = app.querySelector<HTMLElement>("#gen-access-desc")!;
  const genTargetDesc = app.querySelector<HTMLElement>("#gen-target-desc")!;
  const genTargetLabel = app.querySelector<HTMLElement>("#gen-target-label")!;
  const genTargetWrap = app.querySelector<HTMLElement>("#gen-target-wrap")!;
  const genMountWrap = app.querySelector<HTMLElement>("#gen-mount-wrap")!;
  const genSecretWrap = app.querySelector<HTMLElement>("#gen-secret-wrap")!;
  const genScopeWrap = app.querySelector<HTMLElement>("#gen-scope-wrap")!;
  const sysEndpointWrap = app.querySelector<HTMLElement>("#sys-endpoint-wrap")!;
  const genSysEndpoint = app.querySelector<HTMLElement>("#gen-sys-endpoint")!;
  const genMount = app.querySelector<HTMLInputElement>("#gen-mount")!;
  const genSecret = app.querySelector<HTMLInputElement>("#gen-secret")!;
  const genSecretLabel = app.querySelector<HTMLElement>("#gen-secret-label")!;
  const genTarget = app.querySelector<HTMLElement>("#gen-target")!;
  const genScope = app.querySelector<HTMLElement>("#gen-scope")!;
  const genAccess = app.querySelector<HTMLElement>("#gen-access")!;
  const genCaps = app.querySelector<HTMLElement>("#gen-caps")!;
  const customCapsWrap = app.querySelector<HTMLElement>("#custom-caps-wrap")!;
  const genPreview = app.querySelector<HTMLElement>("#gen-preview")!;
  const genHint = app.querySelector<HTMLElement>("#gen-hint")!;
  const genMeta = app.querySelector<HTMLElement>("#gen-meta")!;
  const engineNotes = app.querySelector<HTMLElement>("#engine-notes")!;
  const genAppend = app.querySelector<HTMLButtonElement>("#gen-append")!;
  const genReplace = app.querySelector<HTMLButtonElement>("#gen-replace")!;
  const genGotoSim = app.querySelector<HTMLButtonElement>("#gen-goto-sim")!;

  let filterCap: Capability | "any" = "any";
  let engineId: EngineId = "kv2";
  let sysEndpointIds = new Set<string>(["policies-acl-name"]);
  let access: AccessLevel = "read";
  let scope: "exact" | "prefix" = "prefix";
  let resourceMode: ResourceMode = "named";

  const KIND_ORDER: EngineKind[] = ["secrets", "auth", "system", "other"];

  type PickerOption = {
    value: string;
    title: string;
    hint?: string;
    badges?: string;
  };

  type PickerGroup = { label: string; options: PickerOption[] };

  function closePicker(el: HTMLElement) {
    const trigger = el.querySelector<HTMLButtonElement>(".gen-picker-trigger");
    const panel = el.querySelector<HTMLElement>(".gen-picker-panel");
    if (!trigger || !panel) return;
    trigger.setAttribute("aria-expanded", "false");
    panel.hidden = true;
    el.classList.remove("open");
    if (el === genSysEndpoint) hideSysTip();
  }

  function closeAllPickers(except?: HTMLElement) {
    for (const el of [genEngine, genSysEndpoint]) {
      if (el !== except) closePicker(el);
    }
  }

  function openPicker(el: HTMLElement) {
    closeAllPickers(el);
    const trigger = el.querySelector<HTMLButtonElement>(".gen-picker-trigger");
    const panel = el.querySelector<HTMLElement>(".gen-picker-panel");
    if (!trigger || !panel) return;
    trigger.setAttribute("aria-expanded", "true");
    panel.hidden = false;
    el.classList.add("open");
    panel.querySelector<HTMLElement>(".gen-picker-option.active")?.scrollIntoView({ block: "nearest" });
  }

  function renderPicker(
    el: HTMLElement,
    groups: PickerGroup[],
    selected: string,
    labelledBy: string,
  ) {
    const flat = groups.flatMap((g) => g.options);
    const current = flat.find((o) => o.value === selected) ?? flat[0];
    const triggerHtml = `
      <button type="button" class="gen-picker-trigger" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="${escapeHtml(
        labelledBy,
      )}">
        <span class="gen-picker-trigger-body">
          <span class="gen-picker-trigger-title">${escapeHtml(current?.title ?? "")}</span>
          ${current?.badges ?? ""}
        </span>
        <span class="gen-picker-chevron" aria-hidden="true"></span>
      </button>`;
    const panelHtml = `
      <div class="gen-picker-panel" role="listbox" hidden>
        ${groups
          .map(
            (g) => `
          <div class="gen-picker-group" role="group" aria-label="${escapeHtml(g.label)}">
            <div class="gen-picker-group-label">${escapeHtml(g.label)}</div>
            ${g.options
              .map(
                (o) => `
              <button type="button" class="gen-picker-option${o.value === selected ? " active" : ""}" role="option" aria-selected="${
                o.value === selected
              }" data-value="${escapeHtml(o.value)}">
                <span class="gen-picker-option-main">
                  <span class="gen-picker-option-title">${escapeHtml(o.title)}</span>
                  ${o.badges ?? ""}
                </span>
                ${o.hint ? `<span class="gen-picker-option-hint">${escapeHtml(o.hint)}</span>` : ""}
              </button>`,
              )
              .join("")}
          </div>`,
          )
          .join("")}
      </div>`;
    el.innerHTML = triggerHtml + panelHtml;
  }

  function renderSeg(
    el: HTMLElement,
    options: Array<{ value: string; label: string }>,
    selected: string,
  ) {
    el.innerHTML = options
      .map(
        (o) =>
          `<button type="button" class="seg-btn${o.value === selected ? " active" : ""}" role="radio" aria-checked="${
            o.value === selected
          }" data-value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</button>`,
      )
      .join("");
  }

  function resourceKind() {
    return getEngine(engineId).resourceKind;
  }

  function renderTargetSelect() {
    const kind = resourceKind();
    const hide = kind === "none";
    genTargetWrap.hidden = hide;
    if (hide) {
      resourceMode = "named";
      return;
    }
    const allKey = `gen.target.${kind}.all`;
    const namedKey = `gen.target.${kind}.named`;
    const allLabel = t(allKey) === allKey ? t("gen.target.all") : t(allKey);
    const namedLabel = t(namedKey) === namedKey ? t("gen.target.named") : t(namedKey);
    genTargetLabel.textContent = t("gen.target");
    renderSeg(
      genTarget,
      [
        { value: "all", label: allLabel },
        { value: "named", label: namedLabel },
      ],
      resourceMode,
    );
    genTargetDesc.textContent =
      resourceMode === "all" ? t("gen.target.all.desc") : t("gen.target.named.desc");
  }

  function selectedSysIds(): string[] {
    return SYS_ENDPOINTS.map((e) => e.id).filter((id) => sysEndpointIds.has(id));
  }

  function sysIncludesCustom(): boolean {
    return sysEndpointIds.has("custom");
  }

  function syncSecretVisibility() {
    const kind = resourceKind();
    const isSys = engineId === "sys";
    const sysCustom = isSys && sysIncludesCustom();
    // Scope only matters for free-form paths (engines + sys custom)
    genScopeWrap.hidden = isSys && !sysCustom;
    if (isSys) {
      genSecretWrap.hidden = !sysCustom;
      return;
    }
    if (kind === "none") {
      genSecretWrap.hidden = true;
      return;
    }
    genSecretWrap.hidden = resourceMode === "all";
  }

  function renderLangSwitcher() {
    langSelect.innerHTML = LOCALES.map(
      (loc) =>
        `<option value="${loc.id}"${loc.id === getLocale() ? " selected" : ""}>${escapeHtml(loc.label)}</option>`,
    ).join("");
  }

  function sysEpHelpHtml(ep: ReturnType<typeof getSysEndpoint>): string {
    const capsMeta =
      ep.id === "custom"
        ? ""
        : `<span class="sys-doc-meta">${escapeHtml(
            t("sys.ep.caps", { caps: (access === "read" ? ep.read : ep.write).join(", ") }),
          )}</span>`;
    const doc = ep.doc?.trim() || (ep.id === "custom" ? t("sys.ep.custom.desc") : "");
    const badges =
      ep.id === "custom"
        ? ""
        : renderFlagBadges({
            enterprise: ep.enterprise,
            legacy: ep.legacy,
            deprecated: ep.deprecated,
            beta: ep.beta,
            root: ep.root,
          });
    const url = sysEndpointDocUrl(ep.id);
    const link = url ? `<div class="sys-doc-link">${apiDocLink(url)}</div>` : "";
    const pathLabel =
      ep.id === "custom" ? t("sys.group.custom") : ep.path;
    return `<div class="sys-help-head"><code>${escapeHtml(pathLabel)}</code>${badges}</div>${
      doc ? `<span class="sys-doc">${escapeHtml(doc)}</span>` : ""
    }${link}${capsMeta}`;
  }

  function updateSysDesc() {
    const ids = selectedSysIds();
    if (ids.length === 0) {
      genSysDesc.innerHTML = `<span class="sys-doc">${escapeHtml(t("gen.sys.hoverHint"))}</span>`;
      return;
    }
    if (ids.length === 1) {
      genSysDesc.innerHTML = sysEpHelpHtml(getSysEndpoint(ids[0]));
      return;
    }
    const list = ids
      .map((id) => {
        const ep = getSysEndpoint(id);
        const label = ep.id === "custom" ? t("sys.group.custom") : ep.path;
        return `<li><code>${escapeHtml(label)}</code></li>`;
      })
      .join("");
    genSysDesc.innerHTML = `<span class="sys-doc">${escapeHtml(
      tp("gen.sys.n", ids.length),
    )}</span><ul class="sys-selected-list">${list}</ul>`;
  }

  const sysTip = document.createElement("div");
  sysTip.className = "gen-sys-tip";
  sysTip.hidden = true;
  document.body.appendChild(sysTip);

  let sysTipAnchor: HTMLElement | null = null;

  function hideSysTip() {
    sysTipAnchor = null;
    sysTip.hidden = true;
    sysTip.innerHTML = "";
  }

  function positionSysTip(anchor: HTMLElement) {
    const rect = anchor.getBoundingClientRect();
    const tipW = Math.min(352, window.innerWidth - 16);
    let left = rect.right + 10;
    if (left + tipW > window.innerWidth - 8) {
      left = Math.max(8, rect.left - tipW - 10);
    }
    sysTip.style.width = `${tipW}px`;
    const tipH = Math.min(sysTip.scrollHeight || 120, window.innerHeight * 0.55);
    let top = rect.top;
    if (top + tipH > window.innerHeight - 8) {
      top = Math.max(8, window.innerHeight - tipH - 8);
    }
    sysTip.style.top = `${top}px`;
    sysTip.style.left = `${left}px`;
  }

  function showSysTip(id: string, anchor: HTMLElement) {
    sysTipAnchor = anchor;
    sysTip.innerHTML = sysEpHelpHtml(getSysEndpoint(id));
    sysTip.hidden = false;
    positionSysTip(anchor);
  }

  // Delegated once — survives panel re-renders; tip is fixed on body (not clipped).
  // Do not hide on panel scroll: browsers/hover often fire scrollIntoView and that
  // used to clear the tip immediately. Reposition instead while still hovering.
  genSysEndpoint.addEventListener("pointerover", (e) => {
    if (!genSysEndpoint.classList.contains("open")) return;
    const opt = (e.target as HTMLElement).closest<HTMLElement>(".gen-picker-option");
    if (!opt?.dataset.value || !genSysEndpoint.contains(opt)) return;
    showSysTip(opt.dataset.value, opt);
  });
  genSysEndpoint.addEventListener("pointerleave", hideSysTip);
  genSysEndpoint.addEventListener(
    "scroll",
    (e) => {
      if (!(e.target as HTMLElement).classList?.contains("gen-picker-panel")) return;
      if (sysTipAnchor?.isConnected && sysTipAnchor.dataset.value) {
        positionSysTip(sysTipAnchor);
      }
    },
    true,
  );

  function sysTriggerLabel(): string {
    const ids = selectedSysIds();
    if (ids.length === 0) return t("gen.sys.none");
    if (ids.length === 1) {
      const ep = getSysEndpoint(ids[0]);
      return ep.id === "custom" ? t("sys.group.custom") : ep.path;
    }
    return tp("gen.sys.n", ids.length);
  }

  function renderSysEndpointSelect() {
    const wasOpen = genSysEndpoint.classList.contains("open");
    const scroll = genSysEndpoint.querySelector(".gen-picker-panel")?.scrollTop ?? 0;
    const groups = SYS_ENDPOINT_GROUPS.map((g) => ({
      label: t(`sys.group.${g}`),
      options: SYS_ENDPOINTS.filter((e) => e.group === g).map((e) => {
        const title = e.id === "custom" ? t("sys.group.custom") : e.path;
        return {
          value: e.id,
          title,
          badges:
            e.id === "custom"
              ? ""
              : renderFlagBadges({
                  enterprise: e.enterprise,
                  legacy: e.legacy,
                  deprecated: e.deprecated,
                  beta: e.beta,
                  root: e.root,
                }),
        };
      }),
    }));
    const triggerHtml = `
      <button type="button" class="gen-picker-trigger" aria-haspopup="listbox" aria-expanded="${wasOpen}" aria-labelledby="gen-sys-endpoint-label">
        <span class="gen-picker-trigger-body">
          <span class="gen-picker-trigger-title">${escapeHtml(sysTriggerLabel())}</span>
        </span>
        <span class="gen-picker-chevron" aria-hidden="true"></span>
      </button>`;
    const panelHtml = `
      <div class="gen-picker-panel" role="listbox" aria-multiselectable="true"${wasOpen ? "" : " hidden"}>
        ${groups
          .map(
            (g) => `
          <div class="gen-picker-group" role="group" aria-label="${escapeHtml(g.label)}">
            <div class="gen-picker-group-label">${escapeHtml(g.label)}</div>
            ${g.options
              .map((o) => {
                const on = sysEndpointIds.has(o.value);
                return `
              <label class="gen-picker-option multi${on ? " active" : ""}" role="option" aria-selected="${on}" data-value="${escapeHtml(
                o.value,
              )}">
                <input type="checkbox" class="gen-picker-check" ${on ? "checked" : ""} tabindex="-1" />
                <span class="gen-picker-option-stack">
                  <span class="gen-picker-option-main">
                    <span class="gen-picker-option-title">${escapeHtml(o.title)}</span>
                    ${o.badges}
                  </span>
                </span>
              </label>`;
              })
              .join("")}
          </div>`,
          )
          .join("")}
      </div>`;
    genSysEndpoint.innerHTML = triggerHtml + panelHtml;
    if (wasOpen) {
      genSysEndpoint.classList.add("open");
      const panel = genSysEndpoint.querySelector<HTMLElement>(".gen-picker-panel");
      if (panel) panel.scrollTop = scroll;
    }
    updateSysDesc();
  }

  function renderEngineSelect() {
    const groups: PickerGroup[] = KIND_ORDER.flatMap((kind) => {
      const engines = ENGINES.filter((e) => e.kind === kind);
      if (!engines.length) return [];
      return [
        {
          label: t(`gen.kind.${kind}`),
          options: engines.map((e) => {
            const meta = getEngineDocMeta(e.id);
            return {
              value: e.id,
              title: t(`engine.${e.id}.label`),
              hint: t(`engine.${e.id}.desc`),
              badges: renderFlagBadges({
                enterprise: e.enterprise || meta?.enterprise,
                deprecated: meta?.deprecated,
                beta: meta?.beta,
                minVersion: meta?.minVersion,
              }),
            };
          }),
        },
      ];
    });
    renderPicker(genEngine, groups, engineId, "gen-engine-label");
  }

  function renderScopeAccessSelects() {
    renderSeg(
      genScope,
      [
        { value: "prefix", label: t("gen.scope.prefix") },
        { value: "exact", label: t("gen.scope.exact") },
      ],
      scope,
    );
    renderSeg(
      genAccess,
      [
        { value: "read", label: t("gen.access.read") },
        { value: "write", label: t("gen.access.write") },
        { value: "custom", label: t("gen.access.custom") },
      ],
      access,
    );
    genScopeDesc.textContent = t(`gen.scope.${scope}.desc`);
    genAccessDesc.textContent = t(`gen.access.${access}.desc`);
  }

  function renderCapFilter() {
    capFilter.innerHTML = CAP_FILTER_OPTIONS.map(
      (c) =>
        `<option value="${c}"${c === filterCap ? " selected" : ""}>${c === "any" ? t("filter.any") : c}</option>`,
    ).join("");
  }

  function renderGenCaps() {
    const useful = relevantCapabilitiesForGenerator({
      engine: engineId,
      mount: genMount.value,
      sysEndpointIds: selectedSysIds(),
    });
    const prevChecked = new Set(
      [...genCaps.querySelectorAll<HTMLInputElement>('input[type="checkbox"]:checked')].map(
        (b) => b.value,
      ),
    );
    if (prevChecked.size === 0) prevChecked.add("read");

    genCaps.innerHTML = GENERATOR_CAPABILITIES.map((c) => {
      const relevant = useful.has(c);
      const keep = prevChecked.has(c);
      return `
      <label class="cap-check${c === "deny" ? " deny" : ""}${relevant ? "" : " irrelevant"}" title="${
        relevant ? "" : escapeHtml(t("gen.caps.irrelevant"))
      }">
        <input type="checkbox" value="${c}" ${keep ? "checked" : ""} />
        ${c}
      </label>`;
    }).join("");
  }

  function applyEngineDefaults() {
    const eng = getEngine(engineId);
    const isSys = engineId === "sys";
    const isAuth = eng.kind === "auth";
    sysEndpointWrap.hidden = !isSys;
    genMountWrap.hidden = isSys;
    genMount.disabled = engineId === "cubbyhole" || isSys;
    genMount.value = isSys ? "sys" : eng.defaultMount;
    genSecretLabel.textContent = t(`engine.${engineId}.secretLabel`);
    engineNotes.innerHTML = engineNotesHtml(engineId);
    const engMeta = getEngineDocMeta(engineId);
    const engBadges =
      isSys
        ? ""
        : renderFlagBadges({
            enterprise: eng.enterprise || engMeta?.enterprise,
            deprecated: engMeta?.deprecated,
            beta: engMeta?.beta,
            minVersion: engMeta?.minVersion,
          });
    genEngineDesc.innerHTML = `${engBadges}<span class="sys-doc">${escapeHtml(t(`engine.${engineId}.desc`))}</span>`;
    renderEngineSelect();
    if (eng.resourceKind === "none") resourceMode = "named";
    renderTargetSelect();

    if (isSys) {
      renderSysEndpointSelect();
      if (sysIncludesCustom() && !genSecret.value.trim()) {
        genSecret.value = eng.secretPlaceholder;
      }
      genMount.placeholder = "sys";
    } else {
      genSecret.value = eng.secretPlaceholder;
      if (engineId === "custom") {
        genMount.value = "";
        genMount.placeholder = "";
      } else {
        genMount.placeholder = isAuth ? `auth/${eng.defaultMount}` : eng.defaultMount;
      }
    }
    syncSecretVisibility();
    renderGenCaps();
  }

  function refreshStaticUI() {
    applyStaticI18n(app);
    simHelp!.innerHTML = formatHelpText(t("sim.help"));
    genHelpHint!.innerHTML = formatHelpText(t("gen.help"));
    docHelp!.innerHTML = formatHelpText(t("doc.help"));
    if (!(app.querySelector("#tab-doc") as HTMLElement | null)?.hidden) renderDoc();
    renderLangSwitcher();
    renderEngineSelect();
    renderScopeAccessSelects();
    renderTargetSelect();
    renderCapFilter();
    renderGenCaps();
    if (engineId === "sys") renderSysEndpointSelect();
    syncSecretVisibility();
  }

  function onLocaleChange(locale: Locale) {
    setLocale(locale);
    refreshStaticUI();
    applyEngineDefaults();
    refreshGenerator();
    refresh();
  }

  renderLangSwitcher();
  renderEngineSelect();
  renderScopeAccessSelects();
  applyEngineDefaults();
  refreshStaticUI();

  const hash = location.hash.slice(1);
  if (hash.startsWith("s=")) {
    const json = await decodeState(hash.slice(2));
    policyEl.value = json?.p ?? DEFAULT_POLICY;
    pathsEl.value = json?.t ?? DEFAULT_PATHS;
    filterCap = (json?.c as Capability | "any" | undefined) ?? "any";
  } else {
    policyEl.value = DEFAULT_POLICY;
    pathsEl.value = DEFAULT_PATHS;
  }
  renderCapFilter();

  function selectedCaps(): Capability[] {
    const boxes = [...genCaps.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
    const selected = boxes.filter((b) => b.checked).map((b) => b.value as Capability);
    if (selected.includes("deny")) return ["deny"];
    return selected;
  }

  function renderDocRulesTable(
    rules: Array<{ path: string; capabilities: string[] }>,
  ): string {
    if (!rules.length) return `<p class="doc-lead">—</p>`;
    return `<table class="doc-table doc-table-paths">
      <thead><tr><th>path</th><th>capabilities</th></tr></thead>
      <tbody>
        ${rules
          .map(
            (r) => `<tr>
            <td><code>${escapeHtml(r.path)}</code></td>
            <td><code>${escapeHtml(r.capabilities.join(", "))}</code></td>
          </tr>`,
          )
          .join("")}
      </tbody>
    </table>`;
  }

  function renderDocCatalog(): string {
    const kindOrder: EngineKind[] = ["secrets", "auth", "system", "other"];
    const engineBlocks = kindOrder
      .map((kind) => {
        const engines = ENGINES.filter((e) => e.kind === kind && e.id !== "sys" && e.id !== "custom");
        if (!engines.length) return "";
        const cards = engines
          .map((eng) => {
            const label = t(`engine.${eng.id}.label`);
            const desc = t(`engine.${eng.id}.desc`);
            const meta = getEngineDocMeta(eng.id);
            const role = meta ? t(meta.roleKey) : "";
            const notes =
              meta?.notes
                ?.map((k) => `<li>${escapeHtml(t(k))}</li>`)
                .join("") ?? "";
            const docRef = meta?.docPath
              ? `<p class="doc-ref">${apiDocLink(vaultApiDocUrl(meta.docPath))}</p>`
              : "";
            const mountHint =
              eng.kind === "auth" ? `auth/${eng.defaultMount}` : eng.defaultMount;
            const badges = renderFlagBadges({
              enterprise: eng.enterprise || meta?.enterprise,
              deprecated: meta?.deprecated,
              beta: meta?.beta,
              minVersion: meta?.minVersion,
            });
            const levels = `
              <div class="doc-accesses">
                ${(["read", "write"] as const)
                  .map((access) => {
                    const rules = buildEngineRules({
                      engine: eng.id,
                      mount: eng.defaultMount,
                      secretPath: eng.resourceKind === "none" ? "" : "<name>",
                      access,
                      scope: "exact",
                      resourceMode: "named",
                    });
                    return `
                      <div class="doc-access">
                        <h4>${escapeHtml(t(`doc.catalog.${access}`))}</h4>
                        ${renderDocRulesTable(
                          rules.map((r) => ({
                            path: r.path,
                            capabilities: r.capabilities,
                          })),
                        )}
                      </div>`;
                  })
                  .join("")}
              </div>`;
            return `
              <article class="doc-engine">
                <header>
                  <h3>${escapeHtml(label)}</h3>
                  <code class="doc-mount">${escapeHtml(mountHint)}</code>
                </header>
                ${badges}
                <p class="doc-lead">${escapeHtml(desc)}</p>
                ${role ? `<p class="doc-role">${escapeHtml(role)}</p>` : ""}
                ${notes ? `<ul class="doc-notes">${notes}</ul>` : ""}
                ${docRef}
                ${levels}
              </article>`;
          })
          .join("");
        return `
          <div class="doc-kind">
            <h3 class="doc-kind-title">${escapeHtml(t(`gen.kind.${kind}`))}</h3>
            <div class="doc-engines">${cards}</div>
          </div>`;
      })
      .join("");

    const sysRows = SYS_ENDPOINTS.filter((e) => e.id !== "custom")
      .map((ep) => {
        const badges = renderFlagBadges({
          enterprise: ep.enterprise,
          legacy: ep.legacy,
          deprecated: ep.deprecated,
          beta: ep.beta,
          root: ep.root,
        });
        const url = sysEndpointDocUrl(ep.id);
        const link = url ? `<p class="doc-ref">${apiDocLink(url)}</p>` : "";
        const caps = [...new Set([...ep.read, ...ep.write])].join(", ");
        return `<tr class="doc-sys-row" tabindex="0" role="button" aria-expanded="false">
          <td><code>${escapeHtml(ep.path)}</code>${badges}</td>
          <td><code>${escapeHtml(caps)}</code></td>
        </tr>
        <tr class="doc-sys-doc" hidden>
          <td colspan="2">
            <p class="sys-doc">${escapeHtml(ep.doc)}</p>
            ${link}
          </td>
        </tr>`;
      })
      .join("");

    const omitRows = DOC_OMITTED.map((o) => {
      const badges = renderFlagBadges({
        enterprise: "enterprise" in o ? o.enterprise : undefined,
        beta: "beta" in o ? o.beta : undefined,
        minVersion: "minVersion" in o ? o.minVersion : undefined,
      });
      const url = vaultApiDocUrl(o.docPath);
      return `<tr>
        <td>${escapeHtml(o.name)} ${badges}</td>
        <td>${apiDocLink(url)}</td>
        <td>${escapeHtml(t(o.reasonKey))}</td>
      </tr>`;
    }).join("");

    return `
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.source"))}</h2></div>
        <div class="generator-body">
          <p class="doc-lead">${escapeHtml(t("doc.source.body", { site: DOC_SITE }))}</p>
          <p class="doc-ref">${apiDocLink(DOC_SITE)}</p>
        </div>
      </section>
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.catalog"))}</h2></div>
        <div class="generator-body">
          <p class="doc-lead">${escapeHtml(t("doc.catalog.body"))}</p>
          <p class="doc-lead">${escapeHtml(t("doc.meta.body"))}</p>
          <p class="doc-legend">${escapeHtml(t("doc.legend.body"))}</p>
          <div class="doc-badges doc-legend-chips" aria-hidden="true">
            ${badgeHtml("ent", t("doc.badge.ent"))}
            ${badgeHtml("legacy", t("doc.badge.legacy"))}
            ${badgeHtml("dep", t("doc.badge.deprecated"))}
            ${badgeHtml("beta", t("doc.badge.beta"))}
            ${badgeHtml("sudo", t("doc.badge.sudo"))}
          </div>
          ${engineBlocks}
          <div class="doc-kind">
            <h3 class="doc-kind-title">${escapeHtml(t("doc.catalog.sys"))}</h3>
            <p class="doc-lead">${escapeHtml(t("doc.catalog.sys.body"))}</p>
            <table class="doc-table doc-table-paths doc-table-sys">
              <thead><tr><th>path</th><th>capabilities</th></tr></thead>
              <tbody>${sysRows}</tbody>
            </table>
          </div>
          <div class="doc-kind">
            <h3 class="doc-kind-title">${escapeHtml(t("doc.omit"))}</h3>
            <p class="doc-lead">${escapeHtml(t("doc.omit.body"))}</p>
            <table class="doc-table">
              <thead>
                <tr>
                  <th></th>
                  <th>api-docs</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>${omitRows}</tbody>
            </table>
          </div>
        </div>
      </section>`;
  }

  function renderDoc() {
    const matchCards = DOC_MATCH_KEYS.map(
      (key) => `
        <article class="doc-card">
          <h3>${escapeHtml(t(`doc.match.${key}`))}</h3>
          <p>${escapeHtml(t(`doc.match.${key}.body`))}</p>
        </article>`,
    ).join("");

    const groups = (["syntax", "wildcards", "policy", "vault"] as const)
      .map((group) => {
        const rows = DOC_DIAG_RULES.filter((r) => r.group === group)
          .map(
            (r) => `
            <li class="doc-diag">
              <span class="sev ${r.severity}">${r.severity}</span>
              <code>${escapeHtml(r.code)}</code>
              <span>${escapeHtml(t(`diag.${r.code}`))}</span>
            </li>`,
          )
          .join("");
        return `
          <div class="doc-diag-group">
            <h3>${escapeHtml(t(`doc.diags.${group}`))}</h3>
            <ul class="doc-diag-list">${rows}</ul>
          </div>`;
      })
      .join("");

    const caps = VALID_CAPABILITIES.map((c) => `<code class="doc-chip">${c}</code>`).join("");
    const roots = SYS_ROOT_PATHS.map((p) => `<li><code>${escapeHtml(p)}</code></li>`).join("");
    const endpoints = Object.entries(KNOWN_ENDPOINT_CAPS)
      .map(
        ([path, capsList]) =>
          `<li><code>${escapeHtml(path)}</code> → <code>${escapeHtml(capsList.join(", "))}</code></li>`,
      )
      .join("");

    docBody.innerHTML = `
      ${renderDocCatalog()}
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.match"))}</h2></div>
        <div class="doc-grid">${matchCards}</div>
      </section>
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.diags"))}</h2></div>
        <div class="doc-diags">${groups}</div>
      </section>
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.caps"))}</h2></div>
        <div class="generator-body">
          <p class="doc-lead">${escapeHtml(t("doc.caps.body"))}</p>
          <div class="doc-chips">${caps}</div>
        </div>
      </section>
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.root"))}</h2></div>
        <div class="generator-body">
          <p class="doc-lead">${escapeHtml(t("doc.root.body"))}</p>
          <ul class="doc-path-list">${roots}</ul>
        </div>
      </section>
      <section class="panel doc-section">
        <div class="panel-header"><h2>${escapeHtml(t("doc.endpoints"))}</h2></div>
        <div class="generator-body">
          <p class="doc-lead">${escapeHtml(t("doc.endpoints.body"))}</p>
          <ul class="doc-path-list">${endpoints}</ul>
        </div>
      </section>
    `;
    bindSysDocRows(docBody);
  }

  function bindSysDocRows(root: HTMLElement) {
    const toggle = (row: HTMLTableRowElement) => {
      const detail = row.nextElementSibling as HTMLTableRowElement | null;
      if (!detail?.classList.contains("doc-sys-doc")) return;
      const open = detail.hidden;
      detail.hidden = !open;
      row.classList.toggle("open", open);
      row.setAttribute("aria-expanded", String(open));
    };
    root.querySelectorAll<HTMLTableRowElement>("tr.doc-sys-row").forEach((row) => {
      row.addEventListener("click", (e) => {
        if ((e.target as HTMLElement).closest("a")) return;
        toggle(row);
      });
      row.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggle(row);
        }
      });
    });
  }

  function setTab(tab: "sim" | "gen" | "doc") {
    app.querySelectorAll<HTMLElement>(".tab-panel").forEach((p) => {
      const on = p.id === `tab-${tab}`;
      p.hidden = !on;
      p.classList.toggle("active", on);
    });
    app.querySelectorAll<HTMLButtonElement>(".tab").forEach((b) => {
      const on = b.dataset.tab === tab;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", String(on));
    });
    simActions.hidden = tab !== "sim";
    if (tab === "sim") refresh();
    if (tab === "doc") renderDoc();
  }

  function refreshGenerator() {
    customCapsWrap.hidden = access !== "custom";
    const rules = buildEngineRules({
      engine: engineId,
      mount: genMount.value,
      secretPath: genSecret.value,
      access,
      scope,
      resourceMode: resourceKind() === "none" ? "named" : resourceMode,
      customCapabilities: selectedCaps(),
      sysEndpointIds: engineId === "sys" ? selectedSysIds() : undefined,
    });
    const hcl = buildPolicyHcl(rules);
    const ready = rules.length > 0 && Boolean(hcl);
    genAppend.disabled = !ready;
    genReplace.disabled = !ready;
    genPreview.textContent = ready ? hcl : t("gen.empty");
    genMeta.textContent = ready ? tp("gen.paths", rules.length) : "";
    const ids = engineId === "sys" ? selectedSysIds() : [];
    genHint.innerHTML =
      engineId === "sys" && ids.length === 1
        ? renderFlagBadges({
            enterprise: getSysEndpoint(ids[0]).enterprise,
            legacy: getSysEndpoint(ids[0]).legacy,
            deprecated: getSysEndpoint(ids[0]).deprecated,
            beta: getSysEndpoint(ids[0]).beta,
            root: getSysEndpoint(ids[0]).root,
          })
        : engineId === "sys" && ids.length > 1
          ? `<span class="sys-doc-meta">${escapeHtml(tp("gen.sys.n", ids.length))}</span>`
          : "";
  }

  let syncUrlGen = 0;
  /** Returns the shareable URL (always includes `#s=…` when encoding succeeds). */
  async function syncUrl(): Promise<string> {
    const gen = ++syncUrlGen;
    const base = `${location.origin}${location.pathname}${location.search}`;
    try {
      const payload = await encodeState({ p: policyEl.value, t: pathsEl.value, c: filterCap });
      if (gen !== syncUrlGen) return location.href;
      const hash = `#s=${payload}`;
      const url = `${base}${hash}`;
      if (location.hash !== hash) {
        // Use path + hash (not hash-only): more reliable on project Pages base paths.
        history.replaceState(null, "", `${location.pathname}${location.search}${hash}`);
      }
      return url;
    } catch (err) {
      console.warn("Failed to sync URL state", err);
      return location.href;
    }
  }

  function jumpToLine(line: number) {
    const lines = policyEl.value.split("\n");
    let pos = 0;
    for (let i = 0; i < line - 1 && i < lines.length; i++) pos += lines[i].length + 1;
    policyEl.focus();
    policyEl.setSelectionRange(pos, pos + (lines[line - 1]?.length ?? 0));
    const lineHeight = parseFloat(getComputedStyle(policyEl).lineHeight) || 20;
    policyEl.scrollTop = Math.max(0, (line - 3) * lineHeight);
    backdropEl.scrollTop = policyEl.scrollTop;
    linesEl.scrollTop = policyEl.scrollTop;
  }

  function refresh() {
    const parsed = parsePolicy(policyEl.value);
    const results = matchPaths(pathsEl.value.split("\n"), parsed.rules);
    const errors = parsed.diagnostics.filter((d) => d.severity === "error").length;
    const warns = parsed.diagnostics.filter((d) => d.severity === "warning").length;
    policyMeta.textContent =
      errors || warns
        ? t("meta.issues", {
            n: parsed.rules.length,
            errors,
            warns,
          })
        : tp("meta.ok", parsed.rules.length);
    pathsMeta.textContent = tp("meta.tests", results.length);
    syncEditorChrome(policyEl, linesEl, backdropEl, parsed.diagnostics);
    diagEl.innerHTML = renderDiagnostics(parsed.diagnostics);
    resultsEl.innerHTML = renderResults(results, filterCap);
    syncUrl();
  }

  langSelect.addEventListener("change", () => {
    onLocaleChange(langSelect.value as Locale);
  });

  app.querySelectorAll<HTMLButtonElement>(".tab").forEach((btn) => {
    btn.addEventListener("click", () => setTab(btn.dataset.tab as "sim" | "gen" | "doc"));
  });

  genEngine.addEventListener("click", (e) => {
    const target = e.target as HTMLElement;
    const option = target.closest<HTMLButtonElement>(".gen-picker-option");
    if (option?.dataset.value) {
      engineId = option.dataset.value as EngineId;
      closePicker(genEngine);
      applyEngineDefaults();
      refreshGenerator();
      return;
    }
    if (target.closest(".gen-picker-trigger")) {
      if (genEngine.classList.contains("open")) closePicker(genEngine);
      else openPicker(genEngine);
    }
  });

  genSysEndpoint.addEventListener("click", (e) => {
    const target = e.target as HTMLElement;
    const option = target.closest<HTMLElement>(".gen-picker-option");
    if (option?.dataset.value) {
      e.preventDefault();
      e.stopPropagation();
      const id = option.dataset.value;
      if (sysEndpointIds.has(id)) {
        if (sysEndpointIds.size > 1) sysEndpointIds.delete(id);
      } else {
        sysEndpointIds.add(id);
      }
      if (sysIncludesCustom() && !genSecret.value.trim()) {
        genSecret.value = "policies/acl/*";
      }
      renderSysEndpointSelect();
      syncSecretVisibility();
      renderGenCaps();
      refreshGenerator();
      return;
    }
    if (target.closest(".gen-picker-trigger")) {
      e.stopPropagation();
      if (genSysEndpoint.classList.contains("open")) closePicker(genSysEndpoint);
      else openPicker(genSysEndpoint);
    }
  });

  // Keep the multi-select open: re-render detaches the click target, so stop before document closes it.
  genSysEndpoint.addEventListener("mousedown", (e) => {
    if ((e.target as HTMLElement).closest(".gen-picker-option, .gen-picker-panel")) {
      e.stopPropagation();
    }
  });

  document.addEventListener("click", (e) => {
    const t = e.target as Node;
    if (!genEngine.contains(t) && !genSysEndpoint.contains(t)) closeAllPickers();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAllPickers();
  });

  genTarget.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("button.seg-btn");
    if (!btn?.dataset.value) return;
    resourceMode = btn.dataset.value as ResourceMode;
    genTargetDesc.textContent =
      resourceMode === "all" ? t("gen.target.all.desc") : t("gen.target.named.desc");
    if (resourceMode === "named" && !genSecret.value.trim()) {
      genSecret.value = getEngine(engineId).secretPlaceholder;
    }
    renderTargetSelect();
    syncSecretVisibility();
    refreshGenerator();
  });

  genAccess.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("button.seg-btn");
    if (!btn?.dataset.value) return;
    access = btn.dataset.value as AccessLevel;
    genAccessDesc.textContent = t(`gen.access.${access}.desc`);
    renderScopeAccessSelects();
    if (engineId === "sys") updateSysDesc();
    refreshGenerator();
  });

  genScope.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("button.seg-btn");
    if (!btn?.dataset.value) return;
    scope = btn.dataset.value as "exact" | "prefix";
    genScopeDesc.textContent = t(`gen.scope.${scope}.desc`);
    renderScopeAccessSelects();
    refreshGenerator();
  });

  genMount.addEventListener("input", refreshGenerator);
  genSecret.addEventListener("input", refreshGenerator);
  genCaps.addEventListener("change", (e) => {
    const target = e.target as HTMLInputElement;
    if (target.value === "deny" && target.checked) {
      genCaps.querySelectorAll<HTMLInputElement>('input[type="checkbox"]').forEach((box) => {
        box.checked = box.value === "deny";
      });
    } else if (target.value !== "deny" && target.checked) {
      const denyBox = genCaps.querySelector<HTMLInputElement>('input[value="deny"]');
      if (denyBox) denyBox.checked = false;
    }
    refreshGenerator();
  });

  genAppend.addEventListener("click", () => {
    const block = genPreview.textContent ?? "";
    if (!block.includes('path "')) return;
    policyEl.value = appendToPolicy(policyEl.value, block);
    setTab("sim");
    policyEl.scrollTop = policyEl.scrollHeight;
  });

  genReplace.addEventListener("click", () => {
    const block = genPreview.textContent ?? "";
    if (!block.includes('path "')) return;
    policyEl.value = `${block}\n`;
    setTab("sim");
  });

  genGotoSim.addEventListener("click", () => setTab("sim"));

  policyEl.addEventListener("input", refresh);
  pathsEl.addEventListener("input", refresh);
  policyEl.addEventListener("scroll", () => {
    linesEl.scrollTop = policyEl.scrollTop;
    backdropEl.scrollTop = policyEl.scrollTop;
    backdropEl.scrollLeft = policyEl.scrollLeft;
  });

  policyEl.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const start = policyEl.selectionStart;
      const end = policyEl.selectionEnd;
      policyEl.value = `${policyEl.value.slice(0, start)}  ${policyEl.value.slice(end)}`;
      policyEl.selectionStart = policyEl.selectionEnd = start + 2;
      refresh();
    }
  });

  diagEl.addEventListener("click", (e) => {
    const row = (e.target as HTMLElement).closest<HTMLElement>(".diag");
    if (!row?.dataset.line) return;
    const line = Number(row.dataset.line);
    if (line > 0) jumpToLine(line);
  });

  capFilter.addEventListener("change", () => {
    filterCap = capFilter.value as Capability | "any";
    refresh();
  });

  exSelect.addEventListener("change", () => {
    const key = exSelect.value;
    exSelect.value = "";
    const ex = EXAMPLES[key];
    if (!ex) return;
    policyEl.value = ex.policy;
    pathsEl.value = ex.paths;
    setTab("sim");
  });

  app.querySelector("#share-btn")!.addEventListener("click", async () => {
    const url = await syncUrl();
    const shareBtn = app.querySelector<HTMLButtonElement>("#share-btn")!;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url);
      } else {
        throw new Error("clipboard unavailable");
      }
      shareBtn.textContent = t("share.copied");
      setTimeout(() => {
        shareBtn.textContent = t("share");
      }, 1500);
    } catch {
      prompt(t("share.prompt"), url);
    }
  });

  refreshGenerator();
  refresh();
}

void mount();
