import type { Capability, Diagnostic, PathRule } from "./types";
import { SYS_ENDPOINTS } from "./catalog";

/**
 * System backend PathsSpecial.Root entries (relative to mount `sys/`),
 * from vault/vault/logical_system.go. Requests to these paths set
 * RootPrivsRequired — AllowOperation must grant sudo or Vault returns deny.
 */
const SYS_ROOT_SUFFIXES = [
  "auth/*",
  "mounts/auth/+/tune",
  "remount",
  "audit",
  "audit/*",
  "raw",
  "raw/*",
  "replication/primary/secondary-token",
  "replication/performance/primary/secondary-token",
  "replication/dr/primary/secondary-token",
  "replication/reindex",
  "replication/dr/reindex",
  "replication/performance/reindex",
  "rotate",
  "config/cors",
  "config/auditing/*",
  "config/ui/headers/*",
  "plugins/catalog/*",
  "plugins/runtimes/catalog/*",
  "revoke-prefix/*",
  "revoke-force/*",
  "leases/revoke-prefix/*",
  "leases/revoke-force/*",
  "leases/lookup/*",
  "storage/raft/snapshot-auto/config/*",
  "leases",
  "reporting/scan",
  "internal/inspect/*",
  "internal/counters/activity/export",
  "seal",
  "step-down",
  "activation-flags/oauth-resource-server/activate",
  "activation-flags/oauth-resource-server/deactivate",
  "config/oauth-resource-server/*",
] as const;

export const SYS_ROOT_PATHS: string[] = SYS_ROOT_SUFFIXES.map((s) => `sys/${s}`);

/** Endpoints with a documented required verb (besides sudo). */
export const KNOWN_ENDPOINT_CAPS: Record<string, Capability[]> = {
  "sys/rotate": ["update"],
  "sys/seal": ["update"],
  "sys/step-down": ["update"],
  "sys/remount": ["update"],
};

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Vault policy/root pattern → regex against a concrete request path. */
export function patternToRegex(pattern: string): RegExp {
  let p = pattern;
  const isPrefix = p.endsWith("*");
  if (isPrefix) p = p.slice(0, -1);

  const segments = p.split("/");
  const reSegs = segments.map((seg, i) => {
    if (seg === "+") return "[^/]+";
    if (isPrefix && i === segments.length - 1) return `${escapeRe(seg)}.*`;
    return escapeRe(seg);
  });
  return new RegExp(`^${reSegs.join("/")}$`);
}

/**
 * Capabilities that actually matter for a known Vault path (sys catalog / fixed verbs).
 * Returns null when the path is not in our curated knowledge.
 */
export function relevantCapabilitiesForPath(path: string): Capability[] | null {
  const set = new Set<Capability>();

  const known = KNOWN_ENDPOINT_CAPS[path];
  if (known) for (const c of known) set.add(c);

  const patterned = findSysEndpointForPath(path);

  if (patterned) {
    for (const c of patterned.read) set.add(c);
    for (const c of patterned.write) set.add(c);
    if (patterned.root) set.add("sudo");
  }

  if (!patterned && known) {
    for (const rootPat of SYS_ROOT_PATHS) {
      if (patternToRegex(rootPat).test(path)) {
        set.add("sudo");
        break;
      }
    }
  }

  if (set.size === 0) return null;
  return [...set];
}

/** Curated sys/identity catalog entry matching a concrete or pattern path. */
export function findSysEndpointForPath(path: string) {
  const candidates = SYS_ENDPOINTS.filter((e) => e.id !== "custom");
  const exact = candidates.find((e) => e.path === path);
  if (exact) return exact;
  return candidates
    .filter((e) => e.path.includes("*") || e.path.includes("+"))
    .find((e) => patternToRegex(e.path).test(path));
}

export function ruleCoversPath(rule: PathRule, requestPath: string): boolean {
  if (rule.capabilities.includes("deny")) return false;

  if (!rule.isPrefix && !rule.hasSegmentWildcards) {
    return rule.path === requestPath;
  }

  if (rule.hasSegmentWildcards) {
    return patternToRegex(rule.path).test(requestPath);
  }

  return requestPath.startsWith(rule.matchPath);
}

/** Concrete examples derived from each root pattern (for coverage checks). */
function concreteExamples(rootPattern: string): string[] {
  if (!rootPattern.includes("+") && !rootPattern.endsWith("*")) {
    return [rootPattern];
  }
  if (rootPattern.endsWith("/*") && !rootPattern.includes("+")) {
    const base = rootPattern.slice(0, -2);
    return [base + "/x", base + "/x/y"];
  }
  if (rootPattern.includes("+")) {
    return [rootPattern.replace(/\+/g, "x").replace(/\*$/, "y")];
  }
  // foo* style under sys — none currently
  return [rootPattern.replace(/\*$/, "x")];
}

/**
 * Returns a root-protected path this rule can grant access to, or null.
 */
export function ruleTouchesRootProtected(rule: PathRule): string | null {
  if (rule.capabilities.includes("deny")) return null;

  for (const rootPat of SYS_ROOT_PATHS) {
    for (const example of concreteExamples(rootPat)) {
      if (ruleCoversPath(rule, example)) {
        return rootPat.includes("*") || rootPat.includes("+") ? rootPat : example;
      }
    }
    // Exact policy path equals the root pattern itself (e.g. path "sys/auth/*")
    if (rule.path === rootPat) return rootPat;
  }

  return null;
}

export function lintRules(rules: PathRule[]): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  for (const rule of rules) {
    if (rule.capabilities.includes("deny")) continue;

    const rootHit = ruleTouchesRootProtected(rule);
    if (rootHit && !rule.capabilities.includes("sudo")) {
      diagnostics.push({
        severity: "error",
        code: "missing_sudo",
        params: { root: rootHit },
        line: rule.line,
        path: rule.path,
      });
    }

    const required = KNOWN_ENDPOINT_CAPS[rule.path];
    if (required) {
      const missing = required.filter((c) => !rule.capabilities.includes(c));
      if (missing.length > 0) {
        diagnostics.push({
          severity: "error",
          code: "missing_caps",
          params: {
            path: rule.path,
            required: missing.join(", "),
            have: rule.capabilities.join(", "),
          },
          line: rule.line,
          path: rule.path,
        });
      }
    }

    const relevant = relevantCapabilitiesForPath(rule.path);
    if (relevant) {
      const useful = new Set(relevant);
      const unused = rule.capabilities.filter((c) => !useful.has(c));
      if (unused.length > 0) {
        diagnostics.push({
          severity: "warning",
          code: "unused_caps",
          params: {
            path: rule.path,
            unused: unused.join(", "),
            useful: relevant.join(", "),
          },
          line: rule.line,
          path: rule.path,
        });
      }
    }

    const catalog = findSysEndpointForPath(rule.path);
    if (catalog?.deprecated) {
      diagnostics.push({
        severity: "warning",
        code: "deprecated_path",
        params: { path: catalog.path },
        line: rule.line,
        path: rule.path,
      });
    } else if (catalog?.legacy) {
      diagnostics.push({
        severity: "warning",
        code: "legacy_path",
        params: { path: catalog.path },
        line: rule.line,
        path: rule.path,
      });
    } else if (/^[^/]+\/(token|key)\/[^/]+$/.test(rule.path)) {
      // GCP secrets engine legacy shapes (prefer roleset/<name>/token|key).
      diagnostics.push({
        severity: "warning",
        code: "deprecated_path",
        params: { path: rule.path },
        line: rule.line,
        path: rule.path,
      });
    }

    if (
      !rule.isPrefix &&
      !rule.hasSegmentWildcards &&
      rule.path.endsWith("/") &&
      rule.path.length > 1
    ) {
      diagnostics.push({
        severity: "warning",
        code: "trailing_slash",
        params: { path: rule.path },
        line: rule.line,
        path: rule.path,
      });
    }
  }

  for (let i = 0; i < rules.length; i++) {
    const a = rules[i];
    if (a.capabilities.includes("deny") || a.isPrefix || a.hasSegmentWildcards) continue;
    for (let j = 0; j < rules.length; j++) {
      if (i === j) continue;
      const b = rules[j];
      if (b.capabilities.includes("deny") || !b.isPrefix || b.hasSegmentWildcards) continue;
      if (!a.path.startsWith(b.matchPath)) continue;
      if (a.capabilities.every((c) => b.capabilities.includes(c))) {
        diagnostics.push({
          severity: "warning",
          code: "redundant_rule",
          params: { path: a.path, broader: b.path },
          line: a.line,
          path: a.path,
        });
      }
    }
  }

  return diagnostics;
}
