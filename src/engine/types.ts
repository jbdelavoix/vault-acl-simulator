export const VALID_CAPABILITIES = [
  "create",
  "read",
  "update",
  "patch",
  "delete",
  "list",
  "sudo",
  "deny",
  "subscribe",
  "recover",
] as const;

export type Capability = (typeof VALID_CAPABILITIES)[number];

export type Severity = "error" | "warning" | "info";

export interface Diagnostic {
  severity: Severity;
  /** i18n key suffix under diag.* */
  code: string;
  params?: Record<string, string | number>;
  line?: number;
  column?: number;
  path?: string;
}

export interface PathRule {
  /** Original path string from the policy (after leading / strip). */
  path: string;
  /** Path used for matching (prefix * stripped when no segment wildcards). */
  matchPath: string;
  capabilities: Capability[];
  isPrefix: boolean;
  hasSegmentWildcards: boolean;
  isTemplated: boolean;
  line: number;
  comment?: string;
}

export interface ParsedPolicy {
  rules: PathRule[];
  diagnostics: Diagnostic[];
  raw: string;
}

export interface MatchCandidate {
  rule: PathRule;
  firstWCOrGlob: number;
  wildcards: number;
  isPrefix: boolean;
  wcPath: string;
}

export interface PathMatchResult {
  requestPath: string;
  allowed: boolean;
  denied: boolean;
  capabilities: Capability[];
  winningRule: PathRule | null;
  candidates: MatchCandidate[];
  explanation: string;
}
