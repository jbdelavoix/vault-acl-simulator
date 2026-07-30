import type { Severity } from "./types";
import { VALID_CAPABILITIES } from "./types";
import { SYS_ROOT_PATHS } from "./lint";
import { KNOWN_ENDPOINT_CAPS } from "./lint";

export type DocDiagGroup = "syntax" | "wildcards" | "policy" | "vault";

export interface DocDiagRule {
  code: string;
  severity: Severity;
  group: DocDiagGroup;
}

/** All diagnostic / lint rules the simulator knows about. */
export const DOC_DIAG_RULES: DocDiagRule[] = [
  { code: "invalid_capability", severity: "error", group: "syntax" },
  { code: "unsupported_policy_attr", severity: "error", group: "syntax" },
  { code: "no_path_block", severity: "error", group: "syntax" },
  { code: "unclosed_block", severity: "error", group: "syntax" },
  { code: "no_capabilities", severity: "error", group: "syntax" },
  { code: "plus_star", severity: "error", group: "wildcards" },
  { code: "star_position", severity: "error", group: "wildcards" },
  { code: "missing_sudo", severity: "error", group: "vault" },
  { code: "missing_caps", severity: "error", group: "vault" },
  { code: "unused_caps", severity: "warning", group: "vault" },
  { code: "legacy_path", severity: "warning", group: "vault" },
  { code: "deprecated_path", severity: "warning", group: "vault" },
  { code: "deny_overrides", severity: "warning", group: "policy" },
  { code: "duplicate_path", severity: "warning", group: "policy" },
  { code: "unknown_toplevel", severity: "warning", group: "syntax" },
  { code: "unknown_attr", severity: "warning", group: "syntax" },
  { code: "plus_segment", severity: "warning", group: "wildcards" },
  { code: "trailing_slash", severity: "warning", group: "wildcards" },
  { code: "redundant_rule", severity: "warning", group: "policy" },
  { code: "empty_policy", severity: "warning", group: "policy" },
  { code: "leading_slash", severity: "info", group: "syntax" },
  { code: "templated", severity: "info", group: "wildcards" },
];

export const DOC_MATCH_KEYS = [
  "deny_default",
  "exact",
  "prefix",
  "plus",
  "priority",
  "merge",
  "sudo",
] as const;

export { VALID_CAPABILITIES, SYS_ROOT_PATHS, KNOWN_ENDPOINT_CAPS };
