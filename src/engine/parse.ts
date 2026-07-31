import type {
  Capability,
  Diagnostic,
  ParsedPolicy,
  PathRule,
} from "./types";
import { VALID_CAPABILITIES } from "./types";
import { lintRules } from "./lint";

const CAP_SET = new Set<string>(VALID_CAPABILITIES);

interface BlockMatch {
  path: string;
  body: string;
  line: number;
  pathStart: number;
}

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function stripComments(source: string): string {
  // Preserve length and newlines so indices/line numbers stay aligned with source.
  // Must be string-aware: path globs like "foo/*/bar" contain /* and */ and must
  // not be treated as block comments (otherwise mid-* paths vanish and never lint).
  const out = source.split("");
  let i = 0;
  while (i < source.length) {
    const ch = source[i];

    if (ch === '"' || ch === "'") {
      const quote = ch;
      i++;
      while (i < source.length) {
        if (source[i] === "\\") {
          i += 2;
          continue;
        }
        if (source[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    if (ch === "/" && source[i + 1] === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < source.length) {
        if (source[i] === "\n") {
          i++;
          continue;
        }
        if (source[i] === "*" && source[i + 1] === "/") {
          out[i] = " ";
          out[i + 1] = " ";
          i += 2;
          break;
        }
        out[i] = " ";
        i++;
      }
      continue;
    }

    if (ch === "/" && source[i + 1] === "/" && source[i - 1] !== ":") {
      while (i < source.length && source[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }

    if (ch === "#") {
      while (i < source.length && source[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }

    i++;
  }
  return out.join("");
}

function extractStringList(raw: string): string[] {
  const values: string[] = [];
  const re = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    values.push((m[1] ?? m[2]).replace(/\\"/g, '"').replace(/\\'/g, "'"));
  }
  return values;
}

function findPathBlocks(source: string): BlockMatch[] {
  const blocks: BlockMatch[] = [];
  const cleaned = stripComments(source);
  const pathRe = /\bpath\s+("([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')\s*\{/g;
  let match: RegExpExecArray | null;

  while ((match = pathRe.exec(cleaned))) {
    const pathLiteral = match[2] ?? match[3] ?? "";
    const braceStart = match.index + match[0].length - 1;
    let depth = 0;
    let i = braceStart;
    let end = -1;

    for (; i < cleaned.length; i++) {
      const ch = cleaned[i];
      if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }

    if (end === -1) {
      blocks.push({
        path: pathLiteral,
        body: "",
        line: lineOf(source, match.index),
        pathStart: match.index,
      });
      continue;
    }

    blocks.push({
      path: pathLiteral.replace(/\\"/g, '"'),
      body: cleaned.slice(braceStart + 1, end),
      line: lineOf(source, match.index),
      pathStart: match.index,
    });

    pathRe.lastIndex = end + 1;
  }

  return blocks;
}

function parseCapabilities(body: string, path: string, line: number, diagnostics: Diagnostic[]): Capability[] {
  const capsMatch = body.match(/\bcapabilities\s*=\s*\[([\s\S]*?)\]/);
  const policyMatch = body.match(/\bpolicy\s*=\s*("([^"]*)"|'([^']*)')/);

  let capabilities: Capability[] = [];

  if (capsMatch) {
    const listed = extractStringList(capsMatch[1]);
    for (const cap of listed) {
      if (!CAP_SET.has(cap)) {
        diagnostics.push({
          severity: "error",
          code: "invalid_capability",
          params: { cap, valid: VALID_CAPABILITIES.join(", ") },
          line,
          path,
        });
        continue;
      }
      capabilities.push(cap as Capability);
    }
  }

  if (policyMatch) {
    diagnostics.push({
      severity: "error",
      code: "unsupported_policy_attr",
      line,
      path,
    });
  }

  if (capabilities.includes("deny")) {
    if (capabilities.length > 1) {
      diagnostics.push({
        severity: "warning",
        code: "deny_overrides",
        line,
        path,
      });
    }
    return ["deny"];
  }

  // Dedupe preserving order
  return [...new Set(capabilities)];
}

function analyzePathPattern(
  rawPath: string,
  line: number,
  diagnostics: Diagnostic[],
): Pick<PathRule, "path" | "matchPath" | "isPrefix" | "hasSegmentWildcards" | "isTemplated"> {
  let path = rawPath;
  if (path.startsWith("/")) {
    diagnostics.push({
      severity: "info",
      code: "leading_slash",
      params: { path: rawPath },
      line,
      path: rawPath,
    });
    path = path.slice(1);
  }

  const isTemplated = /\{\{[^{}]+\}\}/.test(path);
  if (isTemplated) {
    diagnostics.push({
      severity: "info",
      code: "templated",
      line,
      path,
    });
  }

  if (path.includes("+*")) {
    diagnostics.push({
      severity: "error",
      code: "plus_star",
      line,
      path,
    });
  }

  const hasSegmentWildcards =
    path === "+" || path.includes("/+") || path.startsWith("+/");

  // Glob * is only valid as the last character (Vault docs).
  const starIndex = path.indexOf("*");
  if (starIndex !== -1 && starIndex !== path.length - 1) {
    diagnostics.push({
      severity: "error",
      code: "star_position",
      line,
      path,
    });
  }

  let matchPath = path;
  let isPrefix = false;

  if (path.endsWith("*")) {
    if (!hasSegmentWildcards) {
      matchPath = path.slice(0, -1);
      isPrefix = true;
    } else {
      isPrefix = true;
      // Keep trailing * for segment-wildcard + prefix rules
      matchPath = path;
    }
  }

  if (hasSegmentWildcards) {
    const segments = (path.endsWith("*") ? path.slice(0, -1) : path).split("/");
    for (const seg of segments) {
      if (seg.includes("+") && seg !== "+") {
        diagnostics.push({
          severity: "warning",
          code: "plus_segment",
          params: { seg },
          line,
          path,
        });
      }
    }
  }

  return { path, matchPath, isPrefix, hasSegmentWildcards, isTemplated };
}

function extractComment(body: string): string | undefined {
  const m = body.match(/\bcomment\s*=\s*("([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')/);
  if (!m) return undefined;
  return m[2] ?? m[3];
}

export function parsePolicy(source: string): ParsedPolicy {
  const diagnostics: Diagnostic[] = [];
  const trimmed = source.trim();

  if (!trimmed) {
    return {
      rules: [],
      diagnostics: [
        {
          severity: "warning",
          code: "empty_policy",
        },
      ],
      raw: source,
    };
  }

  // Top-level unknown keys (rough check)
  const cleaned = stripComments(source);
  const topLevel = cleaned.replace(/\bpath\s+(?:"[^"]*"|'[^']*')\s*\{[\s\S]*?\}/g, " ");
  const unknown = topLevel.match(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|\{)/g);
  if (unknown) {
    for (const hit of unknown) {
      const key = hit.replace(/\s*(=|\{)$/, "");
      if (key !== "name" && key !== "path") {
        diagnostics.push({
          severity: "warning",
          code: "unknown_toplevel",
          params: { key },
        });
      }
    }
  }

  const blocks = findPathBlocks(source);
  if (blocks.length === 0) {
    diagnostics.push({
      severity: "error",
      code: "no_path_block",
    });
  }

  // Unclosed brace detection
  for (const block of blocks) {
    if (block.body === "" && !source.slice(block.pathStart).includes("}")) {
      diagnostics.push({
        severity: "error",
        code: "unclosed_block",
        params: { path: block.path },
        line: block.line,
        path: block.path,
      });
    }
  }

  const rules: PathRule[] = [];
  const seen = new Map<string, number>();

  for (const block of blocks) {
    if (block.path === "" && block.body === "") continue;

    const pattern = analyzePathPattern(block.path, block.line, diagnostics);
    const capabilities = parseCapabilities(block.body, pattern.path, block.line, diagnostics);

    if (capabilities.length === 0) {
      diagnostics.push({
        severity: "error",
        code: "no_capabilities",
        params: { path: pattern.path },
        line: block.line,
        path: pattern.path,
      });
    }

    const dupKey = pattern.path;
    if (seen.has(dupKey)) {
      diagnostics.push({
        severity: "warning",
        code: "duplicate_path",
        params: { path: dupKey, lineA: seen.get(dupKey)!, lineB: block.line },
        line: block.line,
        path: pattern.path,
      });
    } else {
      seen.set(dupKey, block.line);
    }

    // Unknown keys inside path block
    const known = new Set([
      "comment",
      "policy",
      "capabilities",
      "allowed_parameters",
      "denied_parameters",
      "required_parameters",
      "min_wrapping_ttl",
      "max_wrapping_ttl",
      "mfa_methods",
      "control_group",
      "subscribe_event_types",
    ]);
    const keyRe = /\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=/g;
    let km: RegExpExecArray | null;
    while ((km = keyRe.exec(block.body))) {
      if (!known.has(km[1])) {
        diagnostics.push({
          severity: "warning",
          code: "unknown_attr",
          params: { key: km[1], path: pattern.path },
          line: block.line,
          path: pattern.path,
        });
      }
    }

    rules.push({
      ...pattern,
      capabilities,
      line: block.line,
      comment: extractComment(block.body),
    });
  }

  diagnostics.push(...lintRules(rules));

  return { rules, diagnostics, raw: source };
}
