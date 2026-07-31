import { describe, expect, it } from "vitest";
import { parsePolicy } from "./parse";
import { isLowerPriority, matchPath } from "./match";
import type { MatchCandidate } from "./types";

const sample = `
path "secret/data/foo" {
  capabilities = ["read"]
}

path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/super-secret" {
  capabilities = ["deny"]
}

path "secret/+/teamb" {
  capabilities = ["read"]
}

path "secret/zip-*" {
  capabilities = ["read"]
}
`;

describe("parsePolicy", () => {
  it("parses path blocks and capabilities", () => {
    const { rules, diagnostics } = parsePolicy(sample);
    expect(rules.length).toBe(5);
    expect(rules[0].path).toBe("secret/data/foo");
    expect(rules[0].capabilities).toEqual(["read"]);
    expect(rules[1].isPrefix).toBe(true);
    expect(rules[1].matchPath).toBe("secret/data/");
    expect(diagnostics.some((d) => d.severity === "error")).toBe(false);
  });

  it("rejects invalid capability", () => {
    const { diagnostics } = parsePolicy(`path "x" { capabilities = ["nope"] }`);
    expect(diagnostics.some((d) => d.code === "invalid_capability" && d.params?.cap === "nope")).toBe(
      true,
    );
  });

  it("rejects +*", () => {
    const { diagnostics } = parsePolicy(`path "secret/+*" { capabilities = ["read"] }`);
    expect(diagnostics.some((d) => d.code === "plus_star")).toBe(true);
  });

  it("rejects unsupported policy = attribute", () => {
    const { diagnostics, rules } = parsePolicy(`path "secret/x" { policy = "write" }`);
    expect(diagnostics.some((d) => d.code === "unsupported_policy_attr")).toBe(true);
    expect(rules[0].capabilities).toEqual([]);
  });

  it("rejects mid-path * on every block (does not treat /* in strings as comments)", () => {
    const { diagnostics, rules } = parsePolicy(`path "kv-*/config" {
  capabilities = ["read"]
}
path "foo/*/bar" {
  capabilities = ["read"]
}
path "foo/*/bar/*/baz" {
  capabilities = ["list"]
}
path "ok/*" {
  capabilities = ["read"]
}
`);
    expect(rules.map((r) => r.path)).toEqual([
      "kv-*/config",
      "foo/*/bar",
      "foo/*/bar/*/baz",
      "ok/*",
    ]);
    const stars = diagnostics.filter((d) => d.code === "star_position");
    expect(stars).toHaveLength(3);
    expect(stars.map((d) => d.path)).toEqual([
      "kv-*/config",
      "foo/*/bar",
      "foo/*/bar/*/baz",
    ]);
  });

  it("still strips real /* */ comments outside strings", () => {
    const { rules, diagnostics } = parsePolicy(`/* ignore
this */
path "secret/data/*" {
  capabilities = ["read"]
}
`);
    expect(rules).toHaveLength(1);
    expect(rules[0].path).toBe("secret/data/*");
    expect(diagnostics.filter((d) => d.severity === "error")).toEqual([]);
  });
});

describe("matchPath", () => {
  const rules = parsePolicy(sample).rules;

  it("exact match beats prefix", () => {
    const r = matchPath("secret/data/foo", rules);
    expect(r.allowed).toBe(true);
    expect(r.capabilities).toEqual(["read"]);
    expect(r.winningRule?.path).toBe("secret/data/foo");
  });

  it("prefix glob matches nested paths", () => {
    const r = matchPath("secret/data/bar/baz", rules);
    expect(r.allowed).toBe(true);
    expect(r.capabilities).toContain("create");
    expect(r.winningRule?.path).toBe("secret/data/*");
  });

  it("deny wins on exact path", () => {
    const r = matchPath("secret/data/super-secret", rules);
    expect(r.denied).toBe(true);
    expect(r.winningRule?.path).toBe("secret/data/super-secret");
  });

  it("segment wildcard + matches one segment", () => {
    const r = matchPath("secret/alpha/teamb", rules);
    expect(r.allowed).toBe(true);
    expect(r.winningRule?.path).toBe("secret/+/teamb");
  });

  it("segment wildcard does not match multi-segment", () => {
    const r = matchPath("secret/alpha/beta/teamb", rules);
    expect(r.winningRule?.path).not.toBe("secret/+/teamb");
  });

  it("prefix without slash works (zip-*)", () => {
    const r = matchPath("secret/zip-zap/zong", rules);
    expect(r.allowed).toBe(true);
    expect(r.winningRule?.path).toBe("secret/zip-*");
  });

  it("deny by default", () => {
    const r = matchPath("sys/health", rules);
    expect(r.denied).toBe(true);
    expect(r.winningRule).toBeNull();
  });

  it("strips leading slash and v1/", () => {
    const r = matchPath("/v1/secret/data/foo", rules);
    expect(r.requestPath).toBe("secret/data/foo");
    expect(r.allowed).toBe(true);
  });
});

describe("priority", () => {
  it("later first wildcard wins", () => {
    const mk = (path: string, first: number, wc = 0, prefix = true): MatchCandidate => ({
      rule: { path, matchPath: path, capabilities: ["read"], isPrefix: prefix, hasSegmentWildcards: true, isTemplated: false, line: 1 },
      firstWCOrGlob: first,
      wildcards: wc,
      isPrefix: prefix,
      wcPath: path.replace(/\*$/, ""),
    });
    const a = mk("secret/*", 7);
    const b = mk("secret/data/*", 12);
    expect(isLowerPriority(a, b)).toBe(true);
  });
});

describe("priority integration", () => {
  it("more specific prefix wins over broad prefix", () => {
    const { rules } = parsePolicy(`
path "secret/*" {
  capabilities = ["list"]
}
path "secret/data/*" {
  capabilities = ["read"]
}
`);
    const r = matchPath("secret/data/x", rules);
    expect(r.capabilities).toEqual(["read"]);
    expect(r.winningRule?.path).toBe("secret/data/*");
  });

  it("non-prefix beats prefix at same specificity tier", () => {
    const { rules } = parsePolicy(`
path "secret/+/foo" {
  capabilities = ["read"]
}
path "secret/+/foo/*" {
  capabilities = ["list"]
}
`);
    const r = matchPath("secret/x/foo", rules);
    expect(r.capabilities).toEqual(["read"]);
  });
});
