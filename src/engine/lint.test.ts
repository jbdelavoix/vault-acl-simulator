import { describe, expect, it } from "vitest";
import { parsePolicy } from "./parse";
import { ruleTouchesRootProtected } from "./lint";

describe("sudo / root-protected", () => {
  it("errors on sys/rotate without sudo", () => {
    const { diagnostics } = parsePolicy(`
path "sys/rotate" {
  capabilities = ["create", "read"]
}
`);
    expect(diagnostics.some((d) => d.code === "missing_sudo")).toBe(true);
    expect(diagnostics.some((d) => d.code === "missing_caps")).toBe(true);
  });

  it("ok when sudo + update present", () => {
    const { diagnostics } = parsePolicy(`
path "sys/rotate" {
  capabilities = ["update", "sudo"]
}
`);
    expect(diagnostics.filter((d) => d.severity === "error")).toEqual([]);
    expect(diagnostics.some((d) => d.code === "unused_caps")).toBe(false);
  });

  it("warns on unused capabilities for the endpoint", () => {
    const { diagnostics } = parsePolicy(`
path "sys/rotate" {
  capabilities = ["create", "read", "update", "sudo"]
}
`);
    const unused = diagnostics.find((d) => d.code === "unused_caps");
    expect(unused).toBeTruthy();
    expect(String(unused?.params?.unused)).toMatch(/create/);
    expect(String(unused?.params?.unused)).toMatch(/read/);
  });

  it("errors on sys/* covering root paths without sudo", () => {
    const { diagnostics } = parsePolicy(`
path "sys/*" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.some((d) => d.code === "missing_sudo")).toBe(true);
  });

  it("does not flag secret paths for sudo", () => {
    const { diagnostics } = parsePolicy(`
path "secret/data/foo" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.some((d) => d.code === "missing_sudo")).toBe(false);
  });
});

describe("path shape", () => {
  it("warns on exact trailing slash", () => {
    const { diagnostics } = parsePolicy(`
path "secret/data/foo/" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.some((d) => d.code === "trailing_slash")).toBe(true);
  });

  it("warns on legacy sys/policy paths", () => {
    const { diagnostics } = parsePolicy(`
path "sys/policy/*" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.some((d) => d.code === "legacy_path")).toBe(true);
  });

  it("warns on deprecated gcp token path shape", () => {
    const { diagnostics } = parsePolicy(`
path "gcp/token/my-roleset" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.some((d) => d.code === "deprecated_path")).toBe(true);
  });
});

describe("ruleTouchesRootProtected", () => {
  it("detects exact sys/rotate", () => {
    const hit = ruleTouchesRootProtected({
      path: "sys/rotate",
      matchPath: "sys/rotate",
      capabilities: ["update"],
      isPrefix: false,
      hasSegmentWildcards: false,
      isTemplated: false,
      line: 1,
    });
    expect(hit).toBe("sys/rotate");
  });
});
