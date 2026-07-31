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
    expect(diagnostics.some((d) => d.code === "legacy_path" && d.severity === "info")).toBe(true);
  });

  it("warns on deprecated gcp token path shape", () => {
    const { diagnostics } = parsePolicy(`
path "gcp/token/my-roleset" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.some((d) => d.code === "deprecated_path" && d.severity === "warning")).toBe(
      true,
    );
  });

  it("does not flag auth/token or keymgmt/key as deprecated gcp shapes", () => {
    const { diagnostics } = parsePolicy(`
path "auth/token/create" {
  capabilities = ["update"]
}
path "keymgmt/key/my-key" {
  capabilities = ["read"]
}
`);
    expect(diagnostics.filter((d) => d.code === "deprecated_path")).toEqual([]);
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

  it("detects concrete paths under a root wildcard (sys/raw/foo)", () => {
    const hit = ruleTouchesRootProtected({
      path: "sys/raw/foo",
      matchPath: "sys/raw/foo",
      capabilities: ["read"],
      isPrefix: false,
      hasSegmentWildcards: false,
      isTemplated: false,
      line: 1,
    });
    expect(hit).toBe("sys/raw/*");
  });

  it("flags missing_sudo on every concrete root child", () => {
    const { diagnostics } = parsePolicy(`
path "sys/raw/a" { capabilities = ["read"] }
path "sys/raw/b" { capabilities = ["read"] }
path "sys/auth/approle" { capabilities = ["read"] }
`);
    const sudo = diagnostics.filter((d) => d.code === "missing_sudo");
    expect(sudo.map((d) => d.path).sort()).toEqual([
      "sys/auth/approle",
      "sys/raw/a",
      "sys/raw/b",
    ]);
  });
});
