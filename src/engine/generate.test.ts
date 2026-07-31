import { describe, expect, it } from "vitest";
import { buildEngineRules, ENGINES, SYS_ENDPOINTS, getSysEndpoint } from "./generate";
import { parsePolicy } from "./parse";

describe("generator catalog", () => {
  it("covers builtin secrets + auth kinds", () => {
    const kinds = new Set(ENGINES.map((e) => e.kind));
    expect(kinds.has("secrets")).toBe(true);
    expect(kinds.has("auth")).toBe(true);
    expect(kinds.has("system")).toBe(true);
    expect(ENGINES.some((e) => e.id === "approle")).toBe(true);
    expect(ENGINES.some((e) => e.id === "ssh")).toBe(true);
    expect(ENGINES.some((e) => e.id === "totp")).toBe(true);
  });

  it("exposes a curated sys endpoint catalog", () => {
    expect(SYS_ENDPOINTS.length).toBeGreaterThan(80);
    expect(SYS_ENDPOINTS.some((e) => e.path === "sys/rotate" && e.root)).toBe(true);
    expect(SYS_ENDPOINTS.some((e) => e.path.startsWith("identity/") && e.group === "identity")).toBe(
      true,
    );
    expect(SYS_ENDPOINTS.some((e) => e.path.includes("replication/dr") && e.enterprise)).toBe(true);
    expect(SYS_ENDPOINTS.some((e) => e.path === "sys/policies/rgp/*" && e.enterprise)).toBe(true);
    expect(SYS_ENDPOINTS.some((e) => e.id === "custom")).toBe(true);
  });

  it("builds multiple sys endpoints at once", () => {
    const rules = buildEngineRules({
      engine: "sys",
      mount: "sys",
      secretPath: "",
      access: "read",
      scope: "exact",
      sysEndpointIds: ["health", "leader", "policies-acl"],
    });
    expect(rules.map((r) => r.path)).toEqual([
      "sys/health",
      "sys/leader",
      "sys/policies/acl",
    ]);
  });

  it("builds sys/rotate with sudo", () => {
    const rules = buildEngineRules({
      engine: "sys",
      mount: "sys",
      secretPath: "",
      access: "write",
      scope: "exact",
      sysEndpointId: "rotate",
    });
    expect(rules).toHaveLength(1);
    expect(rules[0].path).toBe("sys/rotate");
    expect(rules[0].capabilities).toEqual(expect.arrayContaining(["update", "sudo"]));
  });

  it("builds identity paths without sys/ prefix", () => {
    const rules = buildEngineRules({
      engine: "sys",
      mount: "sys",
      secretPath: "",
      access: "read",
      scope: "exact",
      sysEndpointId: "identity-entity-id",
    });
    expect(rules[0].path).toBe("identity/entity/id/*");
  });

  it("builds approle login under auth/", () => {
    const rules = buildEngineRules({
      engine: "approle",
      mount: "approle",
      secretPath: "ci",
      access: "read",
      scope: "exact",
    });
    expect(rules.some((r) => r.path === "auth/approle/login")).toBe(true);
  });

  it("builds all roles with resourceMode=all", () => {
    const rules = buildEngineRules({
      engine: "database",
      mount: "database",
      secretPath: "ignored",
      access: "write",
      scope: "exact",
      resourceMode: "all",
    });
    expect(rules.map((r) => r.path)).toEqual(
      expect.arrayContaining([
        "database/config/*",
        "database/roles/*",
        "database/static-roles/*",
        "database/creds/*",
        "database/static-creds/*",
      ]),
    );
  });

  it("includes ldap secrets config on write", () => {
    const rules = buildEngineRules({
      engine: "ldap_secrets",
      mount: "ldap",
      secretPath: "svc",
      access: "write",
      scope: "exact",
      resourceMode: "named",
    });
    expect(rules.map((r) => r.path)).toEqual(
      expect.arrayContaining([
        "ldap/config",
        "ldap/static-role/svc",
        "ldap/role/svc",
        "ldap/library/svc",
        "ldap/static-cred/svc",
        "ldap/creds/svc",
      ]),
    );
  });

  it("includes auth method config on write", () => {
    const cases: Array<{ engine: "ldap" | "jwt" | "kubernetes_auth" | "github"; mount: string; config: string }> = [
      { engine: "ldap", mount: "ldap", config: "auth/ldap/config" },
      { engine: "jwt", mount: "jwt", config: "auth/jwt/config" },
      { engine: "kubernetes_auth", mount: "kubernetes", config: "auth/kubernetes/config" },
      { engine: "github", mount: "github", config: "auth/github/config" },
    ];
    for (const c of cases) {
      const rules = buildEngineRules({
        engine: c.engine,
        mount: c.mount,
        secretPath: "x",
        access: "write",
        scope: "exact",
        resourceMode: "named",
      });
      expect(rules.map((r) => r.path), c.engine).toEqual(expect.arrayContaining([c.config]));
    }
  });

  it("builds a dedicated approle role", () => {
    const rules = buildEngineRules({
      engine: "approle",
      mount: "approle",
      secretPath: "ci",
      access: "write",
      scope: "exact",
      resourceMode: "named",
    });
    expect(rules.map((r) => r.path)).toEqual(
      expect.arrayContaining(["auth/approle/role/ci", "auth/approle/login"]),
    );
  });

  it("builds ldap secrets static-cred + dynamic creds", () => {
    const rules = buildEngineRules({
      engine: "ldap_secrets",
      mount: "ldap",
      secretPath: "svc",
      access: "read",
      scope: "exact",
      resourceMode: "named",
    });
    expect(rules.map((r) => r.path)).toEqual(
      expect.arrayContaining(["ldap/static-cred/svc", "ldap/creds/svc"]),
    );
  });

  it("builds kubernetes secrets creds", () => {
    const rules = buildEngineRules({
      engine: "kubernetes",
      mount: "kubernetes",
      secretPath: "ci",
      access: "write",
      scope: "exact",
      resourceMode: "named",
    });
    expect(rules.map((r) => r.path)).toEqual(
      expect.arrayContaining(["kubernetes/roles/ci", "kubernetes/creds/ci"]),
    );
  });

  it("builds kubernetes auth login", () => {
    const rules = buildEngineRules({
      engine: "kubernetes_auth",
      mount: "kubernetes",
      secretPath: "default",
      access: "read",
      scope: "exact",
    });
    expect(rules.some((r) => r.path === "auth/kubernetes/login")).toBe(true);
  });

  it("marks transform and kmip as enterprise engines", () => {
    expect(ENGINES.find((e) => e.id === "transform")?.enterprise).toBe(true);
    expect(ENGINES.find((e) => e.id === "kmip")?.enterprise).toBe(true);
    expect(ENGINES.find((e) => e.id === "saml")?.enterprise).toBe(true);
    expect(ENGINES.find((e) => e.id === "keymgmt")?.enterprise).toBe(true);
  });

  it("uses singular role for alicloud and nomad (api-docs)", () => {
    for (const engine of ["alicloud", "nomad"] as const) {
      const rules = buildEngineRules({
        engine,
        mount: engine,
        secretPath: "app",
        access: "write",
        scope: "exact",
      });
      expect(rules.map((r) => r.path)).toEqual(
        expect.arrayContaining([`${engine}/role/app`, `${engine}/creds/app`]),
      );
      expect(rules.some((r) => r.path.includes("/roles/"))).toBe(false);
    }
  });

  it("covers new secrets/auth from api-docs", () => {
    expect(ENGINES.some((e) => e.id === "mongodbatlas")).toBe(true);
    expect(ENGINES.some((e) => e.id === "gcpkms")).toBe(true);
    expect(ENGINES.some((e) => e.id === "azure_auth")).toBe(true);
    expect(ENGINES.some((e) => e.id === "scep")).toBe(true);
    const atlas = buildEngineRules({
      engine: "mongodbatlas",
      mount: "mongodbatlas",
      secretPath: "r",
      access: "write",
      scope: "exact",
    });
    expect(atlas.map((r) => r.path)).toEqual(
      expect.arrayContaining(["mongodbatlas/roles/r", "mongodbatlas/creds/r"]),
    );
    const approle = buildEngineRules({
      engine: "approle",
      mount: "approle",
      secretPath: "ci",
      access: "write",
      scope: "exact",
    });
    expect(approle.some((r) => r.path === "auth/approle/role/ci/secret-id")).toBe(true);
    expect(SYS_ENDPOINTS.some((e) => e.id === "identity-scim")).toBe(true);
    expect(getSysEndpoint("internal-counters").doc.toLowerCase()).toContain("client");
    expect(getSysEndpoint("policy").doc).toMatch(/ACL/i);
    expect(getSysEndpoint("policy").doc).not.toMatch(/Sentinel RGP\/EGP are managed here/i);
    expect(getSysEndpoint("policy").doc).toMatch(/not Sentinel RGP\/EGP/i);
    expect(getSysEndpoint("policy").legacy).toBe(true);
    expect(getSysEndpoint("identity-scim").beta).toBe(true);
    expect(getSysEndpoint("identity-scim").enterprise).toBe(true);
    expect(SYS_ENDPOINTS.every((e) => e.doc.trim().split("\n").length >= 3)).toBe(true);
  });

  it("emits no parse errors/warnings for representative engines", () => {
    const samples: Array<Parameters<typeof buildEngineRules>[0]> = [
      { engine: "kv2", mount: "secret", secretPath: "apps/x", access: "write", scope: "prefix" },
      { engine: "gcp", mount: "gcp", secretPath: "my-roleset", access: "read", scope: "prefix", resourceMode: "named" },
      { engine: "gcp", mount: "gcp", secretPath: "x", access: "read", scope: "exact", resourceMode: "all" },
      { engine: "gcp", mount: "gcp", secretPath: "my-roleset", access: "write", scope: "prefix" },
      { engine: "approle", mount: "approle", secretPath: "ci", access: "write", scope: "prefix" },
      { engine: "approle", mount: "approle", secretPath: "ci", access: "write", scope: "exact" },
      { engine: "kmip", mount: "kmip", secretPath: "scope1", access: "read", scope: "exact" },
      { engine: "spiffe", mount: "spiffe", secretPath: "role1", access: "read", scope: "prefix" },
      { engine: "token", mount: "token", secretPath: "create", access: "write", scope: "exact" },
      { engine: "sys", mount: "sys", secretPath: "", access: "write", scope: "exact", sysEndpointIds: ["rotate", "mounts-path", "auth-manage", "policy"] },
    ];
    for (const input of samples) {
      const rules = buildEngineRules(input);
      const hcl = rules
        .map(
          (r) =>
            `path "${r.path}" {\n  capabilities = [${r.capabilities.map((c) => `"${c}"`).join(", ")}]\n}\n`,
        )
        .join("\n");
      const { diagnostics } = parsePolicy(hcl);
      const bad = diagnostics.filter((d) => d.severity === "error" || d.severity === "warning");
      expect(bad, `${input.engine}: ${bad.map((d) => `${d.code}:${d.path}`).join(", ")}`).toEqual([]);
    }
  });

  it("uses + not mid-path * for gcp / kmip / spiffe / approle all-resources", () => {
    const gcp = buildEngineRules({
      engine: "gcp",
      mount: "gcp",
      secretPath: "x",
      access: "read",
      scope: "exact",
      resourceMode: "all",
    });
    expect(gcp.map((r) => r.path)).toEqual(["gcp/roleset/+/token", "gcp/roleset/+/key"]);
    const kmip = buildEngineRules({
      engine: "kmip",
      mount: "kmip",
      secretPath: "x",
      access: "read",
      scope: "exact",
      resourceMode: "all",
    });
    expect(kmip[0].path).toBe("kmip/scope/+/role/+/credential/*");
    const spiffe = buildEngineRules({
      engine: "spiffe",
      mount: "spiffe",
      secretPath: "x",
      access: "read",
      scope: "exact",
      resourceMode: "all",
    });
    expect(spiffe[0].path).toBe("spiffe/role/+/mintjwt");
  });
});
