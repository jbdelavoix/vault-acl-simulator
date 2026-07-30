import { t } from "../i18n";
import type { Capability } from "./types";
import { VALID_CAPABILITIES } from "./types";
import {
  getEngine,
  getSysEndpoint,
  type EngineId,
  type SysEndpoint,
} from "./catalog";

export type { EngineId, EngineKind, EngineDef, SysEndpoint, SysEndpointGroup, ResourceKind } from "./catalog";
export {
  ENGINES,
  SECRET_ENGINES,
  SYS_ENDPOINTS,
  SYS_ENDPOINT_GROUPS,
  getEngine,
  getSysEndpoint,
  enginesByKind,
} from "./catalog";

export interface GeneratorRule {
  path: string;
  capabilities: Capability[];
  comment?: string;
}

export const GENERATOR_CAPABILITIES: Capability[] = VALID_CAPABILITIES.filter(
  (c) => c !== "subscribe" && c !== "recover",
) as Capability[];

export const CAP_PRESETS: Record<string, Capability[]> = {
  read: ["read", "list"],
  write: ["create", "read", "update", "patch", "delete", "list"],
  deny: ["deny"],
  rotate: ["update", "sudo"],
};

export type AccessLevel = "read" | "write" | "deny" | "custom";

/** All resources (*) vs one dedicated name (role, group, path…). */
export type ResourceMode = "all" | "named";

function joinMount(mount: string, ...parts: string[]): string {
  const m = mount.replace(/^\/+|\/+$/g, "");
  const rest = parts
    .map((p) => p.replace(/^\/+|\/+$/g, ""))
    .filter(Boolean)
    .join("/");
  return rest ? `${m}/${rest}` : m;
}

function withGlob(base: string, scope: "exact" | "prefix"): string {
  if (scope === "exact") return base.replace(/\/\*$/, "").replace(/\/$/, "");
  const clean = base.replace(/\/\*$/, "").replace(/\/$/, "");
  return `${clean}/*`;
}

function authMount(mount: string): string {
  const m = mount.replace(/^\/+|\/+$/g, "");
  return m.startsWith("auth/") ? m : `auth/${m}`;
}

/** Mount-level config path (…/config or …/config/*). Included on write/admin. */
function configRule(mount: string, suffix = "config"): GeneratorRule {
  return {
    path: joinMount(mount, ...suffix.split("/")),
    capabilities: ["create", "read", "update", "delete"],
    comment: t("comment.config"),
  };
}

function withConfig(rules: GeneratorRule[], mount: string, suffix = "config"): GeneratorRule[] {
  return [configRule(mount, suffix), ...rules];
}

function defaultCaps(access: AccessLevel, custom?: Capability[]): Capability[] {
  if (access === "custom") return custom ?? [];
  if (access === "deny") return ["deny"];
  if (access === "read") return ["read", "list"];
  return ["create", "read", "update", "patch", "delete", "list"];
}

/** Resolve the typed name: All → `*`, else cleaned input (fallback `*`). */
export function resolveResourceName(secretPath: string, mode: ResourceMode): string {
  if (mode === "all") return "*";
  const clean = secretPath
    .trim()
    .replace(/^\/+/, "")
    .replace(/\/\*$/, "")
    .replace(/\/$/, "");
  return clean || "*";
}

/**
 * `mount/sub/name`, `mount/sub/name/*`, or `mount/sub/*` when name is `*`.
 */
function under(
  mount: string,
  sub: string,
  name: string,
  scope: "exact" | "prefix",
): string {
  const base = joinMount(mount, sub);
  if (!name || name === "*") return `${base}/*`;
  return withGlob(joinMount(base, name), scope);
}

/** Path directly under mount (KV v1 / cubbyhole / custom). */
function underRoot(mount: string, name: string, scope: "exact" | "prefix"): string {
  if (!name || name === "*") {
    const m = mount.replace(/^\/+|\/+$/g, "");
    return m ? `${m}/*` : "*";
  }
  return withGlob(joinMount(mount, name), scope);
}

function simpleCreds(
  mount: string,
  name: string,
  scope: "exact" | "prefix",
  caps: Capability[],
  comment: string,
): GeneratorRule[] {
  return [{ path: under(mount, "creds", name, scope), capabilities: caps, comment }];
}

export interface BuildEnginePathsInput {
  engine: EngineId;
  mount: string;
  secretPath: string;
  access: AccessLevel;
  scope: "exact" | "prefix";
  /** All (*) vs one dedicated resource name. Default named. */
  resourceMode?: ResourceMode;
  customCapabilities?: Capability[];
  /** Selected sys endpoint id when engine === "sys" (single; prefer sysEndpointIds). */
  sysEndpointId?: string;
  /** Selected sys endpoint ids when engine === "sys" (multi-select). */
  sysEndpointIds?: string[];
}

function sysCapsFor(ep: SysEndpoint, access: AccessLevel, custom?: Capability[]): Capability[] {
  if (access === "deny") return ["deny"];
  if (access === "custom") return custom ?? [];
  if (access === "read") return [...ep.read];
  return [...ep.write];
}

/**
 * Capabilities that make sense for the generator’s current engine / sys endpoint.
 * Used to dim irrelevant checkboxes in Custom mode.
 */
export function relevantCapabilitiesForGenerator(input: {
  engine: EngineId;
  mount?: string;
  sysEndpointId?: string;
  sysEndpointIds?: string[];
}): Set<Capability> {
  const useful = new Set<Capability>(["deny"]);
  if (input.engine === "sys") {
    const ids =
      input.sysEndpointIds?.length
        ? input.sysEndpointIds
        : [input.sysEndpointId ?? "custom"];
    for (const id of ids) {
      const ep = getSysEndpoint(id);
      for (const c of ep.read) useful.add(c);
      for (const c of ep.write) useful.add(c);
      if (ep.root) useful.add("sudo");
      if (ep.id === "custom") {
        for (const c of GENERATOR_CAPABILITIES) useful.add(c);
      }
    }
    return useful;
  }

  const eng = getEngine(input.engine);
  const mount = (input.mount || eng.defaultMount).replace(/^\/+|\/+$/g, "");
  for (const access of ["read", "write"] as const) {
    const rules = buildEngineRules({
      engine: input.engine,
      mount,
      secretPath: eng.secretPlaceholder || "x",
      access,
      scope: "exact",
      resourceMode: eng.resourceKind === "none" ? "named" : "all",
    });
    for (const r of rules) for (const c of r.capabilities) useful.add(c);
  }
  return useful;
}

/** Build one or more path rules for the selected engine + access level. */
export function buildEngineRules(input: BuildEnginePathsInput): GeneratorRule[] {
  const mount = (input.mount || getEngine(input.engine).defaultMount).replace(/^\/+|\/+$/g, "");
  const mode = input.resourceMode ?? "named";
  const name = resolveResourceName(input.secretPath, mode);
  const secret = name; // alias used in some branches
  const caps = defaultCaps(input.access, input.customCapabilities);

  if (input.access === "custom" && caps.length === 0) return [];

  switch (input.engine) {
    case "kv2": {
      const data = under(mount, "data", name, input.scope);
      const meta = under(mount, "metadata", name, input.scope);
      if (input.access === "deny") {
        return [
          { path: data, capabilities: ["deny"], comment: t("comment.kv2.dataShort") },
          { path: meta, capabilities: ["deny"], comment: t("comment.kv2.metaShort") },
        ];
      }
      if (input.access === "read") {
        return [
          { path: data, capabilities: ["read"], comment: t("comment.kv2.data") },
          {
            path: meta,
            capabilities: ["list", "read"],
            comment: t("comment.kv2.meta"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: data,
            capabilities: ["create", "read", "update", "patch", "delete"],
            comment: t("comment.kv2.dataWrite"),
          },
          {
            path: meta,
            capabilities: ["list", "read", "delete"],
            comment: t("comment.kv2.metaWrite"),
          },
        ];
      }
      return [
        { path: data, capabilities: caps, comment: t("comment.kv2.dataShort") },
        { path: meta, capabilities: caps, comment: t("comment.kv2.metaShort") },
      ];
    }
    case "kv1": {
      return [{ path: underRoot(mount, name, input.scope), capabilities: caps, comment: t("comment.kv1") }];
    }
    case "database": {
      const credsPath = under(mount, "creds", name, input.scope);
      const staticCredsPath = under(mount, "static-creds", name, input.scope);
      const rolesPath = under(mount, "roles", name, input.scope);
      const staticRolesPath = under(mount, "static-roles", name, input.scope);
      if (input.access === "read") {
        return [
          { path: credsPath, capabilities: ["read"], comment: t("comment.db.creds") },
          { path: staticCredsPath, capabilities: ["read"], comment: t("comment.db.staticCreds") },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: rolesPath,
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.db.roles"),
            },
            {
              path: staticRolesPath,
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.db.staticRoles"),
            },
            { path: credsPath, capabilities: ["read"], comment: t("comment.db.gen") },
            { path: staticCredsPath, capabilities: ["read"], comment: t("comment.db.staticCreds") },
          ],
          mount,
          "config/*",
        );
      }
      return [{ path: credsPath, capabilities: caps, comment: t("comment.db") }];
    }
    case "pki": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "cert", name === "*" ? "*" : name, input.scope),
            capabilities: ["read", "list"],
            comment: t("comment.pki.read"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "issue", name, input.scope),
              capabilities: ["create", "update"],
              comment: t("comment.pki.issue"),
            },
            {
              path: under(mount, "sign", name, input.scope),
              capabilities: ["create", "update"],
              comment: t("comment.pki.sign"),
            },
            {
              path: under(mount, "roles", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.pki.roles"),
            },
          ],
          mount,
          "config/*",
        );
      }
      return [
        {
          path: under(mount, "issue", name, input.scope),
          capabilities: caps,
          comment: t("comment.pki"),
        },
      ];
    }
    case "transit": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "keys", name, input.scope),
            capabilities: ["read", "list"],
            comment: t("comment.transit.read"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: under(mount, "encrypt", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.transit.encrypt"),
          },
          {
            path: under(mount, "decrypt", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.transit.decrypt"),
          },
          {
            path: under(mount, "keys", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.transit.keys"),
          },
        ];
      }
      return [
        {
          path: under(mount, "encrypt", name, input.scope),
          capabilities: caps,
          comment: t("comment.transit"),
        },
      ];
    }
    case "aws":
    case "azure":
    case "rabbitmq":
    case "consul": {
      // Docs use …/roles/:name (plural). AliCloud / Nomad use …/role/:name — see below.
      const commentKey =
        input.engine === "aws"
          ? "comment.aws"
          : input.engine === "azure"
            ? "comment.azure"
            : input.engine === "rabbitmq"
              ? "comment.rabbitmq"
              : "comment.consul";
      const configSuffix =
        input.engine === "aws" || input.engine === "rabbitmq"
          ? "config/*"
          : input.engine === "consul"
            ? "config/access"
            : "config";
      const useCaps =
        input.access === "deny"
          ? (["deny"] as Capability[])
          : input.access === "write" || input.access === "read"
            ? (["read"] as Capability[])
            : caps.includes("deny")
              ? caps
              : caps.length
                ? caps
                : (["read"] as Capability[]);
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "roles", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t(`${commentKey}.roles`),
            },
            {
              path: under(mount, "creds", name, input.scope),
              capabilities: ["read"],
              comment: t(commentKey),
            },
          ],
          mount,
          configSuffix,
        );
      }
      return simpleCreds(mount, name, input.scope, useCaps, t(commentKey));
    }
    case "alicloud":
    case "nomad": {
      // api-docs: /alicloud/role/:name and /nomad/role/:name (singular)
      const commentKey = input.engine === "alicloud" ? "comment.alicloud" : "comment.nomad";
      const configSuffix = input.engine === "nomad" ? "config/*" : "config";
      const useCaps =
        input.access === "deny"
          ? (["deny"] as Capability[])
          : input.access === "write" || input.access === "read"
            ? (["read"] as Capability[])
            : caps.includes("deny")
              ? caps
              : caps.length
                ? caps
                : (["read"] as Capability[]);
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "role", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t(`${commentKey}.roles`),
            },
            {
              path: under(mount, "creds", name, input.scope),
              capabilities: ["read"],
              comment: t(commentKey),
            },
          ],
          mount,
          configSuffix,
        );
      }
      return simpleCreds(mount, name, input.scope, useCaps, t(commentKey));
    }
    case "gcp": {
      if (input.access === "read") {
        const tokenPath =
          name === "*"
            ? joinMount(mount, "roleset", "*", "token")
            : input.scope === "prefix"
              ? joinMount(mount, "roleset", `${name}/*`, "token")
              : joinMount(mount, "roleset", name, "token");
        const keyPath =
          name === "*"
            ? joinMount(mount, "roleset", "*", "key")
            : input.scope === "prefix"
              ? joinMount(mount, "roleset", `${name}/*`, "key")
              : joinMount(mount, "roleset", name, "key");
        return [
          { path: tokenPath, capabilities: ["read"], comment: t("comment.gcp.token") },
          { path: keyPath, capabilities: ["read"], comment: t("comment.gcp.key") },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "roleset", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.gcp.roleset"),
            },
            {
              path:
                name === "*"
                  ? joinMount(mount, "roleset", "*", "token")
                  : joinMount(mount, "roleset", name, "token"),
              capabilities: ["read"],
              comment: t("comment.gcp.token"),
            },
            {
              path:
                name === "*"
                  ? joinMount(mount, "roleset", "*", "key")
                  : joinMount(mount, "roleset", name, "key"),
              capabilities: ["read"],
              comment: t("comment.gcp.key"),
            },
          ],
          mount,
        );
      }
      return simpleCreds(mount, name, input.scope, caps, t("comment.gcp"));
    }
    case "ssh": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["create", "update"],
            comment: t("comment.ssh.creds"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "roles", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.ssh.roles"),
            },
            {
              path: under(mount, "sign", name, input.scope),
              capabilities: ["create", "update"],
              comment: t("comment.ssh.sign"),
            },
            {
              path: under(mount, "creds", name, input.scope),
              capabilities: ["create", "update"],
              comment: t("comment.ssh.creds"),
            },
          ],
          mount,
          "config/ca",
        );
      }
      return [
        {
          path: under(mount, "creds", name, input.scope),
          capabilities: caps,
          comment: t("comment.ssh"),
        },
      ];
    }
    case "totp": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "code", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.totp.code"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: under(mount, "keys", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.totp.keys"),
          },
          {
            path: under(mount, "code", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.totp.code"),
          },
        ];
      }
      return [
        {
          path: under(mount, "keys", name, input.scope),
          capabilities: caps,
          comment: t("comment.totp"),
        },
      ];
    }
    case "ldap_secrets": {
      // Secrets engine (OpenLDAP / AD / RACF) — distinct from auth/ldap
      if (input.access === "read") {
        return [
          {
            path: under(mount, "static-cred", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.ldap_secrets.staticCred"),
          },
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.ldap_secrets.creds"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "static-role", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.ldap_secrets.staticRole"),
            },
            {
              path: under(mount, "role", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.ldap_secrets.role"),
            },
            {
              path: under(mount, "library", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.ldap_secrets.library"),
            },
            {
              path: under(mount, "static-cred", name, input.scope),
              capabilities: ["read"],
              comment: t("comment.ldap_secrets.staticCred"),
            },
            {
              path: under(mount, "creds", name, input.scope),
              capabilities: ["read"],
              comment: t("comment.ldap_secrets.creds"),
            },
          ],
          mount,
        );
      }
      return [
        {
          path: under(mount, "static-cred", name, input.scope),
          capabilities: caps,
          comment: t("comment.ldap_secrets"),
        },
      ];
    }
    case "kubernetes": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["create", "update"],
            comment: t("comment.kubernetes.creds"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(mount, "roles", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.kubernetes.roles"),
          },
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["create", "update"],
            comment: t("comment.kubernetes.creds"),
          },
        ], mount);
      }
      return [
        {
          path: under(mount, "creds", name, input.scope),
          capabilities: caps,
          comment: t("comment.kubernetes"),
        },
      ];
    }
    case "terraform": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.terraform.creds"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(mount, "role", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.terraform.role"),
          },
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.terraform.creds"),
          },
        ], mount);
      }
      return [
        {
          path: under(mount, "creds", name, input.scope),
          capabilities: caps,
          comment: t("comment.terraform"),
        },
      ];
    }
    case "mongodbatlas": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "creds", name, input.scope),
            capabilities: ["read"],
            comment: t("comment.mongodbatlas.creds"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "roles", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.mongodbatlas.roles"),
            },
            {
              path: under(mount, "creds", name, input.scope),
              capabilities: ["read"],
              comment: t("comment.mongodbatlas.creds"),
            },
          ],
          mount,
        );
      }
      return [
        {
          path: under(mount, "creds", name, input.scope),
          capabilities: caps,
          comment: t("comment.mongodbatlas"),
        },
      ];
    }
    case "gcpkms": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "encrypt", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.gcpkms.encrypt"),
          },
          {
            path: under(mount, "decrypt", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.gcpkms.decrypt"),
          },
          {
            path: under(mount, "sign", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.gcpkms.sign"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "keys", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.gcpkms.keys"),
            },
            {
              path: under(mount, "encrypt", name, input.scope),
              capabilities: ["update"],
              comment: t("comment.gcpkms.encrypt"),
            },
            {
              path: under(mount, "decrypt", name, input.scope),
              capabilities: ["update"],
              comment: t("comment.gcpkms.decrypt"),
            },
          ],
          mount,
        );
      }
      return [
        {
          path: under(mount, "encrypt", name, input.scope),
          capabilities: caps,
          comment: t("comment.gcpkms"),
        },
      ];
    }
    case "keymgmt": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "key", name, input.scope),
            capabilities: ["read", "list"],
            comment: t("comment.keymgmt.key"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: under(mount, "key", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.keymgmt.key"),
          },
          {
            path: under(mount, "kms", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.keymgmt.kms"),
          },
        ];
      }
      return [
        {
          path: under(mount, "key", name, input.scope),
          capabilities: caps,
          comment: t("comment.keymgmt"),
        },
      ];
    }
    case "spiffe": {
      if (input.access === "read") {
        return [
          {
            path:
              name === "*"
                ? joinMount(mount, "role", "*", "mintjwt")
                : input.scope === "prefix"
                  ? joinMount(mount, "role", `${name}/*`, "mintjwt")
                  : joinMount(mount, "role", name, "mintjwt"),
            capabilities: ["update"],
            comment: t("comment.spiffe.mint"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(mount, "role", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.spiffe.role"),
            },
            {
              path:
                name === "*"
                  ? joinMount(mount, "role", "*", "mintjwt")
                  : joinMount(mount, "role", name, "mintjwt"),
              capabilities: ["update"],
              comment: t("comment.spiffe.mint"),
            },
          ],
          mount,
        );
      }
      return [
        {
          path: under(mount, "role", name, input.scope),
          capabilities: caps,
          comment: t("comment.spiffe"),
        },
      ];
    }
    case "transform": {
      if (input.access === "read") {
        return [
          {
            path: under(mount, "encode", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.transform.encode"),
          },
          {
            path: under(mount, "decode", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.transform.decode"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: under(mount, "role", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.transform.role"),
          },
          {
            path: under(mount, "transformation", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.transform.transformation"),
          },
          {
            path: under(mount, "encode", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.transform.encode"),
          },
          {
            path: under(mount, "decode", name, input.scope),
            capabilities: ["update"],
            comment: t("comment.transform.decode"),
          },
        ];
      }
      return [
        {
          path: under(mount, "encode", name, input.scope),
          capabilities: caps,
          comment: t("comment.transform"),
        },
      ];
    }
    case "kmip": {
      // name = scope; roles under scope when write
      const scopePath = under(mount, "scope", name, input.scope);
      if (input.access === "read") {
        return [
          {
            path:
              name === "*"
                ? `${joinMount(mount, "scope")}/*/role/*/credential/*`
                : `${joinMount(mount, "scope", name)}/role/*/credential/*`,
            capabilities: ["create", "read", "update"],
            comment: t("comment.kmip.creds"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: scopePath,
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.kmip.scope"),
          },
          {
            path:
              name === "*"
                ? `${joinMount(mount, "scope")}/*/role/*`
                : `${joinMount(mount, "scope", name)}/role/*`,
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.kmip.role"),
          },
        ];
      }
      return [{ path: scopePath, capabilities: caps, comment: t("comment.kmip") }];
    }
    case "cubbyhole": {
      return [
        {
          path: underRoot("cubbyhole", name, input.scope),
          capabilities: caps,
          comment: t("comment.cubbyhole"),
        },
      ];
    }

    // ——— Auth methods (mounted under auth/<mount>/) ———
    case "approle": {
      const m = authMount(mount);
      const secretIdPath =
        name === "*"
          ? `${joinMount(m, "role")}/*/secret-id`
          : `${under(m, "role", name, input.scope)}/secret-id`;
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.approle.login"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: under(m, "role", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.approle.role"),
          },
          {
            path: secretIdPath,
            capabilities: ["create", "read", "update", "list"],
            comment: t("comment.approle.secretId"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.approle.login"),
          },
        ];
      }
      return [
        {
          path: under(m, "role", name, input.scope),
          capabilities: caps,
          comment: t("comment.approle"),
        },
      ];
    }
    case "userpass": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: under(m, "login", name, input.scope),
            capabilities: ["create", "update"],
            comment: t("comment.userpass.login"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: under(m, "users", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.userpass.users"),
          },
        ];
      }
      return [
        {
          path: under(m, "users", name, input.scope),
          capabilities: caps,
          comment: t("comment.userpass"),
        },
      ];
    }
    case "ldap":
    case "okta": {
      const m = authMount(mount);
      const commentLogin = input.engine === "ldap" ? "comment.ldap.login" : "comment.okta.login";
      const commentUsers = input.engine === "ldap" ? "comment.ldap.users" : "comment.okta.users";
      const commentBase = input.engine === "ldap" ? "comment.ldap" : "comment.okta";
      if (input.access === "read") {
        return [
          {
            path: under(m, "login", name, input.scope),
            capabilities: ["create", "update"],
            comment: t(commentLogin),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "users", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t(commentUsers),
          },
          {
            path: under(m, "groups", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t(commentUsers),
          },
          {
            path: under(m, "login", name, input.scope),
            capabilities: ["create", "update"],
            comment: t(commentLogin),
          },
        ], m);
      }
      return [
        {
          path: under(m, "users", name, input.scope),
          capabilities: caps,
          comment: t(commentBase),
        },
      ];
    }
    case "jwt":
    case "oidc": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.jwt.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "role", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.jwt.role"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.jwt.login"),
          },
        ], m);
      }
      return [
        {
          path: under(m, "role", name, input.scope),
          capabilities: caps,
          comment: t("comment.jwt"),
        },
      ];
    }
    case "github": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.github.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "map/teams", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.github.map"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.github.login"),
          },
        ], m);
      }
      return [
        {
          path: joinMount(m, "login"),
          capabilities: caps,
          comment: t("comment.github"),
        },
      ];
    }
    case "cert": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.cert.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "certs", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.cert.certs"),
          },
        ], m);
      }
      return [
        {
          path: under(m, "certs", name, input.scope),
          capabilities: caps,
          comment: t("comment.cert"),
        },
      ];
    }
    case "aws_auth":
    case "azure_auth":
    case "gcp_auth":
    case "alicloud_auth":
    case "scep":
    case "spiffe_auth": {
      const m = authMount(mount);
      const commentBase =
        input.engine === "aws_auth"
          ? "comment.aws_auth"
          : input.engine === "azure_auth"
            ? "comment.azure_auth"
            : input.engine === "gcp_auth"
              ? "comment.gcp_auth"
              : input.engine === "alicloud_auth"
                ? "comment.alicloud_auth"
                : input.engine === "scep"
                  ? "comment.scep"
                  : "comment.spiffe_auth";
      const configSuffix =
        input.engine === "aws_auth" || input.engine === "gcp_auth" ? "config/*" : "config";
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t(`${commentBase}.login`),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(m, "role", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t(`${commentBase}.role`),
            },
            {
              path: joinMount(m, "login"),
              capabilities: ["create", "update"],
              comment: t(`${commentBase}.login`),
            },
          ],
          m,
          configSuffix,
        );
      }
      return [
        {
          path: under(m, "role", name, input.scope),
          capabilities: caps,
          comment: t(commentBase),
        },
      ];
    }
    case "oci": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: under(m, "login", name, input.scope),
            capabilities: ["create", "update"],
            comment: t("comment.oci.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig(
          [
            {
              path: under(m, "role", name, input.scope),
              capabilities: ["create", "read", "update", "delete", "list"],
              comment: t("comment.oci.role"),
            },
            {
              path: under(m, "login", name, input.scope),
              capabilities: ["create", "update"],
              comment: t("comment.oci.login"),
            },
          ],
          m,
        );
      }
      return [
        {
          path: under(m, "role", name, input.scope),
          capabilities: caps,
          comment: t("comment.oci"),
        },
      ];
    }
    case "kubernetes_auth": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.kubernetes_auth.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "role", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.kubernetes_auth.role"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.kubernetes_auth.login"),
          },
        ], m);
      }
      return [
        {
          path: under(m, "role", name, input.scope),
          capabilities: caps,
          comment: t("comment.kubernetes_auth"),
        },
      ];
    }
    case "kerberos": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.kerberos.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "groups", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.kerberos.groups"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.kerberos.login"),
          },
        ], m);
      }
      return [
        {
          path: under(m, "groups", name, input.scope),
          capabilities: caps,
          comment: t("comment.kerberos"),
        },
      ];
    }
    case "saml": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.saml.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "role", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.saml.role"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.saml.login"),
          },
        ], m);
      }
      return [
        {
          path: under(m, "role", name, input.scope),
          capabilities: caps,
          comment: t("comment.saml"),
        },
      ];
    }
    case "radius": {
      const m = authMount(mount);
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.radius.login"),
          },
        ];
      }
      if (input.access === "write") {
        return withConfig([
          {
            path: under(m, "users", name, input.scope),
            capabilities: ["create", "read", "update", "delete", "list"],
            comment: t("comment.radius.users"),
          },
          {
            path: joinMount(m, "login"),
            capabilities: ["create", "update"],
            comment: t("comment.radius.login"),
          },
        ], m);
      }
      return [
        {
          path: under(m, "users", name, input.scope),
          capabilities: caps,
          comment: t("comment.radius"),
        },
      ];
    }
    case "token": {
      const m = authMount(mount || "token");
      const op = mode === "all" ? "*" : secret === "*" ? "create" : secret || "create";
      if (input.access === "read") {
        return [
          {
            path: joinMount(m, "lookup-self"),
            capabilities: ["read"],
            comment: t("comment.token.lookup"),
          },
          {
            path: joinMount(m, "renew-self"),
            capabilities: ["update"],
            comment: t("comment.token.renew"),
          },
        ];
      }
      if (input.access === "write") {
        return [
          {
            path: joinMount(m, "create"),
            capabilities: ["create", "update"],
            comment: t("comment.token.create"),
          },
          {
            path: joinMount(m, "create/*"),
            capabilities: ["create", "update"],
            comment: t("comment.token.create"),
          },
          {
            path: joinMount(m, "lookup"),
            capabilities: ["update"],
            comment: t("comment.token.lookup"),
          },
          {
            path: joinMount(m, "revoke"),
            capabilities: ["update"],
            comment: t("comment.token.revoke"),
          },
        ];
      }
      return [
        {
          path: joinMount(m, op === "*" ? "create" : op),
          capabilities: caps,
          comment: t("comment.token"),
        },
      ];
    }

    case "sys": {
      const ids =
        input.sysEndpointIds?.length
          ? input.sysEndpointIds
          : [input.sysEndpointId ?? "custom"];
      const rules: GeneratorRule[] = [];
      for (const id of ids) {
        const ep = getSysEndpoint(id);
        const sysCaps = sysCapsFor(ep, input.access, input.customCapabilities);
        if (sysCaps.length === 0) continue;
        if (ep.id === "custom") {
          const raw = input.secretPath.trim().replace(/^\/+/, "");
          const path =
            raw.startsWith("sys/") || raw.startsWith("identity/")
              ? withGlob(raw, input.scope)
              : withGlob(joinMount("sys", raw), input.scope);
          rules.push({ path, capabilities: sysCaps, comment: t("comment.sys") });
        } else {
          rules.push({
            path: ep.path,
            capabilities: sysCaps,
            comment: `${t("comment.sys")} — ${ep.path}`,
          });
        }
      }
      return rules;
    }
    case "custom":
    default: {
      const customPath =
        mode === "all"
          ? underRoot(mount || "secret", "*", input.scope)
          : withGlob(input.secretPath.trim().replace(/^\/+/, "") || mount, input.scope);
      return [{ path: customPath, capabilities: caps, comment: t("comment.custom") }];
    }
  }
}
export function normalizeGeneratorPath(raw: string): string {
  return raw.trim().replace(/^\/+/, "").replace(/^v1\//, "");
}

export function buildPathBlock(rule: GeneratorRule): string {
  const path = normalizeGeneratorPath(rule.path);
  const caps = rule.capabilities.includes("deny")
    ? (["deny"] as Capability[])
    : [...new Set(rule.capabilities)];

  const lines: string[] = [];
  if (rule.comment?.trim()) {
    lines.push(`# ${rule.comment.trim()}`);
  }
  lines.push(`path "${path}" {`);
  lines.push(`  capabilities = [${caps.map((c) => `"${c}"`).join(", ")}]`);
  lines.push(`}`);
  return lines.join("\n");
}

export function buildPolicyHcl(rules: GeneratorRule[]): string {
  return rules
    .filter((r) => normalizeGeneratorPath(r.path) && r.capabilities.length > 0)
    .map(buildPathBlock)
    .join("\n\n");
}

export function appendToPolicy(existing: string, block: string): string {
  const trimmed = existing.trim();
  if (!trimmed) return `${block}\n`;
  return `${trimmed}\n\n${block}\n`;
}
