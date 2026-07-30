import type { EngineId } from "./catalog";

/** Doc / UI metadata sourced from Vault unified API docs (v2.x). */
export interface EngineDocMeta {
  id: EngineId;
  /** Short role of this mount for the Doc tab. */
  roleKey: string;
  /** Relative path under web-unified-docs …/api-docs/ */
  docPath: string;
  enterprise?: boolean;
  deprecated?: boolean;
  /** Prefer this engine id instead when deprecated. */
  replacedBy?: EngineId;
  /** e.g. "1.7+", "2.0.3+" when docs state a floor. */
  minVersion?: string;
  beta?: boolean;
  notes?: string[];
}

/**
 * Completeness notes vs HashiCorp web-unified-docs api-docs (Vault v2.x).
 * Paths and verbs in the generator follow these pages — do not invent APIs.
 */
export const ENGINE_DOC_META: EngineDocMeta[] = [
  { id: "kv2", roleKey: "meta.kv2", docPath: "secret/kv/kv-v2.mdx" },
  { id: "kv1", roleKey: "meta.kv1", docPath: "secret/kv/kv-v1.mdx" },
  {
    id: "database",
    roleKey: "meta.database",
    docPath: "secret/databases/index.mdx",
    notes: ["meta.note.db.static"],
  },
  {
    id: "pki",
    roleKey: "meta.pki",
    docPath: "secret/pki/index.mdx",
    notes: ["meta.note.pki.ent"],
  },
  { id: "transit", roleKey: "meta.transit", docPath: "secret/transit.mdx" },
  {
    id: "aws",
    roleKey: "meta.aws",
    docPath: "secret/aws.mdx",
    notes: ["meta.note.aws.sts"],
  },
  {
    id: "azure",
    roleKey: "meta.azure",
    docPath: "secret/azure.mdx",
    notes: ["meta.note.azure.static"],
  },
  {
    id: "gcp",
    roleKey: "meta.gcp",
    docPath: "secret/gcp.mdx",
    deprecated: true,
    notes: ["meta.note.gcp.deprecated"],
  },
  { id: "alicloud", roleKey: "meta.alicloud", docPath: "secret/alicloud.mdx" },
  { id: "ssh", roleKey: "meta.ssh", docPath: "secret/ssh.mdx" },
  { id: "rabbitmq", roleKey: "meta.rabbitmq", docPath: "secret/rabbitmq.mdx" },
  { id: "consul", roleKey: "meta.consul", docPath: "secret/consul.mdx" },
  { id: "nomad", roleKey: "meta.nomad", docPath: "secret/nomad.mdx" },
  { id: "totp", roleKey: "meta.totp", docPath: "secret/totp.mdx" },
  {
    id: "ldap_secrets",
    roleKey: "meta.ldap_secrets",
    docPath: "secret/ldap.mdx",
    notes: ["meta.note.ldap.library"],
  },
  { id: "kubernetes", roleKey: "meta.kubernetes", docPath: "secret/kubernetes.mdx" },
  { id: "terraform", roleKey: "meta.terraform", docPath: "secret/terraform.mdx" },
  { id: "mongodbatlas", roleKey: "meta.mongodbatlas", docPath: "secret/mongodbatlas.mdx" },
  { id: "gcpkms", roleKey: "meta.gcpkms", docPath: "secret/gcpkms.mdx" },
  {
    id: "keymgmt",
    roleKey: "meta.keymgmt",
    docPath: "secret/key-management/index.mdx",
    enterprise: true,
  },
  {
    id: "transform",
    roleKey: "meta.transform",
    docPath: "secret/transform.mdx",
    enterprise: true,
  },
  { id: "kmip", roleKey: "meta.kmip", docPath: "secret/kmip.mdx", enterprise: true },
  { id: "spiffe", roleKey: "meta.spiffe", docPath: "secret/spiffe.mdx" },
  { id: "cubbyhole", roleKey: "meta.cubbyhole", docPath: "secret/cubbyhole.mdx" },
  {
    id: "approle",
    roleKey: "meta.approle",
    docPath: "auth/approle.mdx",
    notes: ["meta.note.approle.secretid"],
  },
  { id: "userpass", roleKey: "meta.userpass", docPath: "auth/userpass.mdx" },
  { id: "ldap", roleKey: "meta.ldap", docPath: "auth/ldap.mdx" },
  { id: "jwt", roleKey: "meta.jwt", docPath: "auth/jwt.mdx" },
  { id: "oidc", roleKey: "meta.oidc", docPath: "auth/jwt.mdx" },
  { id: "github", roleKey: "meta.github", docPath: "auth/github.mdx" },
  { id: "cert", roleKey: "meta.cert", docPath: "auth/cert.mdx" },
  {
    id: "aws_auth",
    roleKey: "meta.aws_auth",
    docPath: "auth/aws.mdx",
    deprecated: true,
    notes: ["meta.note.aws_auth.deprecated"],
  },
  { id: "azure_auth", roleKey: "meta.azure_auth", docPath: "auth/azure.mdx" },
  { id: "gcp_auth", roleKey: "meta.gcp_auth", docPath: "auth/gcp.mdx" },
  { id: "alicloud_auth", roleKey: "meta.alicloud_auth", docPath: "auth/alicloud.mdx" },
  { id: "oci", roleKey: "meta.oci", docPath: "auth/oci.mdx" },
  { id: "okta", roleKey: "meta.okta", docPath: "auth/okta.mdx" },
  { id: "radius", roleKey: "meta.radius", docPath: "auth/radius.mdx" },
  {
    id: "kubernetes_auth",
    roleKey: "meta.kubernetes_auth",
    docPath: "auth/kubernetes.mdx",
  },
  { id: "kerberos", roleKey: "meta.kerberos", docPath: "auth/kerberos.mdx" },
  {
    id: "saml",
    roleKey: "meta.saml",
    docPath: "auth/saml.mdx",
    enterprise: true,
  },
  { id: "scep", roleKey: "meta.scep", docPath: "auth/scep.mdx" },
  { id: "spiffe_auth", roleKey: "meta.spiffe_auth", docPath: "auth/spiffe.mdx" },
  { id: "token", roleKey: "meta.token", docPath: "auth/token.mdx" },
  {
    id: "sys",
    roleKey: "meta.sys",
    docPath: "system/index.mdx",
  },
  { id: "custom", roleKey: "meta.custom", docPath: "" },
];

export function getEngineDocMeta(id: EngineId): EngineDocMeta | undefined {
  return ENGINE_DOC_META.find((m) => m.id === id);
}

/** Engines documented in api-docs but intentionally not generated (deprecated / niche). */
export const DOC_OMITTED = [
  {
    name: "Cassandra (legacy secrets)",
    docPath: "secret/cassandra.mdx",
    reasonKey: "meta.omit.cassandra",
  },
  {
    name: "Cloud Foundry auth",
    docPath: "auth/cf.mdx",
    reasonKey: "meta.omit.cf",
  },
  {
    name: "OS (local accounts)",
    docPath: "secret/os.mdx",
    reasonKey: "meta.omit.os",
    enterprise: true,
  },
  {
    name: "Agent Registry",
    docPath: "secret/agent-registry.mdx",
    reasonKey: "meta.omit.agent",
    enterprise: true,
    beta: true,
    minVersion: "2.0.3+",
  },
  {
    name: "PKI External CA",
    docPath: "secret/pki-external-ca.mdx",
    reasonKey: "meta.omit.pki_ext",
    enterprise: true,
  },
] as const;

/** Public HashiCorp Vault API docs (published from the MDX sources). */
export const DOC_SITE = "https://developer.hashicorp.com/vault/api-docs";

/** Local checkout path of the same MDX tree (reference only). */
export const DOC_API_ROOT = "web-unified-docs/content/vault/v2.x/content/api-docs";

/** Convert a relative api-docs MDX path to the public docs URL. */
export function vaultApiDocUrl(docPath: string): string {
  if (!docPath) return DOC_SITE;
  let p = docPath.replace(/\.mdx$/i, "").replace(/\\/g, "/");
  p = p.replace(/\/index$/i, "");
  return `${DOC_SITE}/${p.replace(/^\/+/, "")}`;
}

/**
 * MDX page under api-docs for each sys/identity generator endpoint.
 * Used for public links (developer.hashicorp.com).
 */
export const SYS_DOC_PATHS: Record<string, string> = {
  health: "system/health.mdx",
  leader: "system/leader.mdx",
  "seal-status": "system/seal-status.mdx",
  "ha-status": "system/ha-status.mdx",
  "host-info": "system/host-info.mdx",
  "key-status": "system/key-status.mdx",
  "version-history": "system/version-history.mdx",
  init: "system/init.mdx",
  monitor: "system/monitor.mdx",
  "in-flight-req": "system/in-flight-req.mdx",
  "policies-acl": "system/policies.mdx",
  "policies-acl-name": "system/policies.mdx",
  policy: "system/policy.mdx",
  "policy-name": "system/policy.mdx",
  "policies-password": "system/policies-password.mdx",
  "policies-rgp": "system/policies.mdx",
  "policies-rgp-name": "system/policies.mdx",
  "policies-egp": "system/policies.mdx",
  "policies-egp-name": "system/policies.mdx",
  "auth-list": "system/auth.mdx",
  "auth-manage": "system/auth.mdx",
  "auth-tune": "system/auth.mdx",
  mounts: "system/mounts.mdx",
  "mounts-path": "system/mounts.mdx",
  "mounts-tune": "system/mounts.mdx",
  remount: "system/remount.mdx",
  leases: "system/leases.mdx",
  "leases-lookup": "system/leases.mdx",
  "leases-revoke": "system/leases.mdx",
  "leases-revoke-prefix": "system/leases.mdx",
  "leases-revoke-force": "system/leases.mdx",
  "leases-renew": "system/leases.mdx",
  "wrapping-unwrap": "system/wrapping-unwrap.mdx",
  "wrapping-lookup": "system/wrapping-lookup.mdx",
  "wrapping-rewrap": "system/wrapping-rewrap.mdx",
  "wrapping-wrap": "system/wrapping-wrap.mdx",
  "tools-random": "system/tools.mdx",
  "tools-hash": "system/tools.mdx",
  "rekey-init": "system/rekey.mdx",
  "rekey-update": "system/rekey.mdx",
  "rekey-verify": "system/rekey.mdx",
  "rekey-recovery": "system/rekey-recovery-key.mdx",
  "generate-root": "system/generate-root.mdx",
  "generate-recovery": "system/generate-recovery-token.mdx",
  audit: "system/audit.mdx",
  "audit-path": "system/audit.mdx",
  "audit-hash": "system/audit-hash.mdx",
  "config-auditing": "system/config-auditing.mdx",
  "plugins-catalog": "system/plugins-catalog.mdx",
  "plugins-reload": "system/plugins-reload.mdx",
  "plugins-reload-status": "system/plugins-reload.mdx",
  "plugins-runtimes": "system/plugins-runtimes-catalog.mdx",
  "identity-entity": "secret/identity/entity.mdx",
  "identity-entity-name": "secret/identity/entity.mdx",
  "identity-entity-id": "secret/identity/entity.mdx",
  "identity-entity-merge": "secret/identity/entity.mdx",
  "identity-entity-batch-delete": "secret/identity/entity.mdx",
  "identity-entity-alias": "secret/identity/entity-alias.mdx",
  "identity-entity-alias-id": "secret/identity/entity-alias.mdx",
  "identity-group": "secret/identity/group.mdx",
  "identity-group-name": "secret/identity/group.mdx",
  "identity-group-id": "secret/identity/group.mdx",
  "identity-group-alias": "secret/identity/group-alias.mdx",
  "identity-group-alias-id": "secret/identity/group-alias.mdx",
  "identity-lookup": "secret/identity/lookup.mdx",
  "identity-oidc": "secret/identity/tokens.mdx",
  "identity-oidc-key": "secret/identity/tokens.mdx",
  "identity-oidc-role": "secret/identity/tokens.mdx",
  "identity-oidc-token": "secret/identity/tokens.mdx",
  "identity-oidc-introspect": "secret/identity/tokens.mdx",
  "identity-oidc-client": "secret/identity/oidc-provider.mdx",
  "identity-oidc-provider": "secret/identity/oidc-provider.mdx",
  "identity-oidc-scope": "secret/identity/oidc-provider.mdx",
  "identity-oidc-assignment": "secret/identity/oidc-provider.mdx",
  "identity-mfa-method": "secret/identity/mfa/index.mdx",
  "identity-mfa-login": "secret/identity/mfa/index.mdx",
  "identity-scim": "secret/identity/scim.mdx",
  "replication-status": "system/replication/index.mdx",
  "replication-merkle": "system/replication/index.mdx",
  "replication-recover": "system/replication/index.mdx",
  "replication-reindex": "system/replication/index.mdx",
  "replication-perf-status": "system/replication/replication-performance.mdx",
  "replication-dr-status": "system/replication/replication-dr.mdx",
  "replication-perf-primary": "system/replication/replication-performance.mdx",
  "replication-perf-secondary": "system/replication/replication-performance.mdx",
  "replication-dr-primary": "system/replication/replication-dr.mdx",
  "replication-dr-secondary": "system/replication/replication-dr.mdx",
  "replication-primary": "system/replication/replication-performance.mdx",
  "replication-secondary": "system/replication/replication-performance.mdx",
  "replication-paths-filter": "system/replication/replication-performance.mdx",
  "storage-raft": "system/storage/raft.mdx",
  "storage-raft-snapshot-auto": "system/storage/raftautosnapshots.mdx",
  namespaces: "system/namespaces.mdx",
  "namespaces-path": "system/namespaces.mdx",
  "namespaces-lock": "system/namespaces.mdx",
  "namespaces-unlock": "system/namespaces.mdx",
  "mfa-method": "system/mfa/index.mdx",
  "mfa-totp": "system/mfa/totp.mdx",
  "mfa-okta": "system/mfa/okta.mdx",
  "mfa-duo": "system/mfa/duo.mdx",
  "mfa-pingid": "system/mfa/pingid.mdx",
  "control-group-authorize": "system/control-group.mdx",
  "control-group-request": "system/control-group.mdx",
  "config-control-group": "system/config-control-group.mdx",
  "quotas-config": "system/quotas-config.mdx",
  "quotas-rate-limit": "system/rate-limit-quotas.mdx",
  "quotas-lease-count": "system/lease-count-quotas.mdx",
  "license-status": "system/license.mdx",
  "reporting-scan": "system/utilization-report.mdx",
  "managed-keys": "system/managed-keys.mdx",
  "sealwrap-rewrap": "system/sealwrap-rewrap.mdx",
  sync: "system/secrets-sync.mdx",
  seal: "system/seal.mdx",
  unseal: "system/unseal.mdx",
  rotate: "system/rotate.mdx",
  "rotate-config": "system/rotate-config.mdx",
  "step-down": "system/step-down.mdx",
  raw: "system/raw.mdx",
  "config-cors": "system/config-cors.mdx",
  "config-ui-headers": "system/config-ui-headers.mdx",
  "config-group-policy": "system/config-group-policy-application.mdx",
  "config-reload": "system/config-reload.mdx",
  "config-state": "system/config-state.mdx",
  capabilities: "system/capabilities.mdx",
  "capabilities-self": "system/capabilities-self.mdx",
  "capabilities-accessor": "system/capabilities-accessor.mdx",
  "internal-ui-mounts": "system/internal-ui-mounts.mdx",
  "internal-counters": "system/internal-counters.mdx",
  "internal-inspect": "system/inspect/index.mdx",
  metrics: "system/metrics.mdx",
  pprof: "system/pprof.mdx",
  experiments: "system/experiments.mdx",
  "activation-flags": "system/activation-flags.mdx",
};

export function sysEndpointDocUrl(id: string): string | undefined {
  const p = SYS_DOC_PATHS[id];
  return p ? vaultApiDocUrl(p) : undefined;
}
