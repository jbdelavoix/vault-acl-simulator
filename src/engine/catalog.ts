import type { Capability } from "./types";

/** Builtin secrets engines + common external / Enterprise plugins. */
export type EngineKind = "secrets" | "auth" | "system" | "other";

export type EngineId =
  | "kv2"
  | "kv1"
  | "database"
  | "pki"
  | "transit"
  | "aws"
  | "azure"
  | "gcp"
  | "alicloud"
  | "ssh"
  | "rabbitmq"
  | "consul"
  | "nomad"
  | "totp"
  | "ldap_secrets"
  | "kubernetes"
  | "terraform"
  | "mongodbatlas"
  | "gcpkms"
  | "keymgmt"
  | "transform"
  | "kmip"
  | "spiffe"
  | "cubbyhole"
  | "approle"
  | "userpass"
  | "ldap"
  | "jwt"
  | "oidc"
  | "github"
  | "cert"
  | "aws_auth"
  | "azure_auth"
  | "gcp_auth"
  | "alicloud_auth"
  | "oci"
  | "okta"
  | "radius"
  | "kubernetes_auth"
  | "kerberos"
  | "saml"
  | "scep"
  | "spiffe_auth"
  | "token"
  | "sys"
  | "custom";

export interface EngineDef {
  id: EngineId;
  kind: EngineKind;
  defaultMount: string;
  /** Placeholder for the path under the mount (app name, role, key…). */
  secretPlaceholder: string;
  /**
   * What the secret/name field represents — drives All (*) vs named UI.
   * `none` = no name field (sys endpoints, token helpers).
   */
  resourceKind: ResourceKind;
  /** Vault Enterprise feature (Ent chip in the UI). */
  enterprise?: boolean;
}

/** Named resource type for generator “all vs one” targeting. */
export type ResourceKind =
  | "path"
  | "role"
  | "user"
  | "user_group"
  | "key"
  | "team"
  | "cert"
  | "scope"
  | "none";

export const ENGINES: EngineDef[] = [
  // Secrets
  { id: "kv2", kind: "secrets", defaultMount: "secret", secretPlaceholder: "apps/myapp", resourceKind: "path" },
  { id: "kv1", kind: "secrets", defaultMount: "secret", secretPlaceholder: "apps/myapp", resourceKind: "path" },
  { id: "database", kind: "secrets", defaultMount: "database", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "pki", kind: "secrets", defaultMount: "pki", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "transit", kind: "secrets", defaultMount: "transit", secretPlaceholder: "my-key", resourceKind: "key" },
  { id: "aws", kind: "secrets", defaultMount: "aws", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "azure", kind: "secrets", defaultMount: "azure", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "gcp", kind: "secrets", defaultMount: "gcp", secretPlaceholder: "my-roleset", resourceKind: "role" },
  { id: "alicloud", kind: "secrets", defaultMount: "alicloud", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "ssh", kind: "secrets", defaultMount: "ssh", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "rabbitmq", kind: "secrets", defaultMount: "rabbitmq", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "consul", kind: "secrets", defaultMount: "consul", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "nomad", kind: "secrets", defaultMount: "nomad", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "totp", kind: "secrets", defaultMount: "totp", secretPlaceholder: "my-key", resourceKind: "key" },
  {
    id: "ldap_secrets",
    kind: "secrets",
    defaultMount: "ldap",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  {
    id: "kubernetes",
    kind: "secrets",
    defaultMount: "kubernetes",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  {
    id: "terraform",
    kind: "secrets",
    defaultMount: "terraform",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  {
    id: "mongodbatlas",
    kind: "secrets",
    defaultMount: "mongodbatlas",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  {
    id: "gcpkms",
    kind: "secrets",
    defaultMount: "gcpkms",
    secretPlaceholder: "my-key",
    resourceKind: "key",
  },
  {
    id: "keymgmt",
    kind: "secrets",
    defaultMount: "keymgmt",
    secretPlaceholder: "my-key",
    resourceKind: "key",
    enterprise: true,
  },
  {
    id: "transform",
    kind: "secrets",
    defaultMount: "transform",
    secretPlaceholder: "my-role",
    resourceKind: "role",
    enterprise: true,
  },
  {
    id: "kmip",
    kind: "secrets",
    defaultMount: "kmip",
    secretPlaceholder: "my-scope",
    resourceKind: "scope",
    enterprise: true,
  },
  {
    id: "spiffe",
    kind: "secrets",
    defaultMount: "spiffe",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  { id: "cubbyhole", kind: "secrets", defaultMount: "cubbyhole", secretPlaceholder: "*", resourceKind: "path" },
  // Auth
  { id: "approle", kind: "auth", defaultMount: "approle", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "userpass", kind: "auth", defaultMount: "userpass", secretPlaceholder: "alice", resourceKind: "user" },
  { id: "ldap", kind: "auth", defaultMount: "ldap", secretPlaceholder: "alice", resourceKind: "user_group" },
  { id: "jwt", kind: "auth", defaultMount: "jwt", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "oidc", kind: "auth", defaultMount: "oidc", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "github", kind: "auth", defaultMount: "github", secretPlaceholder: "my-team", resourceKind: "team" },
  { id: "cert", kind: "auth", defaultMount: "cert", secretPlaceholder: "my-cert", resourceKind: "cert" },
  { id: "aws_auth", kind: "auth", defaultMount: "aws", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "azure_auth", kind: "auth", defaultMount: "azure", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "gcp_auth", kind: "auth", defaultMount: "gcp", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "alicloud_auth", kind: "auth", defaultMount: "alicloud", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "oci", kind: "auth", defaultMount: "oci", secretPlaceholder: "my-role", resourceKind: "role" },
  { id: "okta", kind: "auth", defaultMount: "okta", secretPlaceholder: "alice", resourceKind: "user_group" },
  { id: "radius", kind: "auth", defaultMount: "radius", secretPlaceholder: "alice", resourceKind: "user" },
  {
    id: "kubernetes_auth",
    kind: "auth",
    defaultMount: "kubernetes",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  {
    id: "kerberos",
    kind: "auth",
    defaultMount: "kerberos",
    secretPlaceholder: "my-group",
    resourceKind: "user_group",
  },
  {
    id: "saml",
    kind: "auth",
    defaultMount: "saml",
    secretPlaceholder: "my-role",
    resourceKind: "role",
    enterprise: true,
  },
  { id: "scep", kind: "auth", defaultMount: "scep", secretPlaceholder: "my-role", resourceKind: "role" },
  {
    id: "spiffe_auth",
    kind: "auth",
    defaultMount: "spiffe",
    secretPlaceholder: "my-role",
    resourceKind: "role",
  },
  { id: "token", kind: "auth", defaultMount: "token", secretPlaceholder: "create", resourceKind: "none" },
  // System / other
  { id: "sys", kind: "system", defaultMount: "sys", secretPlaceholder: "policies/acl/*", resourceKind: "none" },
  { id: "custom", kind: "other", defaultMount: "", secretPlaceholder: "my-mount/path/*", resourceKind: "path" },
];

/** @deprecated use ENGINES */
export const SECRET_ENGINES = ENGINES;

export function getEngine(id: EngineId): EngineDef {
  return ENGINES.find((e) => e.id === id) ?? ENGINES[0];
}

export function enginesByKind(kind: EngineKind): EngineDef[] {
  return ENGINES.filter((e) => e.kind === kind);
}

/**
 * System / platform endpoints for the generator.
 * `path` is the full Vault ACL path (`sys/…` or `identity/…`).
 * `enterprise: true` → Vault Enterprise (Ent chip in the UI).
 */
export interface SysEndpoint {
  id: string;
  /** Full Vault ACL path (sys/… or identity/…). Empty for custom. */
  path: string;
  read: Capability[];
  write: Capability[];
  group: SysEndpointGroup;
  /** Short English blurb (generator UI; not localized). */
  doc: string;
  root?: boolean;
  enterprise?: boolean;
  /** Older API still present; prefer a newer path when noted in `doc`. */
  legacy?: boolean;
  deprecated?: boolean;
  beta?: boolean;
}

export type SysEndpointGroup =
  | "health"
  | "policies"
  | "auth"
  | "mounts"
  | "leases"
  | "tools"
  | "audit"
  | "plugins"
  | "identity"
  | "replication"
  | "namespaces"
  | "mfa"
  | "control-group"
  | "quotas"
  | "license"
  | "seal"
  | "config"
  | "custom";

export const SYS_ENDPOINT_GROUPS: SysEndpointGroup[] = [
  "health",
  "policies",
  "auth",
  "mounts",
  "leases",
  "tools",
  "audit",
  "plugins",
  "identity",
  "replication",
  "namespaces",
  "mfa",
  "control-group",
  "quotas",
  "license",
  "seal",
  "config",
  "custom",
];

type Caps = Capability[];

const R: Caps = ["read"];
const L: Caps = ["list"];
const RL: Caps = ["read", "list"];
const U: Caps = ["update"];
const CU: Caps = ["create", "update"];
const CRUD: Caps = ["create", "read", "update", "delete"];
const CRUDL: Caps = ["create", "read", "update", "delete", "list"];
const US: Caps = ["update", "sudo"];
const RS: Caps = ["read", "sudo"];
const RLS: Caps = ["read", "list", "sudo"];
const CRUDS: Caps = ["create", "read", "update", "delete", "sudo"];
const CRUDLS: Caps = ["create", "read", "update", "delete", "list", "sudo"];

function ep(
  id: string,
  path: string,
  group: SysEndpointGroup,
  read: Caps,
  write: Caps,
  doc: string,
  flags?: {
    root?: boolean;
    enterprise?: boolean;
    legacy?: boolean;
    deprecated?: boolean;
    beta?: boolean;
  },
): SysEndpoint {
  return { id, path, group, read, write, doc, ...flags };
}

export const SYS_ENDPOINTS: SysEndpoint[] = [
  // —— Health / status ——
  ep("health", "sys/health", "health", R, R, "Checks Vault health status (initialized, sealed, active/standby).\nMatches Consul-style HTTP health checks for load balancers and monitors.\nDefault codes: 200 active, 429 standby, 472 DR secondary, 473 perf standby, 501 uninitialized.\nOptional query flags can force standby/perf-standby nodes to return 200 for dumb LBs.\nUnauthenticated; useful for probes without a Vault token."),
  ep("leader", "sys/leader", "health", R, R, "Returns the active HA leader address and cluster addresses.\nUnauthenticated discovery of who is active.\nStandbys redirect/forward to the leader for most writes.\nEssential for clients and load balancers."),
  ep("seal-status", "sys/seal-status", "health", R, R, "Returns whether Vault is sealed, initialized, and HA mode details.\nUnauthenticated — safe for probes without a token.\nIncludes seal type, progress toward unseal threshold, and cluster name.\nDoes not unseal; use sys/unseal to submit key shares."),
  ep("ha-status", "sys/ha-status", "health", R, R, "Reports HA membership: active/standby nodes and last contact times.\nHelps diagnose cluster connectivity and failover health.\nAuthenticated read of cluster HA state.\nComplementary to sys/leader for the current active address."),
  ep("host-info", "sys/host-info", "health", R, R, "Host telemetry collected by Vault (CPU, memory, disk, …).\nUseful for support diagnostics and capacity checks.\nRead-only system introspection endpoint.\nContents vary by OS and Vault build."),
  ep("key-status", "sys/key-status", "health", R, R, "Shows the encryption key term and install time.\nConfirms whether a key rotation has taken effect.\nRead-only; rotation itself is sys/rotate (sudo).\nPart of storage encryption lifecycle, not auth tokens."),
  ep("version-history", "sys/version-history", "health", L, L, "Lists installed Vault version history entries on the node.\nHelps track upgrades across a cluster.\nTypically list capability on this path.\nDoes not change the running binary."),
  ep("init", "sys/init", "health", R, CU, "Initialize a brand-new Vault (shares, threshold, recovery keys).\nOnly valid before initialization; afterward returns an error.\nCan configure PGP wrapping of unseal/recovery keys.\nCritical one-time bootstrap — protect the output shares."),
  ep("monitor", "sys/monitor", "health", R, R, "Streams Vault server log lines over HTTP.\nUseful for live debugging without SSH to the host.\nRequires appropriate ACL on sys/monitor.\nCan be chatty — prefer short troubleshooting sessions."),
  ep("in-flight-req", "sys/in-flight-req", "health", R, R, "Lists currently in-flight API requests known to the node.\nOps aid for stuck clients or overload analysis.\nRead-only snapshot of active requests.\nNot a historical audit log."),

  // —— Policies (ACL + Sentinel Enterprise) ——
  ep("policies-acl", "sys/policies/acl", "policies", L, L, "List ACL policy names under sys/policies/acl (modern ACL API).\nACL only — Sentinel RGP/EGP are separate Enterprise endpoints.\nReturns named ACL policies the token can list.\nSpecial policies root and default always exist on the server."),
  ep("policies-acl-name", "sys/policies/acl/*", "policies", R, CRUD, "CRUD a named ACL policy at sys/policies/acl/:name.\nBody is an ACL document (HCL/JSON path + capabilities blocks).\nNot RGP/EGP — no Sentinel rules, only ACL capabilities.\nUse the parent list path to enumerate names."),
  ep("policy", "sys/policy", "policies", L, L, "Legacy ACL policy API at sys/policy (same ACL bodies as sys/policies/acl).\nLists and manages named ACL policies only — not Sentinel RGP/EGP.\nPrefer the newer sys/policies/acl paths for new policies.\nACL policies are HCL/JSON path blocks with capabilities, evaluated on every request.", { legacy: true }),
  ep("policy-name", "sys/policy/*", "policies", R, CRUD, "Read, write, or delete one named ACL policy via sys/policy/:name.\nLegacy ACL endpoint; semantics match sys/policies/acl/:name.\nDoes not manage Sentinel RGP or EGP (sys/policies/rgp|egp).\nReplaces the full ACL policy document on create/update.", { legacy: true }),
  ep("policies-password", "sys/policies/password/*", "policies", R, CRUD, "Password generation policies at sys/policies/password/:name.\nDefine length/charset rules for dynamically generated passwords.\nUsed by secrets engines (e.g. database), not for login ACLs.\nSeparate from ACL policies under sys/policies/acl."),
  ep("policies-rgp", "sys/policies/rgp", "policies", L, L, "List Sentinel Role Governing Policies under sys/policies/rgp (Enterprise).\nRGPs are Sentinel — not ACL policies under sys/policies/acl.\nCommunity Edition has no RGP engine.\nComplement ACL with soft/hard-mandatory Sentinel checks.", { enterprise: true }),
  ep("policies-rgp-name", "sys/policies/rgp/*", "policies", R, CRUD, "CRUD a named RGP (Sentinel) at sys/policies/rgp/:name (Enterprise).\nBody is Sentinel source, not ACL HCL capabilities.\nIncludes enforcement mode (soft/hard mandatory).\nDifferent evaluation path from sys/policies/acl.", { enterprise: true }),
  ep("policies-egp", "sys/policies/egp", "policies", L, L, "List Sentinel Endpoint Governing Policies under sys/policies/egp (Enterprise).\nEGPs bind Sentinel rules to request path prefixes.\nEnterprise only; works with ACL + RGP.\nPath-scoped governance beyond ACL capabilities.", { enterprise: true }),
  ep("policies-egp-name", "sys/policies/egp/*", "policies", R, CRUD, "CRUD a named EGP at sys/policies/egp/:name (Enterprise).\nConfigures paths, Sentinel policy, and enforcement level.\nNot an ACL policy — no capabilities = […] here.\nEvaluated for matching request paths in addition to ACL.", { enterprise: true }),
  ep("policies-rotation", "sys/policies/rotation/*", "policies", R, CRUD, "CRUD rotation policies at sys/policies/rotation/:name (Enterprise).\nControls retries for automated credential rotation.\nNot all secrets plugins consume rotation policies — check plugin docs.\nPairs with enterprise automated credential rotation.", { enterprise: true }),

  // —— Auth mounts (sys) ——
  ep("auth-list", "sys/auth", "auth", RL, RL, "List enabled auth methods at sys/auth.\nShows mount paths and type for each auth method.\nRead/list capabilities are enough for inventory.\nDoes not enable or disable mounts — use sys/auth/:path for that."),
  ep("auth-manage", "sys/auth/*", "auth", R, CRUDS, "Enable, disable, or read an auth method at sys/auth/:path.\nWrites usually need sudo (root-protected mount management).\nConverts user/machine login into Vault tokens once enabled.\nTune TTLs separately via sys/auth/:path/tune.", { root: true }),
  ep("auth-tune", "sys/auth/+/tune", "auth", R, US, "Tune an auth mount at sys/auth/+/tune (TTLs, description, listing).\nDoes not enable/disable the method — only mount options.\nOften requires sudo like other auth mount admin paths.\nUse after the auth method exists under sys/auth/:path.", { root: true }),

  // —— Secrets mounts ——
  ep("mounts", "sys/mounts", "mounts", R, R, "List enabled secrets engines at sys/mounts.\nShows mount paths, types, and accessor metadata.\nRead is enough to inventory mounts for ACL design.\nCreate/delete mounts use sys/mounts/:path instead."),
  ep("mounts-path", "sys/mounts/*", "mounts", R, CRUD, "Enable, disable, or read a secrets engine at sys/mounts/:path.\nConfigures type and mount options for the backend.\nTune TTLs/options separately at sys/mounts/:path/tune.\nCore path for operators managing secrets mounts."),
  ep("mounts-tune", "sys/mounts/+/tune", "mounts", R, U, "Tune a secrets mount at sys/mounts/+/tune (TTLs, description, options).\nDoes not enable or disable the mount.\nApplies to an existing mount path segment.\nUseful for default/max lease TTL without remounting."),
  ep("remount", "sys/remount", "mounts", US, US, "Move a secrets or auth mount to a new path (sudo).\nMigrates mount location without rewriting all secrets.\nRoot-protected; plan client path updates.\nPrefer over disable+enable when keeping data.", { root: true }),
  ep("remount-status", "sys/remount/status/*", "mounts", R, R, "Read remount migration status at sys/remount/status/:migration_id.\nTracks progress after a sys/remount request.\nRead-only companion to remount.\nUse the migration_id returned by remount."),

  // —— Leases / wrapping ——
  ep("leases", "sys/leases", "leases", US, US, "Lease administration under sys/leases (lookup/tidy-style ops).\nMany lease admin paths require sudo.\nLeases track dynamic secrets and renewable auth tokens.\nPrefer specific revoke/renew endpoints for day-to-day ops.", { root: true }),
  ep("leases-lookup", "sys/leases/lookup/*", "leases", US, US, "Look up leases under a path prefix at sys/leases/lookup/* (sudo).\nReturns lease IDs and metadata for matching prefixes.\nRoot-protected lease introspection.\nUse before bulk revoke when you need to see what exists.", { root: true }),
  ep("leases-revoke", "sys/leases/revoke", "leases", U, U, "Revoke a single lease by ID at sys/leases/revoke.\nInvalidates the lease and the associated secret/token as applicable.\nNeeds update capability on this path.\nPrefer prefix revoke for mass cleanup."),
  ep("leases-revoke-prefix", "sys/leases/revoke-prefix/*", "leases", US, US, "Revoke every lease under a path prefix (sudo).\nBulk cleanup after incidents or decommissioned mounts.\nRoot-protected — can revoke many live credentials at once.\nForce variant ignores backend errors during revoke.", { root: true }),
  ep("leases-revoke-force", "sys/leases/revoke-force/*", "leases", US, US, "Force-revoke leases under a prefix ignoring backend errors (sudo).\nUse when normal revoke fails because a secrets engine is unhealthy.\nRoot-protected operational escape hatch.\nPrefer normal revoke when backends respond cleanly.", { root: true }),
  ep("leases-renew", "sys/leases/renew", "leases", U, U, "Renew a lease by ID at sys/leases/renew.\nExtends TTL for renewable secrets or tokens.\nNeeds update capability.\nFails if the lease is not renewable or already expired."),
  ep("leases-tidy", "sys/leases/tidy", "leases", U, U, "Tidy dangling lease entries at sys/leases/tidy.\nCleans expired lease metadata left behind by backends.\nNeeds update capability.\nSafe maintenance when lease count grows unexpectedly."),
  ep("leases-count", "sys/leases/count", "leases", R, R, "Read approximate lease counts at sys/leases/count.\nUseful for capacity and quota planning.\nRead-only snapshot — not a full lease listing.\nComplement to lease-count quotas on Enterprise."),
  ep("wrapping-unwrap", "sys/wrapping/unwrap", "leases", U, U, "Unwraps a response-wrapping token and returns the wrapped payload.\nConsumes the wrapping token (single use by default).\nNeeds update on sys/wrapping/unwrap.\nCommon for one-time secret delivery between systems."),
  ep("wrapping-lookup", "sys/wrapping/lookup", "leases", U, U, "Looks up metadata for a wrapping token (TTL, creation path).\nDoes not reveal the wrapped secret itself.\nHelps validate a wrap before unwrap.\nUse with wrapping tokens created via wrap/rewrap."),
  ep("wrapping-rewrap", "sys/wrapping/rewrap", "leases", U, U, "Rotates a wrapping token and refreshes its TTL.\nReturns a new wrapping token for the same payload.\nDoes not unwrap the secret to the caller.\nUseful to extend delivery windows safely."),
  ep("wrapping-wrap", "sys/wrapping/wrap", "leases", U, U, "Wraps arbitrary JSON as a response-wrapping token.\nAnyone with the wrap path can create cubbyhole-wrapped payloads.\nRecipient unwraps via sys/wrapping/unwrap.\nPrefer short TTLs for sensitive material."),

  // —— Tools / rekey / generate-root ——
  ep("tools-random", "sys/tools/random*", "tools", U, U, "Generate random bytes via sys/tools/random (optional source/bytes in path).\nUtility endpoint — not a secrets engine.\nRequires update capability.\nPath may be sys/tools/random, …/source, or …/source/bytes."),
  ep("tools-hash", "sys/tools/hash*", "tools", U, U, "Hash input via sys/tools/hash (optional algorithm in the path).\nUtility hashing helper (sha2, …).\nRequires update capability.\nNot a substitute for Transit encryption."),
  ep("rekey-init", "sys/rekey/init", "tools", ["read", "update", "delete"], ["read", "update", "delete"], "Start, read, or cancel an unseal-key rekey at sys/rekey/init.\nBegins the ceremony to replace unseal key shares.\nCancel with delete when aborting.\nFollow with update/verify share submission."),
  ep("rekey-update", "sys/rekey/update", "tools", U, U, "Submit an unseal key share during an in-progress rekey.\nProgresses the rekey threshold toward completion.\nPart of the sys/rekey/* ceremony.\nUse only while a rekey is initialized."),
  ep("rekey-verify", "sys/rekey/verify", "tools", ["delete", "update"], ["delete", "update"], "Verify new unseal key shares after rekey (nonce/progress).\nConfirms the new key set before committing.\nDelete/update per API for verify lifecycle.\nFinal safety step of unseal rekey."),
  ep("rekey-recovery", "sys/rekey-recovery-key/*", "tools", ["read", "update", "delete"], ["read", "update", "delete"], "Rekey recovery keys for auto-unseal deployments.\nParallel ceremony to unseal rekey but for recovery keys.\nUnder sys/rekey-recovery-key/*.\nRequired ops path when recovery shares must rotate."),
  ep("generate-root", "sys/generate-root/*", "tools", ["read", "update", "delete"], ["read", "update", "delete"], "Generate a root token via OTP/PGP ceremony under sys/generate-root/*.\nBreak-glass when no root token is available.\nMulti-step init/update/decode flow.\nProtect OTP and encoded root output carefully."),
  ep("generate-recovery", "sys/generate-recovery-token/*", "tools", ["read", "update", "delete"], ["read", "update", "delete"], "Generate a recovery token for auto-unseal setups.\nAnalogous to generate-root but for recovery workflow.\nUnder sys/generate-recovery-token/*.\nEnterprise/auto-unseal operational recovery."),
  ep("decode-token", "sys/decode-token", "tools", US, US, "Decode an OTP-encoded root token from generate-root (sudo).\nFinal step after the generate-root ceremony.\nRoot-protected — yields a usable root token.\nRequires the OTP produced during generate-root init.", { root: true }),
  ep("rekey-backup", "sys/rekey/backup", "tools", ["read", "delete"], ["read", "delete"], "Read or delete PGP-backed-up rekey shares at sys/rekey/backup.\nAvailable when rekey used PGP encryption of new shares.\nRead retrieves ciphertext; delete clears the backup.\nCompanion to the unseal-key rekey flow."),
  ep(
    "rekey-recovery-backup",
    "sys/rekey/recovery-key-backup",
    "tools",
    ["read", "delete"],
    ["read", "delete"],
    "Read or delete PGP-backed-up recovery key shares after recovery rekey.\nParallel to sys/rekey/backup for auto-unseal recovery keys.\nRead returns nonce and fingerprint→ciphertext map.\nDelete clears the stored backup.",
  ),

  // —— Audit ——
  ep("audit", "sys/audit", "audit", RS, RS, "List enabled audit devices at sys/audit (sudo).\nAudit devices record requests/responses to durable sinks.\nRoot-protected listing of auditing backends.\nEnable/disable specific devices under sys/audit/:path.", { root: true }),
  ep("audit-path", "sys/audit/*", "audit", RS, CRUDS, "Enable or disable an audit device at sys/audit/:path (sudo).\nConfigures type and options for file/syslog/socket devices.\nRoot-protected — misconfig can lose audit coverage.\nHash helper lives at sys/audit-hash/:path.", { root: true }),
  ep("audit-hash", "sys/audit-hash/*", "audit", CU, CU, "Hash a value with an audit device’s salt at sys/audit-hash/:path.\nHelps correlate plaintext you know with audit log hashes.\nDoes not enable audit devices.\nPer-device path segment selects the audit backend."),
  ep("config-auditing", "sys/config/auditing/*", "audit", RS, CRUDS, "Configures auditing request/response header allow/deny lists (sudo).\nControls which headers appear in audit logs.\nGlobal auditing settings — not per audit device enablement.\nDevice enable/disable remains under sys/audit.", { root: true }),

  // —— Plugins ——
  ep("plugins-catalog", "sys/plugins/catalog/*", "plugins", RLS, CRUDLS, "Plugin catalog: register, read, list, delete plugin binaries (sudo).\nRequired before mounting a custom plugin type.\nRoot-protected catalog management.\nReload mounted instances via sys/plugins/reload.", { root: true }),
  ep("plugins-reload", "sys/plugins/reload/*", "plugins", U, U, "Reloads mounted plugins by type or mount paths.\nApplies catalog updates without full Vault restart.\nUse after registering a new plugin version.\nCheck reload status on Enterprise if available."),
  ep("plugins-reload-status", "sys/plugins/reload/backend/status", "plugins", R, R, "Reads status of a plugin reload job (Enterprise).\nShows progress/errors for an in-flight reload.\nCompanion to sys/plugins/reload.\nNot used for catalog registration itself.", { enterprise: true }),
  ep("plugins-runtimes", "sys/plugins/runtimes/catalog/*", "plugins", RLS, CRUDLS, "Manages plugin runtimes/container catalog (sudo).\nDefines how containerized plugins execute.\nEnterprise/advanced plugin deployments.\nSeparate from the main plugins catalog entries.", { root: true }),
  ep("plugins-pins", "sys/plugins/pins", "plugins", RL, RL, "List pinned plugin versions at sys/plugins/pins.\nPins force mounts to use a registered non-builtin version.\nRead/list inventory of pins.\nCreate/update/delete pins under sys/plugins/pins/:type/:name."),
  ep("plugins-pins-name", "sys/plugins/pins/*/*", "plugins", R, CRUD, "Pin or unpin a plugin version at sys/plugins/pins/:type/:name.\nType is auth, database, or secret; name is the plugin name.\nVersion must already exist in the catalog.\nReload mounts for the pin to take effect."),

  // —— Identity (mounted at identity/, not under sys/) ——
  ep("identity-entity", "identity/entity", "identity", RL, CRUDL, "Create/list identity entities in the identity store.\nEntities group aliases from one or more auth methods.\nCore building block for policies and groups.\nPaths are under identity/… (not sys/identity/)."),
  ep("identity-entity-name", "identity/entity/name/*", "identity", RL, CRUDL, "CRUD an identity entity by name at identity/entity/name/:name.\nEntities aggregate aliases from one or more auth methods.\nSCIM-managed fields may be read-only on these standard endpoints.\nList/create also via identity/entity."),
  ep("identity-entity-id", "identity/entity/id/*", "identity", R, CRUD, "CRUD an identity entity by ID at identity/entity/id/:id.\nSame entity model as the name-based paths.\nPrefer ID paths in automation once the entity exists.\nSCIM-provisioned entities may restrict some fields."),
  ep("identity-entity-merge", "identity/entity/merge", "identity", U, U, "Merge duplicate identity entities at identity/entity/merge.\nConsolidates aliases and metadata onto a canonical entity.\nNeeds update capability.\nUse carefully — merges are hard to undo cleanly."),
  ep("identity-entity-batch-delete", "identity/entity/batch-delete", "identity", U, U, "Batch-delete identity entities at identity/entity/batch-delete.\nRemoves many entities in one request for cleanup jobs.\nNeeds update capability.\nDoes not replace per-ID delete for single entities."),
  ep("identity-entity-alias", "identity/entity-alias", "identity", RL, CRUDL, "Create/list entity aliases linking auth mounts to entities.\nAn alias is mount + name (e.g. userpass username).\nMerging aliases consolidates a human/machine identity.\nManage by ID under identity/entity-alias/id/*."),
  ep("identity-entity-alias-id", "identity/entity-alias/id/*", "identity", R, CRUD, "CRUD an entity alias by ID at identity/entity-alias/id/:id.\nChanging alias→entity binding can escalate privileges.\nTreat alias write as highly sensitive.\nCreate/list via identity/entity-alias."),
  ep("identity-group", "identity/group", "identity", RL, CRUDL, "Create/list identity groups (internal or external).\nGroups attach policies to sets of entities.\nExternal groups map to IdP groups via aliases.\nManage by name or ID under identity/group/*."),
  ep("identity-group-name", "identity/group/name/*", "identity", RL, CRUDL, "CRUD an identity group by name at identity/group/name/:name.\nAttach policies and entity members on the group object.\nMembership writes can escalate access — protect tightly.\nExternal groups usually pair with group aliases."),
  ep("identity-group-id", "identity/group/id/*", "identity", R, CRUD, "CRUD an identity group by ID at identity/group/id/:id.\nSame semantics as name-based group paths.\nPrefer ID in automation after the group exists.\nMembership changes are privilege-sensitive."),
  ep("identity-group-alias", "identity/group-alias", "identity", RL, CRUDL, "Create/list group aliases for external group mapping.\nTies an auth mount group name to an identity group.\nRequired for LDAP/OIDC group → policy workflows.\nManage by ID under identity/group-alias/id/*."),
  ep("identity-group-alias-id", "identity/group-alias/id/*", "identity", R, CRUD, "CRUD a group alias by ID at identity/group-alias/id/:id.\nMaps an external IdP/LDAP group name onto an identity group.\nNeeded for external group policy workflows.\nCreate/list via identity/group-alias."),
  ep("identity-lookup", "identity/lookup/*", "identity", ["read", "update"], ["read", "update"], "Look up entities or groups by ID, name, or alias.\nConvenience API instead of knowing the exact CRUD path.\nSupports entity and group lookup subpaths.\nUseful for automation and admin tooling."),
  ep("identity-oidc", "identity/oidc/*", "identity", RL, CRUDL, "Identity tokens / OIDC issuer configuration root.\nCovers keys, roles, and token minting under identity/oidc/*.\nVault-issued identity JWTs for other systems.\nProvider feature (clients/scopes) is the sibling OIDC provider API."),
  ep("identity-oidc-key", "identity/oidc/key/*", "identity", RL, CRUDL, "Manage OIDC signing keys at identity/oidc/key/:name.\nKeys sign Vault-issued identity tokens.\nRotate carefully — clients cache JWKS.\nPair with roles that reference a named key."),
  ep("identity-oidc-role", "identity/oidc/role/*", "identity", RL, CRUDL, "Manage OIDC roles that mint identity tokens at identity/oidc/role/:name.\nRoles select key, TTL, and client ID claims.\nClients mint via identity/oidc/token/:name.\nSeparate from the OIDC provider clients API."),
  ep("identity-oidc-client", "identity/oidc/client/*", "identity", RL, CRUDL, "Manage OIDC provider clients at identity/oidc/client/:name.\nRegisters relying parties for Vault as an OIDC provider.\nAssigns scopes and assignments for authorization.\nPart of the identity OIDC provider feature set."),
  ep("identity-oidc-provider", "identity/oidc/provider/*", "identity", RL, CRUDL, "Manage OIDC providers at identity/oidc/provider/:name.\nExposes issuer metadata and authorization endpoints.\nBinds clients, scopes, and assignments together.\nVault acts as an OpenID Connect provider."),
  ep("identity-oidc-scope", "identity/oidc/scope/*", "identity", RL, CRUDL, "Manage OIDC scopes / claim templates at identity/oidc/scope/:name.\nScopes define which identity claims appear in tokens.\nReferenced by clients and providers.\nTemplate carefully — claims can leak PII."),
  ep("identity-oidc-assignment", "identity/oidc/assignment/*", "identity", RL, CRUDL, "Manage OIDC assignments at identity/oidc/assignment/:name.\nAssignments map entities/groups to provider clients.\nControls who may obtain tokens for a client.\nRequired for least-privilege OIDC provider setups."),
  ep("identity-oidc-token", "identity/oidc/token/*", "identity", R, U, "Mint an identity OIDC token for a role at identity/oidc/token/:name.\nReturns a signed JWT for the calling entity.\nNeeds update (and often read) on the token path.\nRole must already exist under identity/oidc/role."),
  ep("identity-oidc-introspect", "identity/oidc/introspect", "identity", U, U, "Introspect a Vault-issued identity OIDC token.\nValidates signature and reports active/claims metadata.\nNeeds update on identity/oidc/introspect.\nUseful for resource servers that trust Vault JWTs."),
  ep("identity-mfa-method", "identity/mfa/method/*", "identity", RL, CRUDL, "Configure Identity MFA methods (TOTP, Okta, Duo, …).\nLogin MFA behaviors live under identity/mfa/method/*.\nDistinct from Enterprise sys/mfa method paths.\nPair with login-enforcement policies to require MFA."),
  ep("identity-mfa-login", "identity/mfa/login-enforcement/*", "identity", RL, CRUDL, "Configure MFA login-enforcement at identity/mfa/login-enforcement/*.\nRequires named MFA methods before login succeeds.\nTargets entities, groups, or auth mounts as configured.\nPrefer this over legacy Enterprise sys/mfa for new setups."),
  ep("identity-scim", "identity/scim/v2/*", "identity", RL, CRUDL, "SCIM provisioning API under identity/scim/v2/* (Enterprise beta).\nProvisions entities/groups from external IdPs via SCIM.\nRequires activation flag enable-scim before use.\nAuthorize via ACL plus SCIM client access grants.", { enterprise: true, beta: true }),
  ep("identity-scim-client", "identity/scim/client/*", "identity", RL, CRUDL, "Manage SCIM clients and resource links at identity/scim/client/* (Enterprise beta).\nRegisters clients and link/unlink entity or group mappings.\nCompanion to the SCIM v2 Users/Groups API.\nNeeds activation flag enable-scim.", { enterprise: true, beta: true }),
  ep("identity-tpm", "identity/tpm/*", "identity", RL, CRUDL, "Manage TPM identity records at identity/tpm/* (Enterprise).\nRegisters TPM endorsement keys for hardware-bound identity.\nCRUD by id or name under identity/tpm/id|name/*.\nEnterprise identity feature for TPM-backed principals.", { enterprise: true }),
  ep("identity-tpmgroup", "identity/tpmgroup/*", "identity", RL, CRUDL, "Manage TPM groups at identity/tpmgroup/* (Enterprise).\nGroups TPM records for authorization collections.\nCRUD by id or name; member_tpm_ids must already exist.\nEnterprise companion to identity/tpm.", { enterprise: true }),

  // —— Replication (mostly Enterprise; status exists on CE as stub) ——
  ep("replication-status", "sys/replication/status", "replication", R, R, "Overall replication status for the cluster.\nOn Community this is limited; Enterprise returns PR/DR detail.\nRead-only health/status style endpoint.\nUse performance/dr subpaths for role-specific ops."),
  ep("replication-merkle", "sys/replication/merkle-check", "replication", U, U, "Compare Merkle trees between replication members (Enterprise).\nDiagnoses replication divergence / lag root causes.\nUpdate capability; operational troubleshooting tool.\nNot for day-to-day enable/disable of replication.", { enterprise: true }),
  ep("replication-recover", "sys/replication/recover", "replication", U, U, "Attempt replication recovery operations (Enterprise).\nUsed when a secondary needs controlled recovery steps.\nDangerous if misused — follow Vault ops docs.\nEnterprise replication clusters only.", { enterprise: true }),
  ep("replication-reindex", "sys/replication/reindex", "replication", US, US, "Reindex replication Merkle trees (Enterprise, often sudo).\nRebuilds indexes after corruption or major upgrades.\nDisruptive operational task — schedule carefully.\nRequires elevated privileges.", {
    root: true,
    enterprise: true,
  }),
  ep("replication-perf-status", "sys/replication/performance/status", "replication", R, R, "Read performance replication status (Enterprise).\nShows primary/secondary mode, connection health, and last WAL info.\nRead-only operational view for PR clusters.\nManage enablement under performance/primary|secondary.", {
    enterprise: true,
  }),
  ep("replication-dr-status", "sys/replication/dr/status", "replication", R, R, "Read disaster-recovery replication status (Enterprise).\nShows DR primary/secondary state and replication health.\nRead-only companion to DR primary/secondary management paths.\nEnterprise DR clusters only.", { enterprise: true }),
  ep("replication-perf-primary", "sys/replication/performance/primary/*", "replication", U, U, "Performance replication primary ops at …/performance/primary/* (Enterprise).\nEnable primary, demote, and issue secondary tokens.\nCore PR cluster administration paths.\nPrefer these over legacy sys/replication/primary/*.", {
    enterprise: true,
  }),
  ep("replication-perf-secondary", "sys/replication/performance/secondary/*", "replication", U, U, "Performance replication secondary ops at …/performance/secondary/* (Enterprise).\nEnable/update secondary and related promotion workflows.\nMust present a valid secondary token from the primary.\nPrefer over legacy sys/replication/secondary/*.", {
    enterprise: true,
  }),
  ep("replication-dr-primary", "sys/replication/dr/primary/*", "replication", U, U, "DR primary enable/demote/secondary-token paths (Enterprise).\nConfigures the disaster-recovery primary cluster.\nIssues tokens for DR secondaries.\nSeparate from performance replication primary paths.", {
    enterprise: true,
  }),
  ep("replication-dr-secondary", "sys/replication/dr/secondary/*", "replication", U, U, "DR secondary enable/promote/update paths (Enterprise).\nBrings a DR secondary online or promotes it in failover.\nRequires a token from the DR primary.\nOperational break-glass for DR drills and outages.", {
    enterprise: true,
  }),
  ep("replication-primary", "sys/replication/primary/*", "replication", U, U, "Legacy performance primary paths under sys/replication/primary/* (Enterprise).\nPrefer sys/replication/performance/primary/* when available.\nEnables demotion and secondary token issuance workflows.\nEnterprise Performance Replication only.", { enterprise: true, legacy: true }),
  ep("replication-secondary", "sys/replication/secondary/*", "replication", U, U, "Legacy performance secondary paths under sys/replication/secondary/* (Enterprise).\nPrefer sys/replication/performance/secondary/* when available.\nEnable/update/promote secondary workflows.\nEnterprise Performance Replication only.", { enterprise: true, legacy: true }),
  ep("replication-paths-filter", "sys/replication/performance/primary/paths-filter/*", "replication", R, CRUD, "Path filters for performance secondaries (Enterprise).\nAllow/deny which mount paths replicate to a given secondary.\nConfigured on the performance primary.\nUse to limit blast radius of secondary data.", {
    enterprise: true,
  }),
  ep("storage-raft", "sys/storage/raft/*", "replication", RL, CRUDL, "Manage integrated Raft storage at sys/storage/raft/*.\nJoin/remove peers, take snapshots, and inspect cluster configuration.\nUsed when Vault storage is raft (HA integrated storage).\nNot the same as file/consul storage backends."),
  ep("storage-raft-snapshot-auto", "sys/storage/raft/snapshot-auto/*", "replication", RL, CRUDL, "Configure automated Raft snapshots at sys/storage/raft/snapshot-auto/* (Enterprise).\nSchedule recurring snapshots to cloud or other storage.\nOften requires sudo on config paths.\nComplementary to one-off raft snapshot endpoints.", {
    enterprise: true,
    root: true,
  }),

  // —— Namespaces (Enterprise) ——
  ep("namespaces", "sys/namespaces", "namespaces", L, L, "List namespaces (Enterprise multi-tenancy).\nNamespaces isolate mounts, policies, and identities.\nCreate/manage children via sys/namespaces/*.\nAPI lock endpoints can freeze a namespace.", { enterprise: true }),
  ep("namespaces-path", "sys/namespaces/*", "namespaces", R, ["create", "read", "update", "delete", "patch"], "CRUD a child namespace at sys/namespaces/:path (Enterprise).\nCreates isolated mounts, policies, and identities under a path.\nSupports patch for partial updates on newer Vault versions.\nList parents via sys/namespaces.", {
    enterprise: true,
  }),
  ep("namespaces-lock", "sys/namespaces/api-lock/lock/*", "namespaces", U, U, "Lock a namespace API (freeze writes) at …/api-lock/lock/* (Enterprise).\nBlocks mutating API calls into that namespace until unlocked.\nOperational freeze for incident response or migrations.\nUnlock via the matching unlock path.", { enterprise: true }),
  ep("namespaces-unlock", "sys/namespaces/api-lock/unlock/*", "namespaces", U, U, "Unlock a previously locked namespace at …/api-lock/unlock/* (Enterprise).\nRestores normal write API access after a lock.\nNeeds update capability.\nPair with lock during maintenance windows.", { enterprise: true }),

  // —— MFA methods (Enterprise sys/mfa; identity MFA above is CE+) ——
  ep("mfa-method", "sys/mfa/method", "mfa", L, L, "List Enterprise sys/mfa method configurations.\nThis is the older sys/mfa tree (Enterprise).\nPrefer Identity MFA (identity/mfa) for many new setups.\nTOTP/Okta/Duo/PingID live under sys/mfa/method/*.", { enterprise: true, legacy: true }),
  ep("mfa-totp", "sys/mfa/method/totp/*", "mfa", R, CRUD, "Configure TOTP MFA methods under sys/mfa/method/totp/* (Enterprise).\nGenerate/admin TOTP seeds for MFA challenges.\nDistinct from identity/mfa TOTP methods.\nEnterprise MFA stack.", { enterprise: true, legacy: true }),
  ep("mfa-okta", "sys/mfa/method/okta/*", "mfa", R, CRUD, "Configure Okta MFA methods under sys/mfa/method/okta/* (Enterprise).\nIntegrates Okta push/verify into Vault MFA.\nEnterprise sys/mfa path — not identity/mfa.\nRequires Okta API credentials in method config.", { enterprise: true, legacy: true }),
  ep("mfa-duo", "sys/mfa/method/duo/*", "mfa", R, CRUD, "Configure Duo MFA methods under sys/mfa/method/duo/* (Enterprise).\nDuo Security push/phone/SMS style MFA for Vault.\nEnterprise sys/mfa path — not identity/mfa.\nNeeds Duo integration keys in the method.", { enterprise: true, legacy: true }),
  ep("mfa-pingid", "sys/mfa/method/pingid/*", "mfa", R, CRUD, "Configure PingID MFA methods under sys/mfa/method/pingid/* (Enterprise).\nPing Identity MFA integration for Vault logins.\nEnterprise sys/mfa path — not identity/mfa.\nRequires PingID settings on the method.", { enterprise: true, legacy: true }),
  ep(
    "mfa-admin-destroy",
    "sys/mfa/method/+/admin-destroy",
    "mfa",
    U,
    U,
    "Destroy an MFA secret for an entity via sys/mfa/method/:name/admin-destroy.\nEnterprise sys/mfa admin operation (body includes entity_id).\nUsed before regenerating TOTP secrets on an entity.\nPrefer identity/mfa for new Identity MFA setups.",
    { enterprise: true, legacy: true },
  ),
  ep("mfa-validate", "sys/mfa/validate", "mfa", U, U, "Validate a login MFA challenge at sys/mfa/validate.\nCompletes MFA-restricted login and returns an auth token on success.\nNeeds update; clients call this after MFA requirement in login response.\nWorks with Identity MFA login-enforcement flows."),

  // —— Control groups (Enterprise) ——
  ep("control-group-authorize", "sys/control-group/authorize", "control-group", U, U, "Authorize a pending control-group request (Enterprise).\nApprovers satisfy required authorizations before the request proceeds.\nUpdate on sys/control-group/authorize.\nPairs with control-group request status lookups.", {
    enterprise: true,
  }),
  ep("control-group-request", "sys/control-group/request", "control-group", U, U, "Read control-group request status (Enterprise).\nShows what approvals remain for a wrapped request.\nUsed by requesters and operators during CG flows.\nConfigure defaults via sys/config/control-group.", { enterprise: true }),
  ep("config-control-group", "sys/config/control-group", "control-group", R, CRUD, "Configure control-group defaults (max TTL, …) (Enterprise).\nGlobal CG behavior for the namespace/cluster.\nRead/update the control-group config object.\nDoes not itself authorize individual requests.", { enterprise: true }),

  // —— Quotas ——
  ep("quotas-config", "sys/quotas/config", "quotas", R, U, "Global quotas configuration (rate-limit defaults, enablement).\nAffects how rate-limit quotas behave cluster-wide.\nRead/update sys/quotas/config.\nNamed quotas live under rate-limit and lease-count paths."),
  ep("quotas-rate-limit", "sys/quotas/rate-limit/*", "quotas", RL, CRUDL, "CRUD named rate-limit quotas at sys/quotas/rate-limit/*.\nThrottle request rates by path/role/namespace as configured.\nAvailable on Community for rate limiting.\nList and manage each quota by name."),
  ep("quotas-lease-count", "sys/quotas/lease-count/*", "quotas", RL, CRUDL, "CRUD lease-count quotas at sys/quotas/lease-count/* (Enterprise).\nCap how many leases a path/namespace may hold.\nEnterprise complement to rate-limit quotas.\nPrevents lease explosion from dynamic secrets.", { enterprise: true }),

  // —— License / reporting / managed keys (Enterprise) ——
  ep("license-status", "sys/license/status", "license", R, R, "Read Enterprise license status (features, expiry, raw metadata).\nDoes not install a license by itself on all versions/workflows.\nEnterprise clusters only.\nMonitor before feature expiry affects the cluster.", { enterprise: true }),
  ep("reporting-scan", "sys/reporting/scan", "license", U, U, "Trigger utilization / reporting scan (Enterprise, often sudo).\nCollects product utilization data for reporting.\nOperational/admin endpoint — not end-user secret access.\nRequires elevated privileges.", { enterprise: true, root: true }),
  ep("utilization-report", "sys/utilization-report", "license", R, R, "Read a utilization report snapshot at sys/utilization-report (Enterprise).\nSummarizes product utilization for licensing/reporting.\nRead-only companion to reporting scan.\nEnterprise admin/reporting use.", { enterprise: true }),
  ep("billing-overview", "sys/billing/overview", "license", R, R, "Monthly usage-based licensing overview at sys/billing/overview (Enterprise).\nReturns retained billing metrics (default ~37 months).\nOptional refresh_data recalculates metrics (expensive).\nEnterprise usage-based billing API.", { enterprise: true }),
  ep("billing-config", "sys/billing/config", "license", R, U, "Configure billing retention and related settings at sys/billing/config (Enterprise).\nControls how long usage metrics are kept.\nRead/update; admin-oriented.\nPairs with sys/billing/overview.", { enterprise: true }),
  ep("billing-certificates", "sys/billing/certificates", "license", R, R, "Billing certificate / attestation material at sys/billing/certificates (Enterprise).\nSupports usage-based licensing workflows.\nRead-only in typical setups.\nEnterprise billing API.", { enterprise: true }),
  ep("managed-keys", "sys/managed-keys/*", "license", RL, CRUDL, "Configure managed keys (HSM/KMS-backed keys) (Enterprise).\nLets Transit/PKI-style features use external key material.\nCRUD under sys/managed-keys/*.\nAdvanced Enterprise cryptography integration.", { enterprise: true }),
  ep("sealwrap-rewrap", "sys/sealwrap/rewrap", "license", ["read", "update"], ["read", "update"], "Rewrap seal-wrapped entries after seal key changes (Enterprise).\nNeeded when seal wrapping must follow a new seal key.\nRead/update depending on operation phase.\nMaintenance task after seal migration/rekey events.", {
    enterprise: true,
  }),
  ep("sync", "sys/sync/*", "license", RL, CRUDL, "Secrets Sync destinations and associations (Enterprise).\nSync Vault secrets out to external stores as configured.\nManage under sys/sync/*.\nEnterprise feature distinct from replication.", { enterprise: true }),
  ep("rotation-orphans", "sys/rotation/orphans/*", "license", R, R, "List orphaned automated-rotation entries at sys/rotation/orphans/ (Enterprise).\nShows rotation jobs whose backing resource is gone.\nRead/list style ops cleanup aid.\nRelated to rotation policies under sys/policies/rotation.", { enterprise: true }),

  // —— Seal / rotate / raw ——
  ep("seal", "sys/seal", "seal", US, US, "Seals Vault so it cannot decrypt data until unsealed (sudo).\nActive node stops serving secrets after seal.\nRoot-protected operational control.\nOpposite of sys/unseal key share submission.", { root: true }),
  ep("unseal", "sys/unseal", "seal", U, U, "Submit one unseal key share toward the unseal threshold.\nUnauthenticated by design for break-glass unseal.\nRepeat from share holders until threshold is met.\nDoes not require a Vault token."),
  ep("seal-backend-status", "sys/seal-backend-status", "seal", R, R, "Read auto-unseal seal backend health at sys/seal-backend-status.\nShows whether the configured seal (cloud KMS/HSM) is reachable.\nRead-only ops signal for auto-unseal clusters.\nDoes not seal or unseal the node."),
  ep("rotate", "sys/rotate", "seal", US, US, "Rotate the encryption key used for storage (sudo).\nInstalls a new key term; old terms remain for decrypt.\nRoot-protected — schedule carefully.\nCheck progress via sys/key-status.", { root: true }),
  ep("rotate-config", "sys/rotate/config", "seal", R, U, "Configure automatic encryption key rotation (often sudo to write).\nSets max TTL / enabled flags for auto-rotate.\nRead config without rotating immediately.\nPairs with manual sys/rotate.", { root: true }),
  ep("step-down", "sys/step-down", "seal", US, US, "Ask the active HA node to step down (sudo).\nTriggers leadership transfer to a standby.\nUseful for graceful maintenance on the active node.\nRoot-protected cluster operation.", { root: true }),
  ep("raw", "sys/raw/*", "seal", RS, CRUDS, "Raw physical storage access under sys/raw/* (sudo) — dangerous.\nBypasses logical backends; can corrupt data if misused.\nRoot-protected escape hatch for support/recovery.\nPrefer normal secret engine APIs whenever possible.", { root: true }),

  // —— Config / misc ——
  ep("config-cors", "sys/config/cors", "config", RS, CRUDS, "Configure CORS origins/headers for the Vault API (sudo).\nNeeded when browsers call Vault cross-origin.\nRoot-protected global config.\nDoes not replace auth/ACL controls.", { root: true }),
  ep("config-ui-headers", "sys/config/ui/headers/*", "config", RLS, CRUDLS, "Custom HTTP headers for the Vault UI responses (sudo).\nSet security headers (CSP, etc.) for UI traffic.\nRoot-protected UI configuration.\nSeparate from API CORS settings.", { root: true }),
  ep("config-ui-custom-messages", "sys/config/ui/custom-messages/*", "config", RL, CRUDL, "CRUD Vault UI custom messages at sys/config/ui/custom-messages/*.\nBanner/announcement content shown in the UI.\nList/create under the collection path; manage by :id.\nUI operator configuration — not secret data."),
  ep("config-ui-login-default-auth", "sys/config/ui/login/default-auth/*", "config", RL, CRUDL, "Configure default UI login auth methods at sys/config/ui/login/default-auth/*.\nControls which auth methods the UI presents by default.\nNamespace-aware (root or child).\nUI login UX configuration."),
  ep("config-oauth-resource-server", "sys/config/oauth-resource-server/*", "config", RL, CRUDL, "Configure OAuth resource-server mounts at sys/config/oauth-resource-server/* (Enterprise).\nRegisters resource servers for OAuth-protected Vault access.\nRequires Vault Enterprise 2.1+.\nManage by name or id subpaths.", { enterprise: true }),
  ep("oauth-resource-server", "sys/oauth-resource-server/*", "config", RL, RL, "OAuth resource-server metadata and authorization-details types (Enterprise).\nRead protected-resource metadata and ADT schemas.\nCompanion to sys/config/oauth-resource-server.\nEnterprise OAuth resource-server feature.", { enterprise: true }),
  ep("config-group-policy", "sys/config/group-policy-application", "config", R, U, "How group policies combine across namespaces (Enterprise).\nControls group policy application behavior.\nRead/update this config endpoint.\nAffects identity group → policy resolution.", { enterprise: true }),
  ep("config-reload", "sys/config/reload/*", "config", U, U, "Reload selected config subsystems (e.g. license) via sys/config/reload/*.\nApply certain config changes without full restart.\nUpdate capability on the reload path.\nNot a general SIGHUP for all settings."),
  ep("config-state", "sys/config/state/sanitized", "config", R, R, "Sanitized running configuration (secrets stripped).\nSafe-ish view of effective config for debugging.\nRead-only introspection.\nDoes not expose raw unseal keys or credentials."),
  ep("capabilities", "sys/capabilities", "config", U, U, "Query which capabilities a token has on given paths.\nPOST a token + path list; returns capability map.\nUseful to debug ACL surprises.\nRelated: capabilities-self and capabilities-accessor."),
  ep("capabilities-self", "sys/capabilities-self", "config", U, U, "Same as sys/capabilities for the calling token.\nNo need to pass another token string.\nHandy “what can I do?” check for the current client.\nStill requires update on this path."),
  ep("capabilities-accessor", "sys/capabilities-accessor", "config", U, U, "Query capabilities by token accessor instead of token ID.\nUseful when you have accessors from audit/list ops.\nDoes not require the raw token string.\nAdmin debugging companion to sys/capabilities."),
  ep("loggers", "sys/loggers", "config", RS, CRUDS, "List or reset all Vault loggers at sys/loggers (often sudo).\nVerbosity controls for the Vault process.\nRoot-restricted operational endpoint.\nPer-logger paths under sys/loggers/:name.", { root: true }),
  ep("loggers-name", "sys/loggers/*", "config", RS, CRUDS, "Read/update/delete a named logger level at sys/loggers/:name (often sudo).\nTemporarily raise verbosity for one subsystem.\nRoot-restricted — can flood logs and expose detail.\nDelete resets that logger to defaults.", { root: true }),
  ep("locked-users", "sys/locked-users", "config", R, R, "List users locked by user-lockout at sys/locked-users.\nShows mount accessor + alias identifiers currently locked.\nRead-only inventory for unlock operations.\nUnlock via sys/locked-users/:mount/unlock/:alias."),
  ep("locked-users-unlock", "sys/locked-users/+/unlock/*", "config", U, U, "Unlock a locked user at sys/locked-users/:mount_accessor/unlock/:alias-identifier.\nClears user-lockout state after failed logins.\nNeeds update capability.\nMount accessor comes from the locked-users list."),
  ep("well-known", "sys/well-known", "config", RL, RL, "List well-known labels registered at sys/well-known.\nDiscovery helpers for standardized metadata URLs.\nRead/list only on the collection.\nPer-label reads under sys/well-known/:label."),
  ep("well-known-label", "sys/well-known/*", "config", R, R, "Read a well-known label document at sys/well-known/:label.\nServes discovery metadata for that label.\nRead-only.\nCollection listing is sys/well-known."),
  ep("internal-ui-mounts", "sys/internal/ui/mounts/*", "config", R, R, "UI helper listing mounts visible to the current token.\nPowers the Vault UI mount browser.\nRead-only; not a substitute for sys/mounts admin APIs.\nInternal/UI-oriented — stable enough for UI clients."),
  ep("internal-ui-namespaces", "sys/internal/ui/namespaces", "config", R, R, "UI helper listing namespaces visible to the token (Enterprise).\nPowers namespace switcher in the UI.\nRead-only internal/UI path.\nNot a substitute for sys/namespaces admin APIs.", { enterprise: true }),
  ep("internal-ui-resultant-acl", "sys/internal/ui/resultant-acl", "config", R, R, "UI helper returning the caller’s resultant ACL.\nSummarizes effective capabilities for the UI.\nRead-only internal path.\nUseful when debugging unexpected UI denials."),
  ep("internal-ui-feature", "sys/internal/ui/feature-flags", "config", R, R, "UI helper listing feature flags visible to the client.\nPowers gated UI features.\nRead-only internal path.\nNot the same as sys/activation-flags admin API."),
  ep("internal-ui-default-auth", "sys/internal/ui/default-auth-methods", "config", R, R, "UI helper for default auth methods presentation.\nRead-only companion to login default-auth config.\nInternal/UI path.\nConfigure defaults under sys/config/ui/login/default-auth."),
  ep("internal-ui-messages", "sys/internal/ui/authenticated-messages", "config", R, R, "UI helper for authenticated custom messages.\nRead-only; messages are configured under custom-messages.\nInternal/UI path.\nUnauthenticated twin exists for pre-login banners."),
  ep("internal-ui-messages-public", "sys/internal/ui/unauthenticated-messages", "config", R, R, "UI helper for unauthenticated custom messages.\nShown before login when configured.\nRead-only internal path.\nConfigure via sys/config/ui/custom-messages."),
  ep("internal-counters", "sys/internal/counters/*", "config", R, R, "Client-count / activity metrics at sys/internal/counters/* (cluster-wide).\nSubpaths include activity, activity/export, activity/monthly, entities, tokens.\nMonthly granularity only — start_time/end_time normalize to calendar months.\nEnterprise billing-period rules differ from Community time ranges.\nCurrent-month new_clients may be estimated; prior months are exact."),
  ep("internal-openapi", "sys/internal/specs/openapi", "config", R, R, "OpenAPI/Swagger spec for the Vault HTTP API at sys/internal/specs/openapi.\nMachine-readable API description for tooling.\nRead-only.\nInternal/specs path — useful for codegen and explorers."),
  ep("internal-inspect", "sys/internal/inspect/*", "config", RLS, RLS, "Internal inspect/debug endpoints under sys/internal/inspect/* (sudo).\nLow-level router/inspect tooling for support.\nRoot-protected; not for application policies.\nPrefer metrics/pprof for routine diagnostics.", { root: true }),
  ep("metrics", "sys/metrics", "config", R, R, "Telemetry metrics in Prometheus or JSON formats.\nScrape for monitoring dashboards and alerts.\nUsually needs a token with read on sys/metrics.\nDoes not include audit event payloads."),
  ep("pprof", "sys/pprof/*", "config", R, R, "Go pprof profiles (CPU, heap, goroutine, …) under sys/pprof/*.\nFor performance debugging of the Vault process.\nProtect tightly — profiles can expose sensitive stacks.\nOps/SRE use only."),
  ep("experiments", "sys/experiments", "config", R, R, "Lists enabled Vault experiments / feature flags on the node.\nRead-only discovery of experimental knobs.\nNot the same as Enterprise activation-flags.\nUseful when verifying preview features."),
  ep("activation-flags", "sys/activation-flags/*", "config", U, U, "Activate opt-in Enterprise features (e.g. SCIM) under sys/activation-flags/*.\nOne-way activation style flags for gated features.\nEnterprise only.\nRequired before some beta APIs accept traffic.", { enterprise: true }),

  // —— Free-form ——
  ep("custom", "", "custom", RL, CRUDLS, "Free-form ACL path for any sys/… or identity/… pattern.\nUse when no curated catalog entry fits.\nApply exact or prefix scope as needed.\nPick capabilities to match the target API verbs."),
];

export function getSysEndpoint(id: string): SysEndpoint {
  return SYS_ENDPOINTS.find((e) => e.id === id) ?? SYS_ENDPOINTS[SYS_ENDPOINTS.length - 1];
}