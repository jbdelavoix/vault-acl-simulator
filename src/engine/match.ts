import type { Capability, MatchCandidate, PathMatchResult, PathRule } from "./types";

/**
 * Priority comparison matching Vault's wildcardPathDescriptorComparePriority.
 * Returns true if `a` is lower priority than `b`.
 */
export function isLowerPriority(a: MatchCandidate, b: MatchCandidate): boolean {
  if (a.firstWCOrGlob !== b.firstWCOrGlob) {
    return a.firstWCOrGlob < b.firstWCOrGlob;
  }
  if (a.isPrefix !== b.isPrefix) {
    return a.isPrefix;
  }
  if (a.wildcards !== b.wildcards) {
    return a.wildcards > b.wildcards;
  }
  if (a.wcPath.length !== b.wcPath.length) {
    return a.wcPath.length < b.wcPath.length;
  }
  return a.wcPath < b.wcPath;
}

function mergeCapabilities(rules: PathRule[]): Capability[] {
  const set = new Set<Capability>();
  for (const rule of rules) {
    if (rule.capabilities.includes("deny")) {
      return ["deny"];
    }
    for (const c of rule.capabilities) set.add(c);
  }
  return [...set];
}

function groupRulesByStorageKey(rules: PathRule[]): Map<string, PathRule[]> {
  const map = new Map<string, PathRule[]>();
  for (const rule of rules) {
    // Storage key: for prefix-without-segment-wc use matchPath; for segment-wc keep full path with *
    const key = rule.hasSegmentWildcards ? rule.path : rule.isPrefix ? rule.matchPath : rule.path;
    const list = map.get(key) ?? [];
    list.push(rule);
    map.set(key, list);
  }
  return map;
}

function tryMatchSegmentWildcard(
  fullWCPath: string,
  pathParts: string[],
  rules: PathRule[],
): MatchCandidate | null {
  let firstWCOrGlob = fullWCPath.indexOf("+");
  if (firstWCOrGlob < 0) firstWCOrGlob = fullWCPath.indexOf("*");

  let currWCPath = fullWCPath;
  let isPrefix = false;
  if (currWCPath.endsWith("*")) {
    isPrefix = true;
    currWCPath = currWCPath.slice(0, -1);
  }

  const splitCurrWCPath = currWCPath.split("/");

  if (pathParts.length < splitCurrWCPath.length) return null;
  if (!isPrefix && splitCurrWCPath.length !== pathParts.length) return null;

  let wildcards = 0;

  for (let i = 0; i < splitCurrWCPath.length; i++) {
    const aclPart = splitCurrWCPath[i];
    const pathPart = pathParts[i];

    if (aclPart === "+") {
      wildcards++;
      continue;
    }
    if (aclPart === pathPart) {
      continue;
    }
    if (isPrefix && i === splitCurrWCPath.length - 1 && pathPart.startsWith(aclPart)) {
      continue;
    }
    return null;
  }

  const merged = mergeCapabilities(rules);
  const representative: PathRule = {
    ...rules[0],
    capabilities: merged,
  };

  return {
    rule: representative,
    firstWCOrGlob: firstWCOrGlob < 0 ? fullWCPath.length : firstWCOrGlob,
    wildcards,
    isPrefix,
    wcPath: currWCPath,
  };
}

function collectCandidates(requestPath: string, rules: PathRule[]): MatchCandidate[] {
  const candidates: MatchCandidate[] = [];
  const grouped = groupRulesByStorageKey(rules);

  // Exact matches (merged if duplicated)
  const exactGroup = rules.filter(
    (r) => !r.isPrefix && !r.hasSegmentWildcards && r.path === requestPath,
  );
  if (exactGroup.length > 0) {
    const merged = mergeCapabilities(exactGroup);
    candidates.push({
      rule: { ...exactGroup[0], capabilities: merged },
      firstWCOrGlob: requestPath.length,
      wildcards: 0,
      isPrefix: false,
      wcPath: requestPath,
    });
  }

  // Prefix rules (no segment wildcards): longest prefix semantics via candidate ranking
  for (const [prefix, group] of grouped) {
    const sample = group[0];
    if (!sample.isPrefix || sample.hasSegmentWildcards) continue;
    if (!requestPath.startsWith(prefix)) continue;

    const merged = mergeCapabilities(group);
    candidates.push({
      rule: { ...sample, capabilities: merged },
      firstWCOrGlob: prefix.length,
      wildcards: 0,
      isPrefix: true,
      wcPath: prefix,
    });
  }

  // Segment wildcard rules
  const pathParts = requestPath.split("/");
  for (const [fullWCPath, group] of grouped) {
    if (!group[0].hasSegmentWildcards) continue;
    const cand = tryMatchSegmentWildcard(fullWCPath, pathParts, group);
    if (cand) candidates.push(cand);
  }

  return candidates;
}

function pickWinner(candidates: MatchCandidate[]): MatchCandidate | null {
  if (candidates.length === 0) return null;

  // Exact non-prefix, non-wildcard wins immediately if present
  // (Vault checks exactRules first before prefix/wc)
  const exact = candidates.filter((c) => !c.isPrefix && c.wildcards === 0 && !c.rule.hasSegmentWildcards);
  if (exact.length > 0) {
    // Same path → merge already handled; take first (all same path)
    const deny = exact.find((c) => c.rule.capabilities.includes("deny"));
    return deny ?? exact[0];
  }

  const nonExact = candidates.filter((c) => c.isPrefix || c.rule.hasSegmentWildcards);
  if (nonExact.length === 0) return null;

  let best = nonExact[0];
  for (let i = 1; i < nonExact.length; i++) {
    if (isLowerPriority(best, nonExact[i])) {
      best = nonExact[i];
    }
  }
  return best;
}

export function matchPath(requestPath: string, rules: PathRule[]): PathMatchResult {
  let path = requestPath.trim();
  if (path.startsWith("/")) path = path.slice(1);
  // Vault API paths often include v1/ — strip common prefixes for convenience
  if (path.startsWith("v1/")) path = path.slice(3);

  const candidates = collectCandidates(path, rules);
  const winner = pickWinner(candidates);

  if (!winner) {
    return {
      requestPath: path,
      allowed: false,
      denied: true,
      capabilities: ["deny"],
      winningRule: null,
      candidates,
      explanation: "none",
    };
  }

  const caps = winner.rule.capabilities;
  const denied = caps.includes("deny") || caps.length === 0;

  return {
    requestPath: path,
    allowed: !denied,
    denied,
    capabilities: denied ? ["deny"] : caps,
    winningRule: winner.rule,
    candidates: [...candidates].sort((a, b) => {
      if (a === winner) return 1;
      if (b === winner) return -1;
      return isLowerPriority(a, b) ? -1 : 1;
    }),
    explanation: denied ? "deny" : "allow",
  };
}

export function matchPaths(paths: string[], rules: PathRule[]): PathMatchResult[] {
  return paths
    .map((p) => p.trim())
    .filter((p) => p.length > 0 && !p.startsWith("#"))
    .map((p) => matchPath(p, rules));
}

export function checkCapability(
  result: PathMatchResult,
  capability: Capability,
): boolean {
  if (result.denied) return false;
  if (capability === "deny") return result.denied;
  return result.capabilities.includes(capability);
}
