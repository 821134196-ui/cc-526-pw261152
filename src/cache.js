import { canonicalJson, sha256 } from './util.js';

/*
 * Permission-scoped query cache.
 *
 * The cache key includes:
 *  - registry version (rule changes never reuse old results),
 *  - role id AND a fingerprint of everything the role is allowed to see,
 *  - the normalized intent with row-scope predicates materialized,
 *  - the content hash of every data partition that would be read.
 *
 * There is no "invalidate on role change" step to forget: a different
 * permission set simply produces a different key. A defense-in-depth check
 * compares the stored ACL fingerprint on read and evicts on mismatch.
 */

export function scopeFingerprint(role) {
  return sha256(canonicalJson({
    id: role.id,
    metrics: [...role.allowedMetrics].sort(),
    fields: [...role.allowedFields].sort(),
    ops: [...role.allowedOps].sort(),
    rowScope: role.rowScope ?? {},
    maxRangeDays: role.maxRangeDays,
    maxLimit: role.maxLimit,
    minCohort: role.minCohort,
    canExport: role.canExport,
  }));
}

export function cacheKey({ registryVersion, roleId, aclFingerprint, intent, partitionHashes, anchorDate }) {
  return sha256(canonicalJson({
    v: 'rulegate.cache/v1',
    registryVersion,
    roleId,
    aclFingerprint,
    intent,
    partitionHashes,
    anchorDate,
  }));
}

export class QueryCache {
  constructor({ maxEntries = 500 } = {}) {
    this.maxEntries = maxEntries;
    this.entries = new Map();
    this.inflight = new Map();
    this.stats = { hits: 0, misses: 0, evictions: 0, denied: 0, coalesced: 0 };
  }

  get(key, { aclFingerprint, roleId = null }) {
    const entry = this.entries.get(key);
    if (!entry) { this.stats.misses += 1; return null; }
    if (entry.aclFingerprint !== aclFingerprint || (roleId !== null && entry.roleId !== roleId)) {
      // Should be unreachable because the fingerprint is part of the key,
      // but never serve a result to a different permission set.
      this.stats.denied += 1;
      this.entries.delete(key);
      return null;
    }
    entry.hits += 1;
    entry.lastAccess = Date.now();
    // LRU touch
    this.entries.delete(key);
    this.entries.set(key, entry);
    this.stats.hits += 1;
    return entry.value;
  }

  put(key, value, { aclFingerprint, registryVersion, roleId, meta }) {
    if (this.entries.size >= this.maxEntries) {
      const oldest = [...this.entries.entries()].sort((a, b) => a[1].lastAccess - b[1].lastAccess)[0];
      if (oldest) { this.entries.delete(oldest[0]); this.stats.evictions += 1; }
    }
    this.entries.set(key, {
      value,
      aclFingerprint,
      registryVersion,
      roleId,
      meta,
      createdAt: Date.now(),
      lastAccess: Date.now(),
      hits: 0,
    });
  }

  clear() { this.entries.clear(); }
  size() { return this.entries.size; }
  describe() {
    return [...this.entries.values()].map((e) => ({
      registryVersion: e.registryVersion,
      roleId: e.roleId,
      createdAt: new Date(e.createdAt).toISOString(),
      hits: e.hits,
      queryId: e.meta?.queryId ?? null,
    }));
  }
}
