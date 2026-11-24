'use strict';

const { buildCacheKey, hashRoleDependencies } = require('./cache-key');
const { SharedShardCache } = require('./shared-cache');

const REUSABLE_RESULTS = new Set(['allow', 'deny']);

class ExtAuthCacheValidator {
  constructor({ shardCount = 16, cache } = {}) {
    this.cache = cache ?? new SharedShardCache(shardCount);
  }

  recordAuthResult(record) {
    const required = [
      'tenant', 'subject', 'tokenFingerprint', 'scope', 'resource', 'action',
      'policyVersion', 'revocationEpoch', 'result', 'ttlMs', 'issuedAt', 'region',
    ];
    for (const field of required) {
      if (record[field] === undefined || record[field] === null) {
        throw new TypeError(`auth result record missing field: ${field}`);
      }
    }
    if (!REUSABLE_RESULTS.has(record.result)) {
      return { cached: false, reason: `result-${record.result}-not-cacheable` };
    }
    const key = buildCacheKey(record);
    const entry = {
      key,
      tenant: String(record.tenant),
      subject: String(record.subject),
      tokenFingerprint: String(record.tokenFingerprint),
      scope: String(record.scope),
      resource: String(record.resource),
      action: String(record.action),
      policyVersion: String(record.policyVersion),
      revocationEpoch: String(record.revocationEpoch),
      roleDepsHash: hashRoleDependencies(record.roleDependencies),
      result: record.result,
      issuedAt: record.issuedAt,
      ttlMs: record.ttlMs,
      expiresAt: record.issuedAt + record.ttlMs,
      region: record.region,
    };
    const shard = this.cache.set(key, entry);
    return { cached: true, key, shard, expiresAt: entry.expiresAt };
  }

  evaluate(request) {
    const now = request.requestTime;
    if (typeof now !== 'number') {
      throw new TypeError('request.requestTime must be a number (ms epoch)');
    }
    const rollout = request.controlPlane?.rollout ?? {};
    const effectiveVersion = rollout[request.region];
    const rolloutComplete =
      effectiveVersion !== undefined &&
      effectiveVersion === String(request.policyVersion) &&
      Object.values(rollout).every((v) => v === String(request.policyVersion));

    const invalidate = [];
    const seenKeys = new Set();
    const markInvalid = (key, shard, why) => {
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        invalidate.push({ key, shard, reason: why });
      }
    };

    const sameIdentity = (e) =>
      e.tenant === String(request.tenant) &&
      e.tokenFingerprint === String(request.tokenFingerprint) &&
      e.resource === String(request.resource) &&
      e.action === String(request.action);

    for (const { key, shard, entry } of this.cache.findAll(
      (e) => sameIdentity(e) && e.revocationEpoch !== String(request.revocationEpoch),
    )) {
      markInvalid(key, shard, 'revocation-epoch-changed');
    }
    for (const { key, shard, entry } of this.cache.findAll(
      (e) => sameIdentity(e) && e.policyVersion !== String(request.policyVersion),
    )) {
      markInvalid(key, shard, 'policy-version-superseded');
    }

    const staleAllows = this.cache.findAll(
      (e) =>
        sameIdentity(e) &&
        e.result === 'allow' &&
        e.expiresAt > now &&
        (e.policyVersion !== String(effectiveVersion) ||
          e.revocationEpoch !== String(request.revocationEpoch)),
    );
    let staleAllowWindow = null;
    if (staleAllows.length > 0) {
      staleAllowWindow = {
        from: Math.min(...staleAllows.map((s) => s.entry.issuedAt)),
        to: Math.max(...staleAllows.map((s) => s.entry.expiresAt)),
      };
      for (const { key, shard } of staleAllows) {
        markInvalid(key, shard, 'stale-allow');
      }
    }

    const deny = (reason, cacheHit = 'none', cacheSource = null) => ({
      decision: 'deny',
      cacheHit,
      cacheSource,
      invalidate,
      staleAllowWindow,
      reason,
    });

    if (effectiveVersion === undefined) {
      return deny('rollout-unknown-for-region');
    }

    const key = buildCacheKey({
      tenant: request.tenant,
      tokenFingerprint: request.tokenFingerprint,
      resource: request.resource,
      action: request.action,
      policyVersion: effectiveVersion,
      revocationEpoch: request.revocationEpoch,
    });
    const entry = this.cache.get(key);

    if (!entry) {
      return deny(
        request.authStatus === 'timeout' ? 'auth-timeout' : 'cache-miss',
      );
    }
    const shard = this.cache.shardOf(key);

    if (entry.expiresAt <= now) {
      markInvalid(key, shard, 'ttl-expired');
      return deny('cache-expired', 'expired', shard);
    }
    if (
      entry.tenant !== String(request.tenant) ||
      entry.tokenFingerprint !== String(request.tokenFingerprint) ||
      entry.resource !== String(request.resource) ||
      entry.action !== String(request.action) ||
      entry.policyVersion !== String(effectiveVersion) ||
      entry.revocationEpoch !== String(request.revocationEpoch)
    ) {
      markInvalid(key, shard, 'cache-key-collision');
      return deny('cache-key-collision', 'collision', shard);
    }
    if (entry.roleDepsHash !== hashRoleDependencies(request.roleDependencies)) {
      markInvalid(key, shard, 'role-dependencies-changed');
      return deny('role-dependencies-changed', 'stale', shard);
    }
    if (!rolloutComplete && entry.region !== request.region) {
      return deny('partial-rollout-cross-region', 'stale', shard);
    }

    if (entry.result === 'deny') {
      return {
        decision: 'deny',
        cacheHit: 'deny',
        cacheSource: shard,
        invalidate,
        staleAllowWindow,
        reason: 'negative-cache-hit',
      };
    }
    return {
      decision: 'allow',
      cacheHit: 'allow',
      cacheSource: shard,
      invalidate,
      staleAllowWindow,
      reason: 'cache-hit',
    };
  }
}

module.exports = { ExtAuthCacheValidator };
