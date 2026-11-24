'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { ExtAuthCacheValidator } = require('../src/validator');
const { buildCacheKey } = require('../src/cache-key');
const { SharedShardCache } = require('../src/shared-cache');

const T0 = 1_700_000_000_000;

function makeValidator() {
  return new ExtAuthCacheValidator({ shardCount: 8 });
}

function baseRecord(overrides = {}) {
  return {
    tenant: 'tenant-a',
    subject: 'user-1',
    tokenFingerprint: 'fp-aaa',
    scope: 'read',
    resource: 'orders/42',
    action: 'GET',
    policyVersion: 'v1',
    revocationEpoch: 'epoch-1',
    roleDependencies: ['role:reader', 'role:orders'],
    result: 'allow',
    ttlMs: 60_000,
    issuedAt: T0,
    region: 'region-1',
    ...overrides,
  };
}

function baseRequest(overrides = {}) {
  return {
    tenant: 'tenant-a',
    subject: 'user-1',
    tokenFingerprint: 'fp-aaa',
    scope: 'read',
    resource: 'orders/42',
    action: 'GET',
    policyVersion: 'v1',
    revocationEpoch: 'epoch-1',
    roleDependencies: ['role:orders', 'role:reader'],
    region: 'region-1',
    requestTime: T0 + 1_000,
    controlPlane: { rollout: { 'region-1': 'v1', 'region-2': 'v1' } },
    ...overrides,
  };
}

test('valid allow cache hit reuses cache and allows', () => {
  const v = makeValidator();
  v.recordAuthResult(baseRecord());
  const out = v.evaluate(baseRequest());
  assert.equal(out.decision, 'allow');
  assert.equal(out.cacheHit, 'allow');
  assert.equal(typeof out.cacheSource, 'number');
  assert.equal(out.reason, 'cache-hit');
  assert.equal(out.staleAllowWindow, null);
});

test('token revocation invalidates old allow and reports stale window', () => {
  const v = makeValidator();
  const rec = v.recordAuthResult(baseRecord());
  const out = v.evaluate(baseRequest({ revocationEpoch: 'epoch-2' }));
  assert.equal(out.decision, 'deny');
  assert.notEqual(out.cacheHit, 'allow');
  assert.deepEqual(out.staleAllowWindow, { from: T0, to: T0 + 60_000 });
  assert.ok(out.invalidate.some((i) => i.key === rec.key));
  assert.ok(
    out.invalidate.some((i) => i.reason === 'revocation-epoch-changed'),
  );
});

test('token refresh (new fingerprint) cannot reuse old allow', () => {
  const v = makeValidator();
  v.recordAuthResult(baseRecord());
  const out = v.evaluate(baseRequest({ tokenFingerprint: 'fp-bbb' }));
  assert.equal(out.decision, 'deny');
  assert.equal(out.cacheHit, 'none');
  assert.equal(out.reason, 'cache-miss');
});

test('policy update supersedes old allow entries', () => {
  const v = makeValidator();
  const rec = v.recordAuthResult(baseRecord());
  const out = v.evaluate(
    baseRequest({
      policyVersion: 'v2',
      controlPlane: { rollout: { 'region-1': 'v2', 'region-2': 'v2' } },
    }),
  );
  assert.equal(out.decision, 'deny');
  assert.equal(out.reason, 'cache-miss');
  assert.ok(out.invalidate.some((i) => i.key === rec.key));
  assert.ok(out.invalidate.some((i) => i.reason === 'policy-version-superseded'));
  assert.deepEqual(out.staleAllowWindow, { from: T0, to: T0 + 60_000 });
});

test('regional rollout lag: old regional allow cannot serve global decision', () => {
  const v = makeValidator();
  // region-1 already on v2, region-2 still on v1 (partial rollout).
  v.recordAuthResult(baseRecord({ policyVersion: 'v2', region: 'region-1' }));
  v.recordAuthResult(baseRecord({ policyVersion: 'v1', region: 'region-1' }));

  // Request hits region-2 whose effective version is still v1.
  const out = v.evaluate(
    baseRequest({
      policyVersion: 'v2',
      region: 'region-2',
      controlPlane: { rollout: { 'region-1': 'v2', 'region-2': 'v1' } },
    }),
  );
  assert.equal(out.decision, 'deny');
  assert.equal(out.reason, 'partial-rollout-cross-region');
  assert.notEqual(out.cacheHit, 'allow');

  // The v2 entry cached by region-1 must not decide for region-2 either.
  const out2 = v.evaluate(
    baseRequest({
      policyVersion: 'v2',
      region: 'region-2',
      controlPlane: { rollout: { 'region-1': 'v2', 'region-2': 'v1' } },
      resource: 'orders/42',
    }),
  );
  assert.equal(out2.decision, 'deny');
});

test('same-region entry is reusable during partial rollout', () => {
  const v = makeValidator();
  v.recordAuthResult(baseRecord({ policyVersion: 'v2', region: 'region-1' }));
  const out = v.evaluate(
    baseRequest({
      policyVersion: 'v2',
      region: 'region-1',
      controlPlane: { rollout: { 'region-1': 'v2', 'region-2': 'v1' } },
    }),
  );
  assert.equal(out.decision, 'allow');
  assert.equal(out.cacheHit, 'allow');
});

test('cache keys differ across tenants, tokens, resources, actions, versions, epochs', () => {
  const base = {
    tenant: 't1',
    tokenFingerprint: 'fp',
    resource: 'r',
    action: 'GET',
    policyVersion: 'v1',
    revocationEpoch: 'e1',
  };
  const baseKey = buildCacheKey(base);
  const variants = [
    { tenant: 't2' },
    { tokenFingerprint: 'fp2' },
    { resource: 'r2' },
    { action: 'POST' },
    { policyVersion: 'v2' },
    { revocationEpoch: 'e2' },
  ];
  for (const variant of variants) {
    assert.notEqual(buildCacheKey({ ...base, ...variant }), baseKey);
  }
  assert.throws(() => buildCacheKey({ ...base, tenant: '' }), TypeError);
});

test('forged entry with colliding key but mismatched metadata is rejected', () => {
  const cache = new SharedShardCache(8);
  const v = new ExtAuthCacheValidator({ cache });
  const request = baseRequest();
  const key = buildCacheKey({
    tenant: request.tenant,
    tokenFingerprint: request.tokenFingerprint,
    resource: request.resource,
    action: request.action,
    policyVersion: 'v1',
    revocationEpoch: 'epoch-1',
  });
  cache.set(key, {
    key,
    tenant: 'tenant-evil',
    subject: 'user-1',
    tokenFingerprint: 'fp-aaa',
    scope: 'read',
    resource: 'orders/42',
    action: 'GET',
    policyVersion: 'v1',
    revocationEpoch: 'epoch-1',
    roleDepsHash: 'x',
    result: 'allow',
    issuedAt: T0,
    ttlMs: 60_000,
    expiresAt: T0 + 60_000,
    region: 'region-1',
  });
  const out = v.evaluate(request);
  assert.equal(out.decision, 'deny');
  assert.equal(out.cacheHit, 'collision');
  assert.equal(out.reason, 'cache-key-collision');
  assert.ok(out.invalidate.some((i) => i.key === key));
});

test('negative cache (deny) is honored and never defaults to allow', () => {
  const v = makeValidator();
  v.recordAuthResult(baseRecord({ result: 'deny' }));
  const out = v.evaluate(baseRequest());
  assert.equal(out.decision, 'deny');
  assert.equal(out.cacheHit, 'deny');
  assert.equal(out.reason, 'negative-cache-hit');
});

test('auth timeout is not cacheable and fails closed', () => {
  const v = makeValidator();
  const rec = v.recordAuthResult(baseRecord({ result: 'timeout' }));
  assert.equal(rec.cached, false);
  const out = v.evaluate(baseRequest({ authStatus: 'timeout' }));
  assert.equal(out.decision, 'deny');
  assert.equal(out.cacheHit, 'none');
  assert.equal(out.reason, 'auth-timeout');
});

test('expired entries are not reused and are invalidated', () => {
  const v = makeValidator();
  const rec = v.recordAuthResult(baseRecord());
  const out = v.evaluate(baseRequest({ requestTime: T0 + 61_000 }));
  assert.equal(out.decision, 'deny');
  assert.equal(out.reason, 'cache-expired');
  assert.ok(out.invalidate.some((i) => i.key === rec.key && i.reason === 'ttl-expired'));
});

test('role dependency change invalidates cached allow', () => {
  const v = makeValidator();
  v.recordAuthResult(baseRecord());
  const out = v.evaluate(
    baseRequest({ roleDependencies: ['role:reader'] }),
  );
  assert.equal(out.decision, 'deny');
  assert.equal(out.reason, 'role-dependencies-changed');
});
