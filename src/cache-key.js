'use strict';

const crypto = require('node:crypto');

const REQUIRED_KEY_FIELDS = [
  'tenant',
  'tokenFingerprint',
  'resource',
  'action',
  'policyVersion',
  'revocationEpoch',
];

function buildCacheKey(parts) {
  for (const field of REQUIRED_KEY_FIELDS) {
    const value = parts[field];
    if (value === undefined || value === null || value === '') {
      throw new TypeError(`cache key missing required field: ${field}`);
    }
  }
  return [
    'extauth',
    'v1',
    String(parts.tenant),
    String(parts.tokenFingerprint),
    String(parts.resource),
    String(parts.action),
    String(parts.policyVersion),
    String(parts.revocationEpoch),
  ].join('|');
}

function shardIndexForKey(key, shardCount) {
  if (!Number.isInteger(shardCount) || shardCount <= 0) {
    throw new TypeError('shardCount must be a positive integer');
  }
  const digest = crypto.createHash('sha256').update(key).digest();
  return digest.readUInt32BE(0) % shardCount;
}

function hashRoleDependencies(roleDependencies) {
  const normalized = [...(roleDependencies ?? [])].map(String).sort();
  return crypto.createHash('sha256').update(normalized.join(',')).digest('hex');
}

module.exports = {
  REQUIRED_KEY_FIELDS,
  buildCacheKey,
  shardIndexForKey,
  hashRoleDependencies,
};
