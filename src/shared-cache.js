'use strict';

const { shardIndexForKey } = require('./cache-key');

class SharedShardCache {
  constructor(shardCount = 16) {
    if (!Number.isInteger(shardCount) || shardCount <= 0) {
      throw new TypeError('shardCount must be a positive integer');
    }
    this.shardCount = shardCount;
    this.shards = Array.from({ length: shardCount }, () => new Map());
  }

  shardOf(key) {
    return shardIndexForKey(key, this.shardCount);
  }

  set(key, entry) {
    const shard = this.shardOf(key);
    this.shards[shard].set(key, entry);
    return shard;
  }

  get(key) {
    return this.shards[this.shardOf(key)].get(key) ?? null;
  }

  delete(key) {
    return this.shards[this.shardOf(key)].delete(key);
  }

  findAll(predicate) {
    const matches = [];
    for (let shard = 0; shard < this.shardCount; shard += 1) {
      for (const [key, entry] of this.shards[shard]) {
        if (predicate(entry, key)) {
          matches.push({ key, shard, entry });
        }
      }
    }
    return matches;
  }

  invalidateWhere(predicate) {
    const removed = [];
    for (const { key, shard } of this.findAll(predicate)) {
      this.shards[shard].delete(key);
      removed.push({ key, shard });
    }
    return removed;
  }
}

module.exports = { SharedShardCache };
