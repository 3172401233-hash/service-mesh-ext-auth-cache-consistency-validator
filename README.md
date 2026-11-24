# service-mesh-ext-auth-cache-consistency-validator

验证 ext-auth 缓存键、策略版本和失效。

本模块是一个**纯本地的一致性校验器**：它不连接任何真实鉴权服务，不发起网络请求。
鉴权结果（allow / deny / timeout）由调用方以记录形式传入，校验器只负责判断
每次请求能否安全复用共享分片缓存中的既有结果。

## 运行环境

- Node.js 24.16.0（仅使用 `node:` 内置模块，无第三方依赖）

## 缓存键

`buildCacheKey` 生成的缓存键覆盖以下字段，任一变化都会产生新键，旧 allow 自然失效：

- 租户（tenant）
- 令牌指纹（tokenFingerprint）——令牌刷新/撤销后旧键不再命中
- 资源与动作（resource + action）
- 路由策略版本（policyVersion）
- 撤销 epoch（revocationEpoch）

除键本身外，命中时还会逐字段比对条目元数据与角色依赖哈希，防止键碰撞或伪造条目被复用。

## 一致性规则

- **令牌撤销/刷新**：`revocationEpoch` 或指纹变化 → 旧 allow 进入失效范围，并输出陈旧 allow 区间。
- **策略更新**：旧 `policyVersion` 的条目被标记为 `policy-version-superseded`，不得复用。
- **区域下发滞后**：控制面 rollout 未完成时，某区域写入的缓存不能代表其他区域的决策
  （`partial-rollout-cross-region`）；请求按本区域实际生效版本求键。
- **负缓存**：缓存的 deny 原样返回 deny，绝不默认放行。
- **鉴权超时**：timeout/error 结果不可缓存；无可用缓存时失败关闭（fail-closed），返回 deny。

## 输出

`evaluate(request)` 返回：

| 字段 | 含义 |
| --- | --- |
| `decision` | 最终决策：`allow` / `deny` |
| `cacheHit` | 命中来源：`allow` / `deny` / `expired` / `collision` / `stale` / `none` |
| `cacheSource` | 命中的分片编号（未命中为 `null`） |
| `invalidate` | 需失效的缓存键、分片及原因列表 |
| `staleAllowWindow` | 陈旧 allow 仍生效的时间区间 `{ from, to }`，无则为 `null` |
| `reason` | 决策/错误原因 |

## 使用示例

```js
const { ExtAuthCacheValidator } = require('./src/validator');

const validator = new ExtAuthCacheValidator({ shardCount: 16 });

validator.recordAuthResult({
  tenant: 't1', subject: 'u1', tokenFingerprint: 'fp-1', scope: 'read',
  resource: 'orders/42', action: 'GET', policyVersion: 'v1',
  revocationEpoch: 'e1', roleDependencies: ['role:reader'],
  result: 'allow', ttlMs: 60_000, issuedAt: Date.now(), region: 'region-1',
});

const verdict = validator.evaluate({
  tenant: 't1', subject: 'u1', tokenFingerprint: 'fp-1', scope: 'read',
  resource: 'orders/42', action: 'GET', policyVersion: 'v1',
  revocationEpoch: 'e1', roleDependencies: ['role:reader'],
  region: 'region-1', requestTime: Date.now(),
  controlPlane: { rollout: { 'region-1': 'v1' } },
});
```

## 测试

```sh
node --test
```

覆盖：令牌撤销、令牌刷新、策略更新、区域下发滞后、缓存键碰撞（含伪造条目）、
负缓存、鉴权超时、TTL 过期、角色依赖变更。
