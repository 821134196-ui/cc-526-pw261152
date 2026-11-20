# RuleGate · 受限数据规则查询台

一个零依赖的 Node.js 应用：用户用**受限的自然语言**提问，系统只把它映射到**已登记**的字段、指标和操作；
解析不了、命中 PII、越权、超范围，都会给出**结构化拒绝**而不是猜测执行。
每条结果都附带**规则版本、过滤条件、来源证据**，缓存按权限隔离，规则升级后旧查询仍可按原版本复现。

```
node src/server.js     # http://127.0.0.1:4173
npm test               # 84 个测试（registry / parser / authorize / service / http / ui）
```

需要 Node ≥ 20，无第三方依赖、无构建步骤、无需联网。

## 演示账号

| 账号 | 密码 | 角色 | 能力 |
| --- | --- | --- | --- |
| `alice` | `analyst-demo-2026` | 数据分析师 | 全区域，400 天，可导出，不可读审计 |
| `wang` | `west-demo-2026` | 华东销售 | 行权限 `region=华东`，180 天，≤100 行，minCohort 5，不可导出 |
| `li` | `east-demo-2026` | 华南销售 | 行权限 `region=华南`，180 天，≤50 行，minCohort 5，不可导出 |
| `audit` | `audit-demo-2026` | 审计员 | 只读全区域 + 审计链，可导出 |
| `admin` | `rules-demo-2026` | 规则管理员 | 校验/发布规则，可读审计 |

登录页会自动列出这些账号，点击即填充。密码用 scrypt 存储，会话走 HttpOnly + SameSite=Strict Cookie。

## 一条查询经历了什么

1. **钉住规则版本** — 请求可指定 `v1/v2/v3` 或版本哈希；缺省取当前版本。后续所有步骤只用这一份**不可变快照**，
   快照哈希 = `sha256(canonical-json(doc))`。
2. **受限解析**（`src/parser.js`）— 词法 + 分类映射，只认登记过的别名。输出意图或一组 `ParseFailure`：
   `UNRECOGNIZED_TERM`、`AMBIGUOUS_TERM`、`DANGEROUS_INTENT`、`FIELD_PII_FORBIDDEN`、
   `OP_INCOMPATIBLE`、`TIME_RANGE_INVALID`、`LIMIT_EXCEEDED`、`SCOPE_VIOLATION`… 每条带原文 span、提示与候选。
   **用户文本永远不进入数据层**——执行时只按登记列 id 和共享的算子枚举过滤。
3. **权限裁决**（`src/authorize.js`）— 对**钉住的角色**逐条检查：
   指标 ⊆ `allowedMetrics`、过滤字段 ⊆ `allowedFields`、算子 ⊆ `allowedOps`、`rowScope` 包含关系、
   `rangeDays ≤ maxRangeDays`、`limit ≤ maxLimit`。任一不满足 → HTTP 403 + 违规清单，不执行查询。
4. **确定性执行**（`src/engine.js` + `src/data.js`）— 合成订单数据按 `sha256(seed+month)` 生成，按月分区落盘并记录内容哈希。
   查询固定使用 `asOf`（默认 2026-11-20 UTC），因此「最近 30 天」在同一 `asOf` 下永远指同一区间。
   分组统计支持 sum / count / count_distinct / ratio，并在角色 `minCohort` 阈值下抑制小样本组。
5. **证据链**（`rulegate.evidence/v1`）— 记录 registryVersion、角色与 ACL、解析映射、意图、分区哈希、
   扫描/命中行数、输出哈希、证据哈希。响应头同时给出 `evidenceHash`。
6. **审计账本**（`src/audit.js`）— 追加写 JSONL，每条含 `seq / prevHash / hash`，哈希链可验证；
   查询、拒绝、复现、导出都入账。导出审计包会先写一条 `audit.export` 记录，再把该记录之前的链打包，保证「导出行为本身可审计」。

## 缓存不跨权限

缓存键由以下内容共同决定：

```
registryVersion + roleId + ACL指纹 + 规范化意图 + 分区内容哈希 + anchorDate
```

其中 ACL 指纹覆盖角色允许的指标/字段/算子、行权限、上限与 minCohort。读取时还会**再次比对**条目里存的 ACL 指纹，
不一致直接拒绝复用并计入 `stats.denied`（测试里专门伪造过指纹，验证读取侧仍会拦下）。
命中缓存时返回的是**新的 queryId**，证据里保留 `cache.hit / sourceQueryId / cacheKey`，便于追溯。

## 旧查询可复现

`POST /api/replay/:queryId` 会用**原始 registryVersion** 重新执行，即使当前最新规则已升到 v3：

- 原始输出哈希与复现输出哈希一致 → `deterministic: true`
- 若该规则版本已从注册表移除 → 409 `REGISTRY_VERSION_MISSING`（不会静默用新规则替代）
- 只有查询发起角色或具备审计权限的角色可以复现，跨角色复现 → 403 `REPLAY_FORBIDDEN`
- 每次复现写 `query.replayed` 审计记录

## 并发规则发布

发布必须携带 `If-Match: "<expectedVersion>"`（或 body 里的 `expectedVersion`）：

- 缺失 → 400 `PRECONDITION_REQUIRED`，防止无条件覆盖
- 版本已变 → 409 `RULE_VERSION_CONFLICT`
- 角色无 `canPublish` → 403
- 文档校验失败 → 422 `RULE_VALIDATION_FAILED`（PII 授权、未知指标字段、非法算子、minCohort 越界…）
- 新版本引入新的歧义别名 → 409 `AMBIGUITY_ACK_REQUIRED`，需显式 `acknowledgeAmbiguities`

页面「一致性演练」里可以同时发出两次同 `expectedVersion` 的发布，稳定得到 1×201 + 1×409。

## 页面

- **查询台**：受限词表（只显示当前角色可用的指标/字段/取值）、示例、结果表、解析映射、拒绝卡片、证据面板、导出。
- **规则登记表**：版本时间线、指标/字段/角色/歧义登记情况、草稿校验与发布。
- **审计与证据**：哈希链状态、账本列表、链校验、JSON 导出、按 queryId 复现。
- **一致性演练**：歧义与拒绝用例（标注所需角色）、并发发布、缓存与分区完整性。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| POST | `/api/login` `/api/logout` | 登录 / 登出 |
| GET | `/api/session` | 当前会话、角色、当前规则 |
| GET | `/api/registry` `/api/registry/versions` `/api/registry/:ref` | 规则快照与版本 |
| GET | `/api/roles` | 角色能力表 |
| POST | `/api/query` | `{ text, registryRef?, cacheBypass? }` |
| POST | `/api/replay/:queryId` | 按原规则版本复现 |
| POST | `/api/export/query/:queryId` | 导出结果 CSV（含证据头） |
| GET | `/api/audit` `/api/audit/verify` `/api/audit/export` | 账本 / 校验 / 打包 |
| POST | `/api/rules/validate` `/api/rules/publish` | 草稿校验 / 发布 |
| GET | `/api/cache` `/api/cache/clear` `/api/integrity` | 缓存与分区完整性 |

拒绝响应统一为 `{ ok: false, stage, registry, rejections: [{ code, title, message, span, hint, suggestions }], audit }`，
`stage` 区分 `parse` 与 `authorize`。

## 目录

```
src/util.js        canonical JSON、sha256、日期、CSV 转义（=+-@ 前缀中和）
src/registry.js    字段/指标/角色登记、文档校验、歧义计算、版本发布
src/data.js        确定性分区生成与内容哈希
src/parser.js      受限词法/语法与拒绝码
src/authorize.js   意图 × 角色裁决（含 rowScope 包含关系）
src/engine.js      谓词编译、分组聚合、证据构建
src/cache.js       权限隔离缓存
src/audit.js       哈希链账本与导出包
src/service.js     编排：查询 / 复现 / 导出 / 发布
src/auth.js        scrypt 账号、会话、登录限流
src/server.js      HTTP 路由、安全头、静态资源
public/            单页前端（无框架）
test/              node:test 用例（含最小 DOM 与恶意字符串渲染测试）
```

运行时数据在 `data/`（分区）与 `.state/`（审计、复现快照），均已在 `.gitignore` 中。
