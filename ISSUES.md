# migears-security — Known Issues

> Summary of this module's issues. The items themselves are in [`issues/`](issues/README.md), one file
> per item: a front-matter header and a thread. This file is generated from them and can be rewritten at
> any time; edit an item, never this file.
>
> From the miGears Full-Module Code Review Report (6th round, 2026-10-01).

| | |
|---|---|
| Status | **Best state** |
| Size | src 739 lines (net) · 158 tests · 8 src files |

Legend — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs

## At a glance

| | |
|---|---|
| Unsettled | P0 0 · P1 0 · P2 0 · P3 4 · other 0 |
| Settled | 3 of 7 |
| Waiting on the owner | _nothing_ |
| Waiting on the coordinator | `P3-6` |
| Waiting on the reviewer | `P3-1`, `P3-5` |
| Deferred, owing nobody | `P3-2` |

| id | level | status | title |
|---|---|---|---|
| [`P3-1`](issues/P3-1.md) | P3 | **rejected** | `@return self<TUser>` remains a suspicious generic form (not standard … |
| [`P3-2`](issues/P3-2.md) | P3 | **deferred** | `MiAuth::classic()` — the convenience wrapper that hides the session … |
| [`P3-3`](issues/P3-3.md) | P3 | **verified** | `classic()` reads its `$options` key by key with `??`, so a misspelled … |
| [`P3-4`](issues/P3-4.md) | P3 | **verified** | `Token::generateWithTtl()` does not validate the TTL: `time() + … |
| [`P3-5`](issues/P3-5.md) | P3 | **rejected** | Csrf::validate() throws the same csrfValidationFailed() exception for … |
| [`P3-6`](issues/P3-6.md) | P3 | **question** | Password::verify() does not reject or handle passwords longer than the … |
| [`G2`](issues/G2.md) | - | **verified** | Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, … |

## Unclosed

What is left to do here: every item whose `status` is not `verified` or `closed`,
highest severity first. `waiting on` is the party who acts next, read from that status.

| | |
|---|---|
| Unclosed | **4** of 7 |
| By status | `question` 1 · `rejected` 2 · `deferred` 1 |
| Waiting on | coordinator 1 · reviewer 2 · - 1 |

| level | item | status | waiting on | title |
|---|---|---|---|---|
| **P3** | [`P3-1`](issues/P3-1.md) | `rejected` | reviewer | `@return self<TUser>` remains a suspicious generic form (not standard … |
| **P3** | [`P3-2`](issues/P3-2.md) | `deferred` | - | `MiAuth::classic()` — the convenience wrapper that hides the session … |
| **P3** | [`P3-5`](issues/P3-5.md) | `rejected` | reviewer | Csrf::validate() throws the same csrfValidationFailed() exception for … |
| **P3** | [`P3-6`](issues/P3-6.md) | `question` | coordinator | Password::verify() does not reject or handle passwords longer than the … |

## Verdict

Every status is consistent with the code; the one open item is a genuine public-behaviour fork that reproduces and legitimately waits on a ruling.

## Fixed since the last round

No item was awaiting a verdict; the record’s statuses match the code (classic() rejects unknown option keys, generateWithTtl() rejects a sub-second TTL) and both rejections stand on PHPStan and OWASP grounds.

## Test gaps

The remember-me cookie’s own flags are unobservable under the CLI SAPI (the documented deferred option A); Password::verify()’s >72-byte truncation has no regression guard because the item is undecided.

## Verification protocol

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: all four on
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.


---

# migears-security — 已知问题

> 本模块问题的概览。条目本体在 [`issues/`](issues/README.md)，一条目一文件：前置字段加讨论串。
> 本文件由条目生成，随时可以整段重写；请改条目，不要改本文件。
>
> 出自 miGears 全模块代码评审报告（6th round，2026-10-01）。

| | |
|---|---|
| 状态 | **状态最好** |
| 体量 | src 739 行（净）· 158 个用例 · 8 个源文件 |

级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## 状态一览

| | |
|---|---|
| 未了结 | P0 0 · P1 0 · P2 0 · P3 4 · 其他 0 |
| 已了结 | 3 / 7 |
| 等模块主 | _无_ |
| 等协调人 | `P3-6` |
| 等评审方 | `P3-1`, `P3-5` |
| 已暂缓，不欠谁 | `P3-2` |

| id | 级别 | 状态 | 标题 |
|---|---|---|---|
| [`P3-1`](issues/P3-1.md) | P3 | **rejected** | @return self<TUser> 仍是可疑的泛型写法（不是标准的 self<T> … |
| [`P3-2`](issues/P3-2.md) | P3 | **deferred** | MiAuth::classic() 这条隐藏会话超全局、设置 secure cookie 默认值并完成轮换的便捷封装，完全没有测试（grep … |
| [`P3-3`](issues/P3-3.md) | P3 | **verified** | classic() 逐键用 ?? 取 $options，拼错的键会静默退回默认值——正是本模块立志要消除的那类静默选项丢弃。 |
| [`P3-4`](issues/P3-4.md) | P3 | **verified** | Token::generateWithTtl() 不校验 TTL：time() + $ttlSeconds，因此 0 … |
| [`P3-5`](issues/P3-5.md) | P3 | **rejected** | Csrf::validate() 对「无存储令牌」和「令牌不匹配」两种情况抛出相同的 csrfValidationFailed() … |
| [`P3-6`](issues/P3-6.md) | P3 | **question** | Password::verify() 未拒绝或处理超过 bcrypt 72 字节限制的密码——直接传给 … |
| [`G2`](issues/G2.md) | - | **verified** | 严格开关：`phpunit.xml.dist` 目前已开启 … |

## 未关闭

本模块还剩什么要做：所有 `status` 不是 `verified` 或 `closed` 的条目，按严重度从高到低。
`waiting on` 是下一步该动手的一方，由其状态读出。

| | |
|---|---|
| 未关闭 | **4** / 7 |
| 按状态 | `question` 1 · `rejected` 2 · `deferred` 1 |
| 等在谁 | 协调人 1 · 评审方 2 · - 1 |

| 级别 | 条目 | 状态 | 等在谁 | 标题 |
|---|---|---|---|---|
| **P3** | [`P3-1`](issues/P3-1.md) | `rejected` | 评审方 | @return self<TUser> 仍是可疑的泛型写法（不是标准的 self<T> … |
| **P3** | [`P3-2`](issues/P3-2.md) | `deferred` | - | MiAuth::classic() 这条隐藏会话超全局、设置 secure cookie 默认值并完成轮换的便捷封装，完全没有测试（grep … |
| **P3** | [`P3-5`](issues/P3-5.md) | `rejected` | 评审方 | Csrf::validate() 对「无存储令牌」和「令牌不匹配」两种情况抛出相同的 csrfValidationFailed() … |
| **P3** | [`P3-6`](issues/P3-6.md) | `question` | 协调人 | Password::verify() 未拒绝或处理超过 bcrypt 72 字节限制的密码——直接传给 … |

## 结论

每条状态都与代码一致；唯一未决项是一条真实复现的公开行为分叉，理应等待裁定。

## 本轮已修复确认

No item was awaiting a verdict; the record’s statuses match the code (classic() rejects unknown option keys, generateWithTtl() rejects a sub-second TTL) and both rejections stand on PHPStan and OWASP grounds.

## 测试盲区

remember-me cookie 自身的标志在 CLI SAPI 下不可观测（已文档化的暂缓选项 A）；Password::verify() 的 >72 字节截断无回归守卫，因为该条尚未裁定。

## 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- `phpunit.xml.dist` 中的 warning/notice/deprecation/risky 开关：四个全开
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。
