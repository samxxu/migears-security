# migears-security — Known Issues / 已知问题

> Summary of this module's issues. The items themselves are in [`issues/`](issues/README.md), one file
> per item: a front-matter header and a thread. This file is generated from them and can be rewritten at
> any time; edit an item, never this file.
>
> 本模块问题的概览。条目本体在 [`issues/`](issues/README.md)，一条目一文件：前置字段加讨论串。
> 本文件由条目生成，随时可以整段重写；请改条目，不要改本文件。
>
> From the miGears Full-Module Code Review Report (4th round, 2026-09-27).

| | |
|---|---|
| Status / 状态 | **P0 cleared / P0 已清零** |
| Size / 体量 | src 1,474 lines (727 net) · 151 tests · 8 src files |

Legend / 图例 — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs
级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## At a glance / 状态一览

| | |
|---|---|
| Items / 条目 | P0 0 · P1 0 · P2 0 · P3 4 · other 1 |
| Answered / 已回复 | 2 of 5 |
| Waiting / 等待回复 | `P3-2`, `P3-3`, `P3-4` |

| id | level | status | title |
|---|---|---|---|
| [`P3-1`](issues/P3-1.md) | P3 | **rejected** | `@return self<TUser>` remains a suspicious generic form (not standard … |
| [`P3-2`](issues/P3-2.md) | P3 | **open** | `MiAuth::classic()` — the convenience wrapper that hides the session … |
| [`P3-3`](issues/P3-3.md) | P3 | **open** | `classic()` reads its `$options` key by key with `??`, so a misspelled … |
| [`P3-4`](issues/P3-4.md) | P3 | **open** | `Token::generateWithTtl()` does not validate the TTL: `time() + … |
| [`G2`](issues/G2.md) | - | **fixed** | Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, … |

## Verdict / 结论

The session lifecycle is now complete and the module is the strongest security story in the workspace. What is left is one untested convenience path and a few metadata points.

会话生命周期现已完整，是全仓安全叙事最强的一个模块。剩下一条未测的便捷路径与几条元数据项。

## Fixed since the last round / 本轮已修复确认

上一轮 8 项全部落地，含四项会话生命周期：login() 先轮换 session id 再写入（有顺序断言）、remember-me 增加 store 模式与 epoch 机制使其可被服务端吊销（加密模式不可吊销已在 README 声明为设计选择）、classic() 默认 cookieSecure=true、AES 与 MAC 采用两个 label 派生密钥分离。另：Csrf docblock 示例改为真实签名、README 四处补 use、MiAuth 构造器回调改 assertCallable、extractUserId 改 is_callable、Password 支持 algo 覆盖并校验、Sanitizer 过滤属性与协议、filename 处理反斜杠与 .。 

## Test gaps / 测试盲区

`MiAuth::classic()` has zero test coverage — and that is exactly where the secure-cookie default and session rotation land; no non-positive TTL case for `Token::generateWithTtl()`; no case for an unknown `classic()` option key.

MiAuth::classic() 零测试覆盖——而 secure cookie 默认值与会话轮换恰好都只在这条路径落地；Token::generateWithTtl() 无非正 TTL 用例；classic() 未知选项键无用例。

## Verification protocol / 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: all four on
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。
