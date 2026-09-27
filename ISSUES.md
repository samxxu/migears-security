# migears-security — Known Issues / 已知问题

> Generated from the miGears Full-Module Code Review Report (4th round, 2026-09-27).
> This file has two regions. Everything above **Owner feedback** is generated from the report — do
> not edit it there. The **Owner feedback** region belongs to the module maintainer: write into it,
> and it is preserved verbatim when the file is regenerated.
> A `fixed` reply is verified against the code by the reviewer before the finding is closed; a
> `rejected` reply is either accepted as a false positive or answered with counter-evidence.
>
> 本文件分两个区域。**「负责人反馈」之前的全部内容**由评审报告生成，请勿在该区修改；
> **「负责人反馈」区**归模块负责人所有，重新生成时会原样保留。
> 标注 `fixed`（已修复）的回复会被评审对照代码核实后才关闭；标注 `rejected`（不认同）的，
> 评审要么采纳为误报，要么给出反驳证据。
>
> 摘自 miGears 全模块代码评审报告（第四轮，2026-09-27）。

| | |
|---|---|
| Status / 状态 | **P0 cleared / P0 已清零** |
| Findings / 问题 | P0 0 · P1 0 · P2 0 · P3 4 |
| Size / 体量 | src 1,474 lines (727 net) · 151 tests · 8 src files |

Legend / 图例 — **P0** functional or security · **P1** documentation that fails when copied · **P2** robustness · **P3** metadata and docs
级别说明 — **P0** 功能性或安全级 · **P1** 文档照抄即错 · **P2** 健壮性 · **P3** 元数据与文档

## Verdict / 结论

The session lifecycle is now complete and the module is the strongest security story in the workspace. What is left is one untested convenience path and a few metadata points.

会话生命周期现已完整，是全仓安全叙事最强的一个模块。剩下一条未测的便捷路径与几条元数据项。

## Fixed since the last round / 本轮已修复确认

上一轮 8 项全部落地，含四项会话生命周期：login() 先轮换 session id 再写入（有顺序断言）、remember-me 增加 store 模式与 epoch 机制使其可被服务端吊销（加密模式不可吊销已在 README 声明为设计选择）、classic() 默认 cookieSecure=true、AES 与 MAC 采用两个 label 派生密钥分离。另：Csrf docblock 示例改为真实签名、README 四处补 use、MiAuth 构造器回调改 assertCallable、extractUserId 改 is_callable、Password 支持 algo 覆盖并校验、Sanitizer 过滤属性与协议、filename 处理反斜杠与 .。 

## Open findings / 未修问题


### P3

**P3-1** — `src/MiAuth.php:124, src/Exception/SecurityException.php:82`

- EN: `@return self<TUser>` remains a suspicious generic form (not standard `self<T>` syntax), and `SecurityException::authenticationFailed()` still has zero call sites in src.
- 中文: @return self<TUser> 仍是可疑的泛型写法（不是标准的 self<T> 语法）；SecurityException::authenticationFailed() 在 src 内仍零调用。
- Verification / 验证: static / 仅静态推断

**P3-2** — `src/MiAuth.php:128-186; tests/`

- EN: `MiAuth::classic()` — the convenience wrapper that hides the session superglobals, sets the secure cookie defaults and performs the rotation — has no test at all (`grep "::classic(" tests/` returns nothing).
- 中文: MiAuth::classic() 这条隐藏会话超全局、设置 secure cookie 默认值并完成轮换的便捷封装，完全没有测试（grep "::classic(" tests/ 零命中）。
- Verification / 验证: reproduced / 已实证

**P3-3** — `src/MiAuth.php:178-186`

- EN: `classic()` reads its `$options` key by key with `??`, so a misspelled key silently falls back to the default — the same class of silent option drop the module set out to remove.
- 中文: classic() 逐键用 ?? 取 $options，拼错的键会静默退回默认值——正是本模块立志要消除的那类静默选项丢弃。
- Verification / 验证: static / 仅静态推断

**P3-4** — `src/Token.php:73-79,108`

- EN: `Token::generateWithTtl()` does not validate the TTL: `time() + $ttlSeconds`, so 0 produces a token that expires in the same second (and the `< time()` check lets it through within that second) and a negative value produces an already-expired token. The README documents only length validation.
- 中文: Token::generateWithTtl() 不校验 TTL：time() + $ttlSeconds，因此 0 会产生同秒即过期的令牌（判断用的是 < time()，那一秒内仍会通过），负数则生成即过期。README 只记录了长度校验。
- Verification / 验证: static / 仅静态推断

## Test gaps / 测试盲区

`MiAuth::classic()` has zero test coverage — and that is exactly where the secure-cookie default and session rotation land; no non-positive TTL case for `Token::generateWithTtl()`; no case for an unknown `classic()` option key.

MiAuth::classic() 零测试覆盖——而 secure cookie 默认值与会话轮换恰好都只在这条路径落地；Token::generateWithTtl() 无非正 TTL 用例；classic() 未知选项键无用例。

## Verification protocol / 验证方式

- `./vendor/bin/phpunit` · `composer analyse` · `composer validate`
- Warning/notice/deprecation/risky flags in `phpunit.xml.dist`: on: Warning, Risky
- A PHP warning counts as a test failure only where those flags are on; otherwise run `./vendor/bin/phpunit --fail-on-warning` explicitly.
- 只有在上述开关打开时 PHP 警告才会导致套件失败；否则请显式加 `--fail-on-warning`。

## Owner feedback / 负责人反馈

<!-- OWNER-FEEDBACK:BEGIN -->
<!-- 渠道说明 / channel notice — 跨模块协调人发布，长期有效 / issued by the cross-module coordinator, standing
     ISSUES.md 是本模块「完整」的问题讨论与修复渠道，不只是评审结论的存放处。
     ISSUES.md is this module's COMPLETE issue-discussion-and-fix channel, not merely where review verdicts land.

     1. 每位负责人只对自己模块负责。对别的模块有意见、疑问、反证或改动建议，写入「对方模块」的 ISSUES.md，
        不要写在自己模块里。
        Each owner is responsible for their own module only. Opinions, questions, counter-evidence and
        change requests about ANOTHER module go into THAT module's ISSUES.md, never into your own.
     2. 在对方模块的文件里注明你是谁：模块名 + 身份。署名是硬要求，不署名则无法追溯来源。
        Sign it in the other module's file: your module name and your role. Signing is mandatory; an
        unsigned entry cannot be traced back to its author.
     3. 署名格式 / signature forms, so the source is distinguishable:
          reviewer — migears-full-review   评审方
          coordinator — cross-module       跨模块协调人
          owner — migears-<module>         其他模块负责人
     4. 结论文本一律带状态词：accepted / fixed / rejected / deferred / question / new-evidence。
        无署名条目下一轮可能被按新发现重新评级。
        Sign conclusions with one status word: accepted / fixed / rejected / deferred / question /
        new-evidence. An unsigned entry may be re-graded as a new finding in the next round.
     5. 开工之前先通读本文件：把每条开启条目按证据评估（签名条目也算），再把你接受的条目与自己的工作一并执行，
        不要拆成两轮。每条都要有状态词。
        Read this file before starting work: evaluate every open item on its evidence, signed entries
        included, then execute the ones you accept together with your own work in one pass. Every item
        gets a status word. -->

<!-- Maintainers: reply under each finding's `### <id>` heading and keep the headings, so the
     reviewer can map your reply to the finding. Status vocabulary, one word followed by your
     reasoning and any evidence:
       accepted      you agree; it will be fixed
       fixed         you believe it is already fixed in the code (the reviewer verifies this)
       rejected      you disagree — give the reason; the reviewer either accepts it as a false
                     positive or answers with counter-evidence
       deferred      deliberate, out of scope for now — give the reason
       question      you need a decision or clarification first
       new-evidence  you have additional facts bearing on the finding
     You may also add findings of your own under `### New — <short title>`.

     负责人：请在对应 `### <编号>` 标题下逐条回复，并保留标题以便评审对应。
     状态词（一个词 + 理由与证据）：
       accepted      认同，将会修复
       fixed         认为代码里已经修好（评审会对照代码核实）
       rejected      不认同——请给理由；评审要么采纳为误报，要么给出反驳证据
       deferred      有意暂缓或超出范围——请给理由
       question      需要先明确或决策
       new-evidence  补充与本次结论相关的新事实
     也欢迎在 `### New — <简短标题>` 下补充你发现的问题。 -->

### P3-1
<!-- 负责人反馈 / owner response here -->

- **rejected** — both halves verified against the current code; neither is a defect.
  - **`@return self<TUser>` is the standard form, not a suspicious one.** The template is declared, so
    the placeholder is grounded: `src/MiAuth.php:18` `@template TUser of object`, `src/AuthInterface.php:14`
    `@template TUser of object`, and `src/MiAuth.php:19` `@implements AuthInterface<TUser>`. `self<TUser>`
    is exactly how PHPDoc/PHPStan spell "this class, with its own class-level template"; the finding's
    "not standard `self<T>` syntax" premise is the error.
  - Probed, not just argued. With PHPStan 2.2.16 (the module's own `vendor/bin/phpstan`) I analysed a
    scratch file (under `/Users/samxx/.trae-cn/work/6aaf7633fe64b0cec08a9e8d/probe_generic/`, not in the
    module) that parameterises the class as `MiAuth<\DateTimeImmutable>` and dumps the result of
    `getCurrentUser()`:
    - `probe_mauth.php:23 Dumped type: DateTimeImmutable|null`
    - a minimal generic-box analogue: `probe.php:49 Dumped type: DateTimeImmutable`.
    So PHPStan parses `self<TUser>` and binds `TUser`; the annotation is live, not decoration.
  - **`SecurityException::authenticationFailed()` — zero src callers is correct.** It is a public,
    tested factory of the domain exception (`tests/SecurityExceptionTest.php:53-69`, plus the factory
    sweep at `:71-86`). `MiAuth` never verifies credentials — `README.md:171`: "it never reads any input
    itself" — so the credential-failure path that throws it belongs to the consumer, not to this module.
    The other eight factories have src callers precisely because the module itself raises those; this one
    is the consumer-facing helper, and deleting a covered public method would be a BC break, not a fix.
  - Commands / observed: `./vendor/bin/phpstan analyse --no-progress` → `[OK] No errors`, exit 0;
    `./vendor/bin/phpunit` → `OK (155 tests, 281 assertions)`, exit 0.
  - No code or doc change (the item is not a defect).

  owner — migears-security

### P3-2
<!-- 负责人反馈 / owner response here -->

### P3-3
<!-- 负责人反馈 / owner response here -->

### P3-4
<!-- 负责人反馈 / owner response here -->
<!-- 跨模块条目 / cross-module items — 由跨模块协调人提出，非本轮评审 finding。口径见工作区根目录 `migears-engineering-gates.md`。
      Filed by the cross-module coordinator, not by the round's review. Standard: `migears-engineering-gates.md` at the workspace root. -->

### G2

- EN: Strict flags: `phpunit.xml.dist` currently sets `failOnWarning`, `failOnRisky`, `beStrictAboutOutputDuringTests`. The standard is all five — `failOnWarning`, `failOnNotice`, `failOnDeprecation`, `failOnRisky`, `beStrictAboutOutputDuringTests` — which 11 of 27 modules set. Missing here: `failOnNotice`, `failOnDeprecation`. Turn them on and make the suite green; run `./vendor/bin/phpunit` and `composer analyse` before and after, and expect the first run to surface real warnings. If a flag genuinely cannot be turned on, reply `deferred` with the failing test and the reason instead of leaving the suite red.
- 中文: 严格开关：`phpunit.xml.dist` 目前已开启 `failOnWarning`、`failOnRisky`、`beStrictAboutOutputDuringTests`。标准是五个全开——`failOnWarning`、`failOnNotice`、`failOnDeprecation`、`failOnRisky`、`beStrictAboutOutputDuringTests`——27 个模块中 11 个如此。本模块缺 `failOnNotice`、`failOnDeprecation`。请打开并让套件保持全绿；改动前后各跑一次 `./vendor/bin/phpunit` 与 `composer analyse`，第一次跑出真警告是预期内的。若某个开关确实无法打开，请回复 `deferred` 并给出失败的用例与原因，而不是把套件留在红灯状态。
- Reply with one status word (`accepted` / `fixed` / `rejected` / `deferred` / `question`). / 请回复一个状态词（`accepted` / `fixed` / `rejected` / `deferred` / `question`）。
coordinator — cross-module

- **fixed** — all five strict flags are now on. `phpunit.xml.dist` previously set
  `failOnWarning`, `failOnRisky`, `beStrictAboutOutputDuringTests`; I added `failOnNotice` and
  `failOnDeprecation` and, matching the reference shape
  (`migears-data-structure/phpunit.xml.dist`), the three `displayDetailsOnTestsThatTrigger*`
  attributes. Every pre-existing attribute (`colors`, `cacheDirectory`, `executionOrder="random"`) and
  the `<testsuites>`/`<source>` structure were kept.
  - Before: `./vendor/bin/phpunit` → `OK (155 tests, 281 assertions)`, exit 0.
  - After: `./vendor/bin/phpunit` → `OK (155 tests, 281 assertions)`, exit 0 — no warning, notice,
    deprecation, risky test or stray output surfaced, so the two new flags cost nothing here.
  - `./vendor/bin/phpstan analyse --no-progress` → `[OK] No errors`, exit 0, before and after.
  - `phpunit.xml.dist:8-15` now sets `failOnWarning`, `failOnNotice`, `failOnDeprecation`,
    `failOnRisky`, `beStrictAboutOutputDuringTests`, `displayDetailsOnTestsThatTriggerWarnings`,
    `displayDetailsOnTestsThatTriggerNotices`, `displayDetailsOnTestsThatTriggerDeprecations`, all `true`.

  owner — migears-security

<!-- OWNER-FEEDBACK:END -->
