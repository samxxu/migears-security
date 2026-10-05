# migears/security

![Version](https://img.shields.io/badge/version-2.0.0-blue)

> Security toolkit + MiAuth classic implementation. PHP 8.1+, interface-only dependencies.

> **Background**: miGears is the open-source successor of **TinyGears**, a
> self-developed PHP framework. It was renamed and open-sourced recently because
> the name *TinyGears* is already taken in the open-source community.

> **Tutorial**: new to the module, or wiring it into `migears/web`? Read
> [docs/tutorial.md](docs/tutorial.md) — it builds the mental model first, then walks a full integration.

## Features

- **Password** — Password hashing and verification (bcrypt, based on `password_hash`)
- **Token** — Cryptographically secure random token generation and TTL verification
- **Csrf** — CSRF protection with storage abstraction
- **Sanitizer** — Input sanitization and XSS protection utilities
- **AuthInterface** — Authentication interface, freely extensible
- **MiAuth** — Classic Session + Cookie login, with session-ID rotation on login
- **RememberMe** — Remember-me Cookie handling: self-contained encrypted data, or opaque rotating tokens backed by a PSR-16 store
- Depends only on PHP 8.1+, `ext-openssl`, and the PSR-16 interface package
- Every core class stays within a few hundred lines (largest is RememberMe, ~380)
- Extensive unit test coverage

## Boundaries

**In scope**

- The six concerns, one class each: `Password` (hash / verify / rehash), `Token` (CSPRNG generation, TTL timestamped tokens, timing-safe comparison), `Csrf` (token generate / validate / HTML hidden field), `Sanitizer` (escape, stripTags, email / url / int / float / string / plainText / filename), `AuthInterface` + `MiAuth` (session + cookie login), and `RememberMe` (remember-me cookie); PSR-4 root `MiGears\Security`, errors raised as `SecurityException`.
- `MiAuth::classic()` convenience adapters over PHP's native `$_SESSION` / `setcookie`: session-ID rotation on login, and remember-me cookies carrying `HttpOnly` / `SameSite=Lax` / `Secure`.
- All I/O through injected callables; runtime dependencies are only PHP 8.1+, `ext-openssl` and the PSR-16 interface package (no global state).

**Not in scope (by design)**

- Bearer / native-client token authentication — access/refresh issuance, rotation, replay detection and revocation belong to `migears/security-token-auth`; here `Token` is only low-level generation and verification (`parse()` does not compare against a stored value — that is the caller's job), and `RememberMe` only handles the browser remember-me cookie.
- Persisting the session / cache backend — `MiAuth` and `Csrf` read and write only through injected callables; where the data lives (a PSR-16 store such as `migears/cache`, your session backend) and the cookie flags on a generic `MiAuth` are the caller's decision.
- User lookup and the identity source — `userLoader` is supplied by the caller (the documented convention is to reach your Manager, not the DAO: `migears/manager` / `migears/dao`); the user object must itself expose `getId()` / `->id` / `['id']`.
- Full HTML purification — `Sanitizer` is explicitly "not a full HTML purifier"; it only strips tags, escapes output and sanitizes common input types.

## Installation

```bash
composer require migears/security
```

Requirements:
- PHP ^8.1
- ext-openssl
- psr/simple-cache (interfaces only, used for revocable remember-me records)

## Quick Start

### Password Hashing

```php
use MiGears\Security\Password;

// Hash (bcrypt, cost 12 by default; pass ['algo' => PASSWORD_ARGON2ID] to override)
$hash = Password::hash('mysecret');

// Verify
if (Password::verify('mysecret', $hash)) {
    // Login successful
}

// Check if rehashing is needed (when upgrading algorithm)
if (Password::needsRehash($hash)) {
    $newHash = Password::hash('mysecret');
}
```

bcrypt only takes the first 72 bytes into account, so `Password::hash()` rejects longer input with
a `SecurityException` instead of silently truncating it — otherwise two different long passwords
sharing a 72-byte prefix would verify against each other. Use
`['algo' => PASSWORD_ARGON2ID]` when longer passwords must be accepted.

### Token Generation

```php
use MiGears\Security\Token;
use MiGears\Security\Exception\SecurityException;

// Generate a random token
$token = Token::generate(); // 64-character hex string

// Generate a token with TTL
$token = Token::generateWithTtl(3600); // 1 hour validity

// Parse and verify a TTL token
try {
    $rawToken = Token::parse($timestampedToken);
} catch (SecurityException $e) {
    // Token is invalid or expired
}

// Timing-safe comparison
if (Token::equals($storedToken, $userToken)) {
    // Match
}
```

Requesting a length below `Token::MIN_LENGTH` (16 bytes) raises a `SecurityException` rather than
being silently widened to the default. Passing a TTL below 1 second to `generateWithTtl()` raises
an `InvalidArgumentException` instead of producing an already-expired token.

### CSRF Protection

`Csrf` never reads a superglobal either: the user-supplied token is passed in as an argument, and
the storage is whatever you inject. The per-session model OWASP allows is one long-lived token per
storage key:

```php
use MiGears\Security\Csrf;
use MiGears\Security\Exception\SecurityException;

// Storage can be anything — here a plain array held by reference; in a real app
// it would be your own session/cache, passed in from the caller
$storage = [];
$setter  = fn(string $key, string $val) => $storage[$key] = $val;
$getter  = fn(string $key): ?string => $storage[$key] ?? null;

$csrf = new Csrf();

// Generate token (stored through the injected setter)
$token = $csrf->generate(setter: $setter);

// Validate — the submitted token arrives as a parameter, not from $_POST
try {
    $csrf->validate(userToken: $submittedToken, getter: $getter);
} catch (SecurityException $e) {
    // CSRF validation failed
}

// Quick output of HTML hidden field
echo $csrf->htmlField(setter: $setter);
```

Call `generate()` again when you want to rotate the token, for example after a login or a
privilege change; rotating on every request would break submissions from other open tabs.

### Input Sanitization & XSS Protection

Every `Sanitizer` call takes the dirty input as a parameter and cleans it internally — no method
reads a superglobal, so the phone, the shell, a test, and the network all feed it the same way:

```php
use MiGears\Security\Sanitizer;

// Escape for HTML output (always use for user input)
echo Sanitizer::escape($rawInput);

// Strip all HTML tags
$plain = Sanitizer::stripTags($htmlInput);

// Strip tags, allow specific ones — attributes on allowed tags are filtered:
// only href/src/alt/title/width/height survive, href/src must use an allowed
// scheme, and every on* handler, style, srcdoc and formaction is removed
$clean = Sanitizer::stripTags($html, '<p><a><strong>');

// Sanitize email (each $raw… is the caller-supplied value)
$email = Sanitizer::email($rawEmail); // returns null if invalid

// Sanitize URL (default: http/https/ftp only)
$url = Sanitizer::url($rawUrl); // returns null if invalid

// Sanitize integer
$id = Sanitizer::int($rawId);

// Sanitize float
$price = Sanitizer::float($rawPrice);

// Clean string (remove control chars, trim)
$clean = Sanitizer::string($dirty);

// Extract plain text from HTML
$text = Sanitizer::plainText($html);

// Sanitize filename (remove path traversal — both separators — plus "." / ".." names)
$safeName = Sanitizer::filename($rawFileName);

// Note: there is deliberately no "does this input look dangerous?" helper.
// Escape on output with escape(); filter on input with stripTags().
```

### MiAuth Classic Implementation

`MiAuth` is a framework-agnostic authentication core: it never reads any input itself. Session
and Cookie I/O arrive through the callables you inject, and every other value is passed in as a
method argument. The data may come from `$_POST`, an HTTP `Request` object, the CLI, or a test —
the calls on `MiAuth` stay identical:

```php
use MiGears\Security\MiAuth;
use MiGears\Security\Password;

// classic() supplies the session/Cookie adapters on top of PHP's native
// $_SESSION/setcookie; the userLoader hits your Manager (the service layer,
// never the DAO directly)
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => $users->findById($id),
);

// Login — the values are given, not read: email/password/remember arrive
// from the caller, so MiAuth never touches a superglobal or a Request
function login(MiAuth $auth, UserManager $users, string $email, string $password, bool $remember): ?User
{
    $user = $users->findByEmail($email);
    if ($user === null || !Password::verify($password, $user->passwordHash)) {
        return null;
    }
    $auth->login($user, remember: $remember);
    return $user;
}

// Check login status and the current user
if ($auth->isLoggedIn()) {
    $user = $auth->getCurrentUser();
}

// Logout
$auth->logout();
```

Login failure and the session state are MiAuth's whole concern; where the input came from is the
caller's. The remember-me Cookie is issued with `HttpOnly`, `SameSite=Lax` and `Secure`, and the
session ID is rotated on every login (`session_regenerate_id(true)`) to prevent session fixation.
Pass `cookieSecure => false` in `options` only when developing over plain HTTP locally:

```php
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => $users->findById($id),
    options: ['cookieSecure' => false],
);
```

`options` accepts only the documented keys (`sessionKey`, `cookieName`, `rememberTtl`,
`cookieSecure`, `rememberStore`, `rememberGrace`); a misspelled key raises an
`InvalidArgumentException` rather than silently falling back to the default.

#### Revocable remember-me (PSR-16 store)

Pass any PSR-16 cache — `migears/cache` qualifies — in `options` to move remember-me into a
server-side record. The Cookie then carries an opaque token, only the token's hash is stored,
the token rotates on every use, and revocation becomes possible:

```php
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => $users->findById($id),
    options: [
        'rememberStore' => $cache,   // any Psr\SimpleCache\CacheInterface
        'rememberGrace' => 30,       // seconds a consumed token is still tolerated
    ],
);

$auth->logout();                      // drops this device's record
$auth->revokeRememberTokens($userId); // drops every device of the user (call on password change)
```

Records live under `__migears_rem_…` (keyed by the token's hash) and the per-user epoch under
`__migears_remv_…`; `revokeRememberTokens()` bumps that epoch, so every Cookie issued earlier
stops resolving. The grace window keeps a just-consumed token valid for a few seconds so parallel
requests are not logged out mid-rotation. Without a store the Cookie stays self-contained
encrypted data and **cannot be revoked** — an encryption key is then required.

### Custom Storage

MiAuth abstracts all I/O through callables and does not depend on any global variables:

```php
use MiGears\Security\MiAuth;

$users = $container->get(UserManager::class); // your Manager, passed in from the caller

$auth = new MiAuth(
    sessionGet: fn(string $key): ?string => $redis->get("session:$sid:$key"),
    sessionSet: fn(string $key, string $val) => $redis->set("session:$sid:$key", $val),
    sessionRemove: fn(string $key) => $redis->del("session:$sid:$key"),
    sessionRegenerate: fn() => session_regenerate_id(true),
    cookieGet: fn(string $name): ?string => $request->cookies->get($name),
    cookieSet: fn(string $name, string $val, int $exp) => $response->headers->setCookie(...),
    cookieRemove: fn(string $name) => $response->headers->clearCookie($name),
    userLoader: fn(string $id): ?object => $users->findById($id),
    encryptionKey: 'your-secret-key',
    rememberStore: $cache,                 // optional PSR-16 store for revocable remember-me tokens
);
```

The `cookieSet` callable is responsible for the Cookie flags; include `Secure`, `HttpOnly`
and `SameSite` there when the store is a browser session.

### Implementing Custom AuthInterface

```php
use MiGears\Security\AuthInterface;

final class JwtAuth implements AuthInterface
{
    public function login(object $user, bool $remember = false): void { /* ... */ }
    public function logout(): void { /* ... */ }
    public function isLoggedIn(): bool { /* ... */ }
    public function getCurrentUser(): ?object { /* ... */ }
}
```

## Design Principles

- **No global state** — Does not depend on superglobals like `$_SESSION` or `$_COOKIE` (except `MiAuth::classic()`, which is a convenience wrapper)
- **Interface-only dependencies** — Only requires PHP 8.1+, the openssl extension, and the PSR-16 interface package
- **Minimalist API** — Each class does one thing, with a small and refined set of methods
- **Security first** — All cryptographic operations use PHP's native CSPRNG, comparisons use `hash_equals`

## License

MIT

---

# migears/security

![Version](https://img.shields.io/badge/version-2.0.0-blue)

> 安全工具集 + MiAuth 经典实现。PHP 8.1+，依赖仅限接口包。

> **教程**：初次使用，或要把它接进 `migears/web`？请读
> [docs/tutorial.md](docs/tutorial.md) —— 先建立心智模型，再走完整套集成。

## 特性

- **Password** — 密码哈希与验证（bcrypt，基于 `password_hash`）
- **Token** — 加密安全的随机令牌生成与 TTL 验证
- **Csrf** — CSRF 防护，存储抽象化
- **Sanitizer** — 输入净化与 XSS 防护工具
- **AuthInterface** — 认证接口，可自由扩展
- **MiAuth** — 经典 Session + Cookie 登录，登录时轮换会话 ID
- **RememberMe** — remember-me Cookie 处理：自包含密文，或由 PSR-16 存储支撑的不透明可轮换令牌
- 仅依赖 PHP 8.1+、`ext-openssl` 与 PSR-16 接口包
- 每个核心类都在数百行内（最大为 RememberMe，约 380 行）
- 充分的单元测试覆盖

## 边界

**范围内**

- 六个关注点各占一个类：`Password`（哈希/验证/重哈希）、`Token`（CSPRNG 生成、TTL 时间戳令牌、时序安全比较）、`Csrf`（令牌生成/校验/HTML 隐藏域）、`Sanitizer`（escape、stripTags、email/url/int/float/string/plainText/filename 净化）、`AuthInterface` + `MiAuth`（Session + Cookie 登录）、`RememberMe`（remember-me Cookie）；PSR-4 根为 `MiGears\Security`，错误统一抛 `SecurityException`。
- `MiAuth::classic()` 在 PHP 原生 `$_SESSION`/`setcookie` 之上的便捷适配：登录时轮换会话 ID，remember-me Cookie 带 `HttpOnly`/`SameSite=Lax`/`Secure`。
- 所有 I/O 都走注入的 callable，运行时依赖仅 PHP 8.1+、`ext-openssl` 与 PSR-16 接口包（无全局状态）。

**范围外（刻意不做）**

- Bearer / 原生客户端令牌认证 —— access/refresh 令牌签发、轮换、重放检测与撤销属于 `migears/security-token-auth`；本模块的 `Token` 只是底层生成与校验（`parse()` 不与已存值比对，比对由调用方负责），`RememberMe` 只处理浏览器 remember-me Cookie。
- Session / 缓存后端的持久化 —— `MiAuth`、`Csrf` 只通过注入的 callable 读写，数据存在哪里（`migears/cache` 之类的 PSR-16 存储、你的会话后端）以及通用 `MiAuth` 上的 Cookie 标志由调用方决定。
- 用户查询与身份来源 —— `userLoader` 由调用方提供（文档约定触碰 Manager 层而非 DAO，即 `migears/manager` / `migears/dao`）；用户对象须自行具备 `getId()` / `->id` / `['id']`。
- 完整的 HTML 净化 —— `Sanitizer` 明确「不是完整 HTML purifier」，只做标签剥离、输出转义与常见输入类型的净化。

## 安装

```bash
composer require migears/security
```

要求：
- PHP ^8.1
- ext-openssl
- psr/simple-cache（仅接口，用于可撤销的 remember-me 记录）

## 快速开始

### 密码哈希

```php
use MiGears\Security\Password;

// 哈希（默认 bcrypt、cost 12；可用 ['algo' => PASSWORD_ARGON2ID] 覆盖算法）
$hash = Password::hash('mysecret');

// 验证
if (Password::verify('mysecret', $hash)) {
    // 登录成功
}

// 检查是否需要重新哈希（升级算法时）
if (Password::needsRehash($hash)) {
    $newHash = Password::hash('mysecret');
}
```

bcrypt 只取前 72 字节，因此 `Password::hash()` 对超长输入直接抛 `SecurityException`，而不是静默截断——
否则前 72 字节相同的两个不同长密码会互相验证通过。若确需接受更长密码，请使用
`['algo' => PASSWORD_ARGON2ID]`。

### 令牌生成

```php
use MiGears\Security\Token;
use MiGears\Security\Exception\SecurityException;

// 生成随机令牌
$token = Token::generate(); // 64 字符十六进制

// 生成带 TTL 的令牌
$token = Token::generateWithTtl(3600); // 1 小时有效

// 解析并验证 TTL 令牌
try {
    $rawToken = Token::parse($timestampedToken);
} catch (SecurityException $e) {
    // 令牌无效或已过期
}

// 时序安全比较
if (Token::equals($storedToken, $userToken)) {
    // 匹配
}
```

请求低于 `Token::MIN_LENGTH`（16 字节）的长度会抛 `SecurityException`，不再静默提升为默认值。
向 `generateWithTtl()` 传入低于 1 秒的 TTL 会抛 `InvalidArgumentException`，而不是生成一个即
已过期的令牌。

### CSRF 防护

`Csrf` 同样从不读取任何 superglobal：用户提交的令牌以参数传入，存储则是你注入的任意实现。
OWASP 认可的每会话模型，就是每个存储键持有**一个长期令牌**：

```php
use MiGears\Security\Csrf;
use MiGears\Security\Exception\SecurityException;

// 存储可以是任意实现——这里用按引用持有的普通数组演示；真实应用中它是你自己的
// session/缓存，由调用方注入
$storage = [];
$setter  = fn(string $key, string $val) => $storage[$key] = $val;
$getter  = fn(string $key): ?string => $storage[$key] ?? null;

$csrf = new Csrf();

// 生成令牌（经注入的 setter 存储）
$token = $csrf->generate(setter: $setter);

// 验证——提交的令牌作为参数传入，而非来自 $_POST
try {
    $csrf->validate(userToken: $submittedToken, getter: $getter);
} catch (SecurityException $e) {
    // CSRF 验证失败
}

// 快捷输出 HTML 隐藏域
echo $csrf->htmlField(setter: $setter);
```

需要轮换时再次调用 `generate()`，例如登录成功或权限变更之后；若每请求都轮换，
会破坏其他已打开标签页的提交。

### 输入净化与 XSS 防护

每次 `Sanitizer` 调用都把脏输入作为参数传入，并在内部完成清洗——没有任何方法读取 superglobal，
因此手机、shell、测试与网络都以相同方式喂给它们：

```php
use MiGears\Security\Sanitizer;

// HTML 转义输出（用户输入务必用这个）
echo Sanitizer::escape($rawInput);

// 去除所有 HTML 标签
$plain = Sanitizer::stripTags($htmlInput);

// 去除标签，保留指定的——被保留标签的属性也会被过滤：只保留
// href/src/alt/title/width/height，href/src 需使用允许的协议，
// 所有 on* 事件、style、srcdoc、formaction 一律移除
$clean = Sanitizer::stripTags($html, '<p><a><strong>');

// 净化邮箱（每个 $raw… 都是调用方提供的值）
$email = Sanitizer::email($rawEmail); // 无效返回 null

// 净化 URL（默认只允许 http/https/ftp）
$url = Sanitizer::url($rawUrl); // 无效返回 null

// 净化整数
$id = Sanitizer::int($rawId);

// 净化浮点数
$price = Sanitizer::float($rawPrice);

// 净化字符串（去除控制字符、首尾空白）
$clean = Sanitizer::string($dirty);

// 从 HTML 中提取纯文本
$text = Sanitizer::plainText($html);

// 净化文件名（去除路径穿越——两种分隔符都处理——以及 "." / ".." 这类名字）
$safeName = Sanitizer::filename($rawFileName);

// 注意：这里刻意不提供“这段输入是否危险”的检测函数。
// 输出用 escape()，输入过滤用 stripTags()。
```

### MiAuth 经典实现

`MiAuth` 是一个 framework-agnostic 的认证核心：它自己从不读取任何输入。Session 与 Cookie 的
I/O 通过你注入的 callable 传入，其余值都作为方法参数传入。数据可能来自 `$_POST`、HTTP
`Request` 对象、CLI 或测试——对 `MiAuth` 的调用方式始终一致：

```php
use MiGears\Security\MiAuth;
use MiGears\Security\Password;

// classic() 在 PHP 原生 $_SESSION/setcookie 之上提供 Session/Cookie 适配；
// userLoader 触碰你的 Manager（服务层，绝不直接接触 DAO）
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => $users->findById($id),
);

// 登录——值是“传入”而非“读取”：email/password/remember 来自调用方，
// 因此 MiAuth 从不直接触碰 superglobal 或 Request
function login(MiAuth $auth, UserManager $users, string $email, string $password, bool $remember): ?User
{
    $user = $users->findByEmail($email);
    if ($user === null || !Password::verify($password, $user->passwordHash)) {
        return null;
    }
    $auth->login($user, remember: $remember);
    return $user;
}

// 检查登录状态与当前用户
if ($auth->isLoggedIn()) {
    $user = $auth->getCurrentUser();
}

// 登出
$auth->logout();
```

登录成败与会话状态是 MiAuth 的全部关注点；输入来自哪里是调用方的事。remember-me Cookie 会带上
`HttpOnly`、`SameSite=Lax` 与 `Secure`，且每次登录都会轮换会话 ID（`session_regenerate_id(true)`）
以防会话固定。仅在本地 HTTP 开发时在 `options` 里传入 `cookieSecure => false`：

```php
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => $users->findById($id),
    options: ['cookieSecure' => false],
);
```

`options` 仅接受文档列出的键（`sessionKey`、`cookieName`、`rememberTtl`、`cookieSecure`、
`rememberStore`、`rememberGrace`）；拼错的键会抛 `InvalidArgumentException`，而不是静默
退回默认值。

#### 可撤销的 remember-me（PSR-16 存储）

在 `options` 里传入任意 PSR-16 缓存（`migears/cache` 即符合），即可把 remember-me 变为服务端记录：
Cookie 只携带不透明令牌，服务端只存令牌哈希，每次使用都会轮换，并且可以撤销：

```php
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => $users->findById($id),
    options: [
        'rememberStore' => $cache,   // 任意 Psr\SimpleCache\CacheInterface
        'rememberGrace' => 30,       // 已消费令牌仍被容忍的秒数
    ],
);

$auth->logout();                      // 撤销本设备的记录
$auth->revokeRememberTokens($userId); // 撤销该用户全部设备（改密时调用）
```

记录存于 `__migears_rem_…`（以令牌哈希为键），每用户的 epoch 存于 `__migears_remv_…`；
`revokeRememberTokens()` 递增该 epoch，于是此前签发的所有 Cookie 立即失效。宽限期让刚被消费的令牌
在数秒内仍然有效，避免轮换过程中并发请求被登出。不注入存储时，Cookie 仍是自包含密文，
**无法撤销**——此时必须提供加密密钥。

### 自定义存储

MiAuth 通过 callable 抽象所有 I/O，不依赖任何全局变量：

```php
use MiGears\Security\MiAuth;

$users = $container->get(UserManager::class); // 你的 Manager，由调用方传入

$auth = new MiAuth(
    sessionGet: fn(string $key): ?string => $redis->get("session:$sid:$key"),
    sessionSet: fn(string $key, string $val) => $redis->set("session:$sid:$key", $val),
    sessionRemove: fn(string $key) => $redis->del("session:$sid:$key"),
    sessionRegenerate: fn() => session_regenerate_id(true),
    cookieGet: fn(string $name): ?string => $request->cookies->get($name),
    cookieSet: fn(string $name, string $val, int $exp) => $response->headers->setCookie(...),
    cookieRemove: fn(string $name) => $response->headers->clearCookie($name),
    userLoader: fn(string $id): ?object => $users->findById($id),
    encryptionKey: 'your-secret-key',
    rememberStore: $cache,                 // 可选的 PSR-16 存储，用于可撤销的 remember-me 令牌
);
```

Cookie 标志由 `cookieSet` 这个 callable 自行负责；当存储面向浏览器会话时，
请在其中带上 `Secure`、`HttpOnly` 与 `SameSite`。

### 实现自定义 AuthInterface

```php
use MiGears\Security\AuthInterface;

final class JwtAuth implements AuthInterface
{
    public function login(object $user, bool $remember = false): void { /* ... */ }
    public function logout(): void { /* ... */ }
    public function isLoggedIn(): bool { /* ... */ }
    public function getCurrentUser(): ?object { /* ... */ }
}
```

## 设计原则

- **无全局状态** — 不依赖 `$_SESSION`、`$_COOKIE` 等超全局变量（`MiAuth::classic()` 除外，它是便捷封装）
- **依赖仅限接口** — 仅需 PHP 8.1+、openssl 扩展与 PSR-16 接口包
- **极简 API** — 每个类只做一件事，方法数量少而精
- **安全优先** — 所有加密操作使用 PHP 原生 CSPRNG，比较使用 `hash_equals`

## License

MIT
