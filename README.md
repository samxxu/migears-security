# migears/security

![Version](https://img.shields.io/badge/version-2.0.0-blue)

> Security toolkit + MiAuth classic implementation. PHP 8.1+, interface-only dependencies.

> **Background**: miGears is the open-source successor of **TinyGears**, a
> self-developed PHP framework. It was renamed and open-sourced recently because
> the name *TinyGears* is already taken in the open-source community.

## Features

- **Password** — Password hashing and verification (bcrypt, based on `password_hash`)
- **Token** — Cryptographically secure random token generation and TTL verification
- **Csrf** — CSRF protection with storage abstraction
- **Sanitizer** — Input sanitization and XSS protection utilities
- **AuthInterface** — Authentication interface, freely extensible
- **MiAuth** — Classic Session + Cookie "remember me" implementation, optionally backed by a PSR-16 store for revocable tokens
- Depends only on PHP 8.1+, `ext-openssl`, and the PSR-16 interface package
- All core classes are < 300 lines
- Complete unit test coverage

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

### CSRF Protection

```php
use MiGears\Security\Csrf;
use MiGears\Security\Exception\SecurityException;

$csrf = new Csrf();

// Generate token (stored in session)
$token = $csrf->generate(
    setter: fn(string $key, string $val) => $_SESSION[$key] = $val
);

// Validate
try {
    $csrf->validate(
        userToken: $_POST['_csrf_token'] ?? '',
        getter: fn(string $key) => $_SESSION[$key] ?? null
    );
} catch (SecurityException $e) {
    // CSRF validation failed
}

// Quick output of HTML hidden field
echo $csrf->htmlField(
    setter: fn(string $key, string $val) => $_SESSION[$key] = $val
);
```

### Input Sanitization & XSS Protection

```php
use MiGears\Security\Sanitizer;

// Escape for HTML output (always use for user input)
echo Sanitizer::escape($userInput);

// Strip all HTML tags
$plain = Sanitizer::stripTags($htmlInput);

// Strip tags, allow specific ones — attributes on allowed tags are filtered:
// only href/src/alt/title/width/height survive, href/src must use an allowed
// scheme, and every on* handler, style, srcdoc and formaction is removed
$clean = Sanitizer::stripTags($html, '<p><a><strong>');

// Sanitize email
$email = Sanitizer::email($_POST['email']); // returns null if invalid

// Sanitize URL (default: http/https/ftp only)
$url = Sanitizer::url($_POST['website']); // returns null if invalid

// Sanitize integer
$id = Sanitizer::int($_GET['id']);

// Sanitize float
$price = Sanitizer::float($_POST['price']);

// Clean string (remove control chars, trim)
$clean = Sanitizer::string($dirty);

// Extract plain text from HTML
$text = Sanitizer::plainText($html);

// Sanitize filename (remove path traversal — both separators — plus "." / ".." names)
$safeName = Sanitizer::filename($_FILES['file']['name']);

// Check for XSS risk patterns (heuristic)
if (Sanitizer::hasXssRisk($input)) {
    // reject or flag
}
```

### MiAuth Classic Implementation

The simplest way, using PHP native Session + Cookie directly:

```php
use MiGears\Security\MiAuth;

$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => User::find($id),
    encryptionKey: 'your-secret-key-for-remember-me',
);

// Login
$user = User::findByEmail($_POST['email']);
if ($user && Password::verify($_POST['password'], $user->passwordHash)) {
    $auth->login($user, remember: isset($_POST['remember']));
}

// Check login status
if ($auth->isLoggedIn()) {
    $user = $auth->getCurrentUser();
}

// Logout
$auth->logout();
```

The remember-me Cookie is issued with `HttpOnly`, `SameSite=Lax` and `Secure`, and the session
ID is rotated on every login (`session_regenerate_id(true)`) to prevent session fixation.
Pass `cookieSecure => false` only when developing over plain HTTP locally:

```php
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => User::find($id),
    encryptionKey: 'your-secret-key',
    options: ['cookieSecure' => false],
);
```

#### Revocable remember-me (PSR-16 store)

Pass any PSR-16 cache — `migears/cache` qualifies — to move remember-me into a server-side
record. The Cookie then carries an opaque token, only the token's hash is stored, the token
rotates on every use, and revocation becomes possible:

```php
use MiGears\Security\MiAuth;

$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => User::find($id),
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

$auth = new MiAuth(
    sessionGet: fn(string $key): ?string => $redis->get("session:$sid:$key"),
    sessionSet: fn(string $key, string $val) => $redis->set("session:$sid:$key", $val),
    sessionRemove: fn(string $key) => $redis->del("session:$sid:$key"),
    sessionRegenerate: fn() => session_regenerate_id(true),
    cookieGet: fn(string $name): ?string => $request->cookies->get($name),
    cookieSet: fn(string $name, string $val, int $exp) => $response->headers->setCookie(...),
    cookieRemove: fn(string $name) => $response->headers->clearCookie($name),
    userLoader: fn(string $id): ?object => User::find($id),
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

## 特性

- **Password** — 密码哈希与验证（bcrypt，基于 `password_hash`）
- **Token** — 加密安全的随机令牌生成与 TTL 验证
- **Csrf** — CSRF 防护，存储抽象化
- **Sanitizer** — 输入净化与 XSS 防护工具
- **AuthInterface** — 认证接口，可自由扩展
- **MiAuth** — 经典 Session + Cookie "记住我" 实现，可选由 PSR-16 存储支撑以实现可撤销令牌
- 仅依赖 PHP 8.1+、`ext-openssl` 与 PSR-16 接口包
- 所有核心类 < 300 行
- 完整的单元测试覆盖

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

### CSRF 防护

```php
use MiGears\Security\Csrf;
use MiGears\Security\Exception\SecurityException;

$csrf = new Csrf();

// 生成令牌（存入 session）
$token = $csrf->generate(
    setter: fn(string $key, string $val) => $_SESSION[$key] = $val
);

// 验证
try {
    $csrf->validate(
        userToken: $_POST['_csrf_token'] ?? '',
        getter: fn(string $key) => $_SESSION[$key] ?? null
    );
} catch (SecurityException $e) {
    // CSRF 验证失败
}

// 快捷输出 HTML 隐藏域
echo $csrf->htmlField(
    setter: fn(string $key, string $val) => $_SESSION[$key] = $val
);
```

### 输入净化与 XSS 防护

```php
use MiGears\Security\Sanitizer;

// HTML 转义输出（用户输入务必用这个）
echo Sanitizer::escape($userInput);

// 去除所有 HTML 标签
$plain = Sanitizer::stripTags($htmlInput);

// 去除标签，保留指定的——被保留标签的属性也会被过滤：只保留
// href/src/alt/title/width/height，href/src 需使用允许的协议，
// 所有 on* 事件、style、srcdoc、formaction 一律移除
$clean = Sanitizer::stripTags($html, '<p><a><strong>');

// 净化邮箱
$email = Sanitizer::email($_POST['email']); // 无效返回 null

// 净化 URL（默认只允许 http/https/ftp）
$url = Sanitizer::url($_POST['website']); // 无效返回 null

// 净化整数
$id = Sanitizer::int($_GET['id']);

// 净化浮点数
$price = Sanitizer::float($_POST['price']);

// 净化字符串（去除控制字符、首尾空白）
$clean = Sanitizer::string($dirty);

// 从 HTML 中提取纯文本
$text = Sanitizer::plainText($html);

// 净化文件名（去除路径穿越——两种分隔符都处理——以及 "." / ".." 这类名字）
$safeName = Sanitizer::filename($_FILES['file']['name']);

// 检查是否有 XSS 风险（启发式检测）
if (Sanitizer::hasXssRisk($input)) {
    // 拒绝或标记
}
```

### MiAuth 经典实现

最简单的方式，直接使用 PHP 原生 Session + Cookie：

```php
use MiGears\Security\MiAuth;

$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => User::find($id),
    encryptionKey: 'your-secret-key-for-remember-me',
);

// 登录
$user = User::findByEmail($_POST['email']);
if ($user && Password::verify($_POST['password'], $user->passwordHash)) {
    $auth->login($user, remember: isset($_POST['remember']));
}

// 检查登录状态
if ($auth->isLoggedIn()) {
    $user = $auth->getCurrentUser();
}

// 登出
$auth->logout();
```

remember-me Cookie 会带上 `HttpOnly`、`SameSite=Lax` 与 `Secure`，且每次登录都会轮换会话 ID
（`session_regenerate_id(true)`）以防会话固定。仅在本地 HTTP 开发时传入 `cookieSecure => false`：

```php
$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => User::find($id),
    encryptionKey: 'your-secret-key',
    options: ['cookieSecure' => false],
);
```

#### 可撤销的 remember-me（PSR-16 存储）

传入任意 PSR-16 缓存（`migears/cache` 即符合）即可把 remember-me 变为服务端记录：Cookie 只携带
不透明令牌，服务端只存令牌哈希，每次使用都会轮换，并且可以撤销：

```php
use MiGears\Security\MiAuth;

$auth = MiAuth::classic(
    userLoader: fn(string $id): ?object => User::find($id),
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

$auth = new MiAuth(
    sessionGet: fn(string $key): ?string => $redis->get("session:$sid:$key"),
    sessionSet: fn(string $key, string $val) => $redis->set("session:$sid:$key", $val),
    sessionRemove: fn(string $key) => $redis->del("session:$sid:$key"),
    sessionRegenerate: fn() => session_regenerate_id(true),
    cookieGet: fn(string $name): ?string => $request->cookies->get($name),
    cookieSet: fn(string $name, string $val, int $exp) => $response->headers->setCookie(...),
    cookieRemove: fn(string $name) => $response->headers->clearCookie($name),
    userLoader: fn(string $id): ?object => User::find($id),
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
