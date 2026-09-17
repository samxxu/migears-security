# migears/security

![Version](https://img.shields.io/badge/version-2.0.0-blue)

> Security toolkit + MiAuth classic implementation. Zero mandatory dependencies, PHP 8.1+.

## Features

- **Password** — Password hashing and verification (bcrypt, based on `password_hash`)
- **Token** — Cryptographically secure random token generation and TTL verification
- **Csrf** — CSRF protection with storage abstraction
- **Sanitizer** — Input sanitization and XSS protection utilities
- **AuthInterface** — Authentication interface, freely extensible
- **MiAuth** — Classic Session + Cookie "remember me" implementation
- Zero mandatory dependencies, only requires PHP 8.1+ and `ext-openssl`
- All core classes are < 300 lines
- Complete unit test coverage

## Installation

```bash
composer require migears/security
```

Requirements:
- PHP ^8.1
- ext-openssl

## Quick Start

### Password Hashing

```php
use MiGears\Security\Password;

// Hash
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

### Token Generation

```php
use MiGears\Security\Token;

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

// Strip tags, allow specific ones
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

// Sanitize filename (remove path traversal, null bytes)
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

### Custom Storage

MiAuth abstracts all I/O through callables and does not depend on any global variables:

```php
use MiGears\Security\MiAuth;

$auth = new MiAuth(
    sessionGet: fn(string $key): ?string => $redis->get("session:$sid:$key"),
    sessionSet: fn(string $key, string $val) => $redis->set("session:$sid:$key", $val),
    sessionRemove: fn(string $key) => $redis->del("session:$sid:$key"),
    cookieGet: fn(string $name): ?string => $request->cookies->get($name),
    cookieSet: fn(string $name, string $val, int $exp) => $response->headers->setCookie(...),
    cookieRemove: fn(string $name) => $response->headers->clearCookie($name),
    userLoader: fn(string $id): ?object => User::find($id),
    encryptionKey: 'your-secret-key',
);
```

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
- **Zero mandatory dependencies** — Only requires PHP 8.1+ and the openssl extension
- **Minimalist API** — Each class does one thing, with a small and refined set of methods
- **Security first** — All cryptographic operations use PHP's native CSPRNG, comparisons use `hash_equals`

## License

MIT

---

# migears/security

![Version](https://img.shields.io/badge/version-2.0.0-blue)

> 安全工具集 + MiAuth 经典实现。零强制依赖，PHP 8.1+。

## 特性

- **Password** — 密码哈希与验证（bcrypt，基于 `password_hash`）
- **Token** — 加密安全的随机令牌生成与 TTL 验证
- **Csrf** — CSRF 防护，存储抽象化
- **Sanitizer** — 输入净化与 XSS 防护工具
- **AuthInterface** — 认证接口，可自由扩展
- **MiAuth** — 经典 Session + Cookie "记住我" 实现
- 零强制依赖，仅需 PHP 8.1+ 和 `ext-openssl`
- 所有核心类 < 300 行
- 完整的单元测试覆盖

## 安装

```bash
composer require migears/security
```

要求：
- PHP ^8.1
- ext-openssl

## 快速开始

### 密码哈希

```php
use MiGears\Security\Password;

// 哈希
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

### 令牌生成

```php
use MiGears\Security\Token;

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

// 去除标签，保留指定的
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

// 净化文件名（去除路径穿越、空字节）
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

### 自定义存储

MiAuth 通过 callable 抽象所有 I/O，不依赖任何全局变量：

```php
use MiGears\Security\MiAuth;

$auth = new MiAuth(
    sessionGet: fn(string $key): ?string => $redis->get("session:$sid:$key"),
    sessionSet: fn(string $key, string $val) => $redis->set("session:$sid:$key", $val),
    sessionRemove: fn(string $key) => $redis->del("session:$sid:$key"),
    cookieGet: fn(string $name): ?string => $request->cookies->get($name),
    cookieSet: fn(string $name, string $val, int $exp) => $response->headers->setCookie(...),
    cookieRemove: fn(string $name) => $response->headers->clearCookie($name),
    userLoader: fn(string $id): ?object => User::find($id),
    encryptionKey: 'your-secret-key',
);
```

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
- **零强制依赖** — 仅需 PHP 8.1+ 和 openssl 扩展
- **极简 API** — 每个类只做一件事，方法数量少而精
- **安全优先** — 所有加密操作使用 PHP 原生 CSPRNG，比较使用 `hash_equals`

## License

MIT
