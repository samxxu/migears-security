# migears/security — Tutorial

> This is the companion to the [README](../README.md). The README is the API reference: one section per
> class, with the exact signatures. This tutorial builds the mental model first, walks the six classes in
> the order you actually meet them, and then spends its longest chapter on the question the README only
> answers in passing — **how to wire this module into `migears/web`**.

## Contents

- [1. What this module is](#1-what-this-module-is)
- [2. The one idea: arguments in, callables out](#2-the-one-idea-arguments-in-callables-out)
- [3. The four leaf utilities](#3-the-four-leaf-utilities)
- [4. MiAuth: session authentication](#4-miauth-session-authentication)
- [5. Wiring into migears/web](#5-wiring-into-migearsweb)
- [6. Common mistakes](#6-common-mistakes)
- [7. What it deliberately does not do](#7-what-it-deliberately-does-not-do)

---

## 1. What this module is

Six concerns, one class each, `MiGears\Security` as the PSR-4 root, every error raised as a
`SecurityException`:

| Class | One job |
|---|---|
| `Password` | hash / verify / rehash a password |
| `Token` | generate cryptographically secure tokens, and timestamped tokens with a TTL |
| `Csrf` | issue and validate a CSRF token, against storage **you** inject |
| `Sanitizer` | clean input: escape, strip tags, email / URL / int / float / string / filename |
| `AuthInterface` + `MiAuth` | session + cookie login state |
| `RememberMe` | the remember-me cookie — self-contained ciphertext, or a revocable PSR-16 record |

The first four are leaves: you call a static method, you get a value. The last two are the ones people
find hard, and they are hard for exactly one reason — the design decision in the next section.

---

## 2. The one idea: arguments in, callables out

Most authentication libraries read `$_SESSION` and write `setcookie()` directly. This one does not read
a single superglobal. Instead:

- **Every value arrives as a method argument** — the password, the submitted CSRF token, the dirty input,
  the user object. Nothing is read from `$_POST` or `$_GET`.
- **Every I/O goes out through a callable you injected** — `sessionGet`, `sessionSet`, `cookieSet`,
  `userLoader`, …

![Overview: values in as arguments, storage out through injected callables](overview-en.svg)

Look at the centre box: `MiAuth` and `RememberMe` never touch `$_SESSION`, a Redis client or `setcookie`.
They hold callables, and when they need to know something they call one. That is why the module has no
runtime dependency beyond PHP itself and the PSR-16 interface: it does not know *where* your data lives,
so it cannot depend on it.

Two consequences follow, and both are load-bearing for the rest of this tutorial:

1. **Testing needs no mocking framework.** Pass `fn() => $array[$key]` for the getter and
   `fn($k, $v) => $array[$k] = $v` for the setter; the whole library runs against a plain array. The
   test suite does exactly this.
2. **`MiAuth::classic()` is a convenience wrapper, not the mechanism.** It builds a ready-made set of
   callables over PHP's native `$_SESSION` / `setcookie`, so a traditional web app does not have to write
   them. It is the *only* place in the module that touches a superglobal, and it is entirely optional.

If you remember one thing: **the module is a pure state machine; you supply the wires.**

---

## 3. The four leaf utilities

### Password

```php
use MiGears\Security\Password;

$hash = Password::hash('mysecret');                       // bcrypt, cost 12
Password::verify('mysecret', $hash);                       // bool
Password::needsRehash($hash);                              // true after you raise the cost
$hash = Password::hash('long passphrase', ['algo' => PASSWORD_ARGON2ID]);
```

The sharp edge is deliberate: **bcrypt only looks at the first 72 bytes.** If the library silently
truncated, two different long passwords sharing a 72-byte prefix would verify against each other. So
`hash()` throws instead of truncating, and you opt into `PASSWORD_ARGON2ID` when you need longer input.

### Token

```php
use MiGears\Security\Token;

$token   = Token::generate();                 // 64 hex chars from random_bytes()
$expiring = Token::generateWithTtl(3600);     // "hexToken.expiresAt"
$raw     = Token::parse($expiring);           // throws when malformed or expired
Token::equals($stored, $submitted);           // timing-safe
```

Read the docblock on `parse()` before using it: **it validates format and TTL only. It does not compare
against a stored value** — that is your job, with `equals()`. This is on purpose: `Token` is the
primitive; the "is this the token I issued?" question belongs to whoever stored it.

### Csrf

```php
use MiGears\Security\Csrf;

$csrf = new Csrf();

// Storage is whatever you inject — here a plain array held by reference.
$storage = [];
$setter  = fn(string $k, string $v) => $storage[$k] = $v;
$getter  = fn(string $k): ?string => $storage[$k] ?? null;

$token = $csrf->generate($setter);            // returns it AND stores it
echo $csrf->htmlField($setter);               // "<input type=hidden …>"

$csrf->validate(userToken: $submitted, getter: $getter);   // throws on failure
```

One long-lived token per storage key is the OWASP-permitted per-session model. Rotate it by calling
`generate()` again after login or a privilege change — not on every request, which would break every
other open tab.

### Sanitizer

```php
use MiGears\Security\Sanitizer;

echo Sanitizer::escape($raw);                 // HTML output — always do this
$plain = Sanitizer::stripTags($html);         // remove all tags
$clean = Sanitizer::stripTags($html, '<p><a><strong>');  // keep these, filter their attributes
$email = Sanitizer::email($raw);              // ?string, null when invalid
$url   = Sanitizer::url($raw);                // ?string, http/https/ftp by default
$id    = Sanitizer::int($raw);
$name  = Sanitizer::filename($raw);           // strips path traversal
```

Two things to internalise. First, this is **not an HTML purifier** — when you allow tags, it keeps only
`href/src/alt/title/width/height`, requires an allowed scheme on `href`/`src`, and drops every `on*`,
`style` and `srcdoc`. It does not parse nesting. Second, there is deliberately **no** "does this look
dangerous?" helper: escape on output, filter on input. Trying to detect badness on the way in is how
sanitizers get bypassed.

---

## 4. MiAuth: session authentication

`MiAuth` owns the login **state**. It does not verify passwords — by the time you call `login()`, you have
already found the user and verified the password. What `MiAuth` does is write that identity down, read it
back, and clear it.

![MiAuth lifecycle: login writes, getCurrentUser reads, logout clears](auth-flow-en.svg)

**`login($user, $remember)`**

1. Extracts the user id, then — before touching any state — checks that remember-me can actually work
   (a store, or an encryption key). A failure must not half-login the user.
2. Rotates the session ID (`session_regenerate_id(true)` through the injected callable), so a session
   planted before login cannot become authenticated.
3. Writes the user id into the session, remembers the user object in memory, and optionally issues the
   remember-me cookie.

**`getCurrentUser()`** is a two-stage lookup: try the session first; if that misses, fall back to the
remember-me cookie. On the cookie path it rebuilds the session so the user is fully logged in again.
`isLoggedIn()` is just `getCurrentUser() !== null`.

**`logout()`** removes the session key, removes the cookie, and — if the incoming cookie carried a token —
asks `RememberMe` to revoke the server-side record, so a copied cookie cannot be replayed.

### The user-object contract

`MiAuth` never assumes a concrete user class. It extracts the id from whatever you hand it, trying in
order `getId()` → `->id` → `['id']`, and throws if none exists. Your domain object only has to expose
one of those three. (The reference app keeps `user_id` as the column-accurate property and adds a tiny
`getId()` alias for exactly this contract.)

### remember-me: two modes

This is the part worth reading twice, because the two modes have **different capabilities**, not just
different wiring:

- **With a PSR-16 `rememberStore`** — the cookie carries an opaque random token; only the token's SHA-256
  is stored; the token rotates on every use (with a short grace window so parallel requests survive the
  rotation); and revocation becomes possible. `logout()` drops this device's record;
  `revokeRememberTokens($userId)` bumps a per-user epoch and invalidates every device at once — call it on
  password change.
- **Without a store** — the cookie is self-contained AES-256-CBC ciphertext with an HMAC. Portable, no
  server storage, but **it can neither rotate nor be revoked**, so an `encryptionKey` is required.

Rule of thumb: **if "sign out everywhere" or "password change logs everyone out" is a requirement, you
must pass a store.**

---

## 5. Wiring into migears/web

`migears/security` has no dependency on `migears/web` — and no awareness of it. The integration is entirely
on your side, and it is small: one adapter class, one registration, and one hook in a resource base class.

![Registration in the composition root, identity resolved in the resource before hook](web-integration-en.svg)

### 5.1 Where the seam is

`migears/web` gives you exactly three things this module needs:

| You need | `migears/web` gives you |
|---|---|
| A place to run code before the handler | a resource's `before(Request): ?Response` |
| A container to hold the configured auth object | `MiRest` **is** a PSR-11 container (`set` / `has` / `get`) |
| Request data without superglobals | `Request::$method`, `$request->header(...)`, `$request->body` |

And it imposes one constraint: **`MiAuth::classic()` uses native `session_start()` / `setcookie()`, which
must run before any output is sent.** In `migears/web` the response body is only written at the very end
(`$response->send()`), and a resource's `before()` runs before the verb handler — so resolving identity in
`before()` satisfies the constraint by construction. Resolve it anywhere after you have started streaming
output and it is too late.

### 5.2 Step 1 — a thin adapter

Do not scatter `MiAuth` calls through your resources. Wrap it once, in your application namespace (not in
`resources/`, which is the routing tree). This is the exact shape the reference app uses:

```php
<?php
namespace App\Auth;

use MiGears\Security\MiAuth;
use Psr\SimpleCache\CacheInterface;

final class WebSessionAuth
{
    /** @var MiAuth<object> */
    private readonly MiAuth $auth;

    public function __construct(
        callable $userLoader,
        string $encryptionKey = '',
        ?CacheInterface $rememberStore = null,
        bool $cookieSecure = true,
    ) {
        $this->auth = MiAuth::classic($userLoader, $encryptionKey, [
            'rememberStore' => $rememberStore,
            'cookieSecure'  => $cookieSecure,
        ]);
    }

    public function login(object $user, bool $remember = false): void { $this->auth->login($user, $remember); }
    public function logout(): void { $this->auth->logout(); }
    public function user(): ?object { return $this->auth->getCurrentUser(); }
    public function revokeRememberTokens(string $userId): void { $this->auth->revokeRememberTokens($userId); }
}
```

Why wrap instead of using `MiAuth` directly? Three reasons: the generic `getCurrentUser(): ?object` is
narrowed to your user type at this one boundary; `classic()`'s option array is assembled in one place; and
your resources never see the security package's API, so swapping the mechanism later is a one-file change.

### 5.3 Step 2 — register in the composition root

`MiRest` is the container, so registration is `set()` in your bootstrap. Only register what needs
configuration — the auth object and its loader do; a value object does not.

```php
<?php
use MiGears\Web\MiRest;
use MiGears\Web\Request;
use MiGears\Web\Response;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use App\Auth\WebSessionAuth;

$rest = new MiRest(baseDir: __DIR__ . '/resources', namespace: 'App\\Resources');

$rest->set(LoggerInterface::class, fn() => new NullLogger());   // required by MiRest
$rest->set(PDO::class, fn() => new PDO('mysql:host=localhost;dbname=app', 'user', 'pass'));
$rest->set(UserManager::class, fn() => new UserManager($rest->get(PDO::class)));

// The security module is wired here: one loader, one session-auth object.
$rest->set(WebSessionAuth::class, fn() => new WebSessionAuth(
    // The loader is the only place that knows how to turn an id into a user.
    // Per the framework convention, it reaches the Manager, never the DAO directly.
    userLoader:     fn(string $id): ?object => $rest->get(UserManager::class)->findById((int) $id),
    encryptionKey:  getenv('REMEMBER_ME_KEY') ?: '',
    rememberStore:  $rest->has(CacheInterface::class) ? $rest->get(CacheInterface::class) : null,
    cookieSecure:   true,   // false only for local plain-HTTP development
));

$response = $rest->handle(Request::fromGlobals());
$response->send();
```

A note on `cookieSecure`. Behind HTTPS it must be `true`. During local HTTP development, a `Secure`
cookie is never sent back by the browser, so the login "succeeds" and then the very next request is
anonymous — the classic "logged in, then immediately logged out" symptom. Infer it from your site URL
rather than hard-coding it, exactly as the reference app does.

### 5.4 Step 3 — resolve identity in a resource base class

Put a base class in your application namespace and extend it from every resource. This is where identity
is resolved, once, before any handler runs.

```php
<?php
namespace App;

use MiGears\Web\AbstractResource as WebResource;
use MiGears\Web\Request;
use MiGears\Web\Response;
use Psr\Container\ContainerInterface;
use App\Auth\WebSessionAuth;

abstract class Resource extends WebResource
{
    protected ?object $user = null;

    public function __construct(protected ContainerInterface $container) {}

    protected function before(Request $request): ?Response
    {
        $auth = $this->container->get(WebSessionAuth::class);
        $this->user = $auth instanceof WebSessionAuth ? $auth->user() : null;

        // Returning a Response here short-circuits: the verb handler never runs.
        // Return null to continue.
        return null;
    }

    protected function requireLogin(): void
    {
        // In a real app, throw your framework's 401 exception instead.
        if ($this->user === null) {
            throw new \RuntimeException('Unauthorized');
        }
    }
}
```

A resource that also takes a path parameter declares its own constructor and **must forward the
container** — this is the `migears/web` 2.3 contract: the container is the first parameter, typed
`ContainerInterface`; wildcards are the remaining parameters, by name.

```php
<?php
namespace App\Resources\users;

use App\Resource;
use MiGears\Web\Request;
use MiGears\Web\Response;
use Psr\Container\ContainerInterface;

class ___user_id___ extends Resource
{
    public function __construct(ContainerInterface $container, private string $user_id)
    {
        parent::__construct($container);
    }

    public function GET(Request $request): Response
    {
        $this->requireLogin();

        return Response::json(['id' => $this->user_id, 'me' => $this->user?->getId()]);
    }
}
```

### 5.5 Step 4 — login and logout resources

A `sessions` resource (`resources/sessions.php` → `class sessions`) is the whole login surface. Notice
that password verification is the **caller's** job; `MiAuth::login()` is handed an already-verified user.

```php
<?php
namespace App\Resources;

use App\Resource;
use MiGears\Security\Password;
use MiGears\Security\Sanitizer;
use MiGears\Web\Request;
use MiGears\Web\Response;
use App\Auth\WebSessionAuth;

class sessions extends Resource
{
    public function POST(Request $request): Response
    {
        $email    = Sanitizer::email((string) ($request->body['email'] ?? ''));
        $password = (string) ($request->body['password'] ?? '');

        if ($email === null || $password === '') {
            return Response::json(['error' => 'invalid credentials'], 401);
        }

        $user = $this->container->get(UserManager::class)->findByEmail($email);
        if ($user === null || !Password::verify($password, $user->passwordHash)) {
            // One message for both branches: do not leak whether the email exists.
            return Response::json(['error' => 'invalid credentials'], 401);
        }

        $this->container->get(WebSessionAuth::class)
             ->login($user, remember: (bool) ($request->body['remember'] ?? false));

        return Response::json(['id' => $user->getId()]);
    }

    public function DELETE(Request $request): Response
    {
        $this->container->get(WebSessionAuth::class)->logout();

        return Response::empty(204);
    }
}
```

On a password change, call `revokeRememberTokens($userId)` so every device's cookie stops resolving. This
only does anything when a `rememberStore` is configured — without one, the cookies are self-contained and
there is nothing to revoke.

### 5.6 Step 5 — CSRF on state-changing requests

Issue a token on the page that renders the form, submit it back, validate it before the handler runs.
Since identity resolution in `before()` already starts the PHP session (`MiAuth::classic()` does it on the
first session read), the session is available to store the token.

```php
// Rendering a form (a GET handler):
$csrf = $this->container->get(Csrf::class);
echo $csrf->htmlField(fn(string $k, string $v) => $_SESSION[$k] = $v);
```

```php
// In the base class before(), after identity is resolved:
if (in_array($request->method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
    $csrf = $this->container->get(Csrf::class);
    try {
        $csrf->validate(
            userToken: (string) ($request->header('x-csrf-token') ?? $request->body['_csrf'] ?? ''),
            getter:    static fn(string $k): ?string => isset($_SESSION[$k]) ? (string) $_SESSION[$k] : null,
        );
    } catch (\MiGears\Security\Exception\SecurityException) {
        return Response::json(['error' => 'CSRF token invalid'], 419);
    }
}
```

Reading `$_SESSION` inside *your* closure is fine — the "no global state" rule is about the library, not
your application. The library only ever sees the callables you hand it.

### 5.7 Step 6 — Sanitizer at the boundary

Filter on the way in, escape on the way out. At the resource boundary:

```php
$id     = Sanitizer::int($request->body['id'] ?? null);        // ?int, null when invalid
$title  = Sanitizer::string((string) ($request->body['title'] ?? ''));
$avatar = Sanitizer::filename((string) ($request->body['avatar'] ?? ''));  // strips traversal
```

and escape anything user-supplied that reaches an HTML template with `Sanitizer::escape()` (or let your
template engine do it — `migears/pages` escapes by default; do not double-escape).

### 5.8 Version note: `migears/web` 2.1 vs 2.3

The security integration above is **identical** across versions — a `WebSessionAuth` adapter, a container
registration, and a `before()` that resolves the user. Only the plumbing by which a resource reaches the
container and its path parameters changed:

| | `migears/web` 2.1–2.2 | `migears/web` ≥ 2.3 |
|---|---|---|
| Container in a resource | injected via `setRest()`; read with `$this->resolve($id)` | first constructor parameter typed `ContainerInterface`; read with `$this->container->get($id)` |
| Path wildcards | `$this->params['user_id']` | constructor parameter `private string $user_id` |

(The reference `server/` application in this workspace pins `^2.1`, so its resources still use
`$this->params` and `$this->resolve()`; the auth wiring in it is otherwise the pattern shown here.) The
security package itself does not care which you are on — it never sees a `Request`, a container or a
route.

---

## 6. Common mistakes

1. **Resolving identity after output has started.** `session_start()` and `setcookie()` must precede any
   output. In `migears/web`, always resolve in `before()`, never in an `after()` hook or a streamed body.
2. **Forgetting the encryption key while using `remember: true`.** `login()` throws
   `SecurityException::missingEncryptionKey()` — by design, because a half-configured remember-me must fail
   loudly rather than issue a credential that cannot be revoked.
3. **Expecting revocation without a store.** The self-contained cookie mode cannot be revoked. If "sign
   out everywhere" matters, pass a PSR-16 `rememberStore`.
4. **A user object without `getId()` / `->id` / `['id']`.** `MiAuth` will throw when it tries to extract
   the id.
5. **A password longer than 72 bytes on bcrypt.** `Password::hash()` throws; switch to
   `['algo' => PASSWORD_ARGON2ID]`.
6. **Treating `Token::parse()` as verification.** It checks format and TTL only. Compare against your
   stored value with `Token::equals()`.
7. **Using `Sanitizer` as an HTML purifier.** It is not one. Escape on output.
8. **`cookieSecure: true` on local HTTP.** The cookie is never sent back; login looks successful and then
   the session is gone.

---

## 7. What it deliberately does not do

- **No user lookup.** `userLoader` is yours; the convention is to reach your Manager, not the DAO.
- **No persistence choice.** Where the session, the cache or the cookie lives is decided by the callables
  you inject — this module never assumes `$_SESSION`.
- **No bearer / refresh token authentication.** That is
  `migears/security-token-auth`; here `Token` is only the low-level primitive.
- **No full HTML purification.** `Sanitizer` strips and escapes; it does not parse HTML.
- **No framework coupling.** `MiAuth::classic()` is a convenience for native PHP sessions, not a
  `migears/web` dependency. The adapter pattern in §5 applies to any host framework.

---
---

# migears/security — 教程

> 本文是 [README](../README.md) 的配套。README 是 API 参考：一个类一节，给出精确签名。本教程先建立
> 心智模型，再按你实际遇到的顺序走一遍六个类，最后用最长的一章回答 README 只是顺带一提的问题——
> **怎么把这个模块接进 `migears/web`**。

## 目录

- [1. 这个模块是什么](#1-这个模块是什么)
- [2. 唯一的核心思想：值进、callable 出](#2-唯一的核心思想值进callable-出)
- [3. 四个叶子工具](#3-四个叶子工具)
- [4. MiAuth：会话认证](#4-miauth会话认证)
- [5. 接入 migears/web](#5-接入-migearsweb)
- [6. 常见错误](#6-常见错误)
- [7. 它刻意不做什么](#7-它刻意不做什么)

---

## 1. 这个模块是什么

六个关注点，各一个类，PSR-4 根为 `MiGears\Security`，所有错误统一抛 `SecurityException`：

| 类 | 唯一职责 |
|---|---|
| `Password` | 密码的哈希 / 校验 / 重哈希 |
| `Token` | 生成加密安全令牌，以及带 TTL 的时间戳令牌 |
| `Csrf` | 签发与校验 CSRF 令牌，存储**由你注入** |
| `Sanitizer` | 清洗输入：转义、剥标签、email / URL / int / float / string / 文件名 |
| `AuthInterface` + `MiAuth` | 会话 + Cookie 登录态 |
| `RememberMe` | remember-me Cookie——自包含密文，或可撤销的 PSR-16 记录 |

前四个是叶子：调一个静态方法，得到一个值。后两个是让人犯难的地方，而它们难的原因只有一个——
也就是下一节的设计决定。

---

## 2. 唯一的核心思想：值进、callable 出

多数认证库直接读写 `$_SESSION`、调用 `setcookie()`。这个模块不读任何超级全局。取而代之：

- **每个值都以方法参数传入**——密码、提交的 CSRF 令牌、脏输入、user 对象。不从 `$_POST`、`$_GET` 读。
- **每次 I/O 都经你注入的 callable 走出**——`sessionGet`、`sessionSet`、`cookieSet`、`userLoader`……

![总览：值以参数进，存储经注入的 callable 出](overview-zh.svg)

看中间那个框：`MiAuth` 与 `RememberMe` 从不碰 `$_SESSION`、Redis 客户端或 `setcookie`。它们握着
callable，需要知道什么时就去调一个。这也是为什么这个模块除了 PHP 本身和 PSR-16 接口之外没有运行时依赖：
它不知道你的数据存在哪，因此也无从依赖。

由此有两个后果，它们支撑着本教程余下的全部内容：

1. **测试不需要 mock 框架。** getter 传 `fn() => $array[$key]`，setter 传 `fn($k, $v) => $array[$k] = $v`，
   整个库就跑在一个普通数组之上。测试套件正是这么做的。
2. **`MiAuth::classic()` 是便捷封装，不是机制本身。** 它在 PHP 原生 `$_SESSION` / `setcookie` 之上
   预先搭好一组 callable，让传统 Web 应用不必手写它们。它是模块里**唯一**触碰超级全局的地方，而且完全可选。

如果只记一件事：**这个模块是一台纯状态机；线由你来接。**

---

## 3. 四个叶子工具

### Password

```php
use MiGears\Security\Password;

$hash = Password::hash('mysecret');                       // bcrypt，cost 12
Password::verify('mysecret', $hash);                       // bool
Password::needsRehash($hash);                              // 提高 cost 后为 true
$hash = Password::hash('long passphrase', ['algo' => PASSWORD_ARGON2ID]);
```

这个坑是刻意留的：**bcrypt 只看前 72 字节。** 如果库静默截断，两个前 72 字节相同的长密码就会互相
验证通过。所以 `hash()` 直接抛异常而不是截断；需要接受更长输入时，显式改用 `PASSWORD_ARGON2ID`。

### Token

```php
use MiGears\Security\Token;

$token    = Token::generate();                // 由 random_bytes() 得到的 64 位十六进制
$expiring = Token::generateWithTtl(3600);     // "hexToken.expiresAt"
$raw      = Token::parse($expiring);          // 格式错误或已过期则抛异常
Token::equals($stored, $submitted);           // 时序安全比较
```

用 `parse()` 之前先读它的文档注释：**它只校验格式与 TTL，不和任何已存值比对**——比对是你的活，用
`equals()`。这是有意的：`Token` 是原语；「这是不是我签发的那一个」这个问题属于存它的人。

### Csrf

```php
use MiGears\Security\Csrf;

$csrf = new Csrf();

// 存储是你注入的任意实现——这里用按引用持有的普通数组。
$storage = [];
$setter  = fn(string $k, string $v) => $storage[$k] = $v;
$getter  = fn(string $k): ?string => $storage[$k] ?? null;

$token = $csrf->generate($setter);            // 返回并存储它
echo $csrf->htmlField($setter);               // "<input type=hidden …>"

$csrf->validate(userToken: $submitted, getter: $getter);   // 失败抛异常
```

每个存储键一个长期令牌，这是 OWASP 认可的每会话模型。要轮换就在登录或权限变更后再次调用
`generate()`——但不要每请求都轮换，那会破坏所有其他已打开的标签页。

### Sanitizer

```php
use MiGears\Security\Sanitizer;

echo Sanitizer::escape($raw);                 // HTML 输出——永远这么做
$plain = Sanitizer::stripTags($html);         // 去掉全部标签
$clean = Sanitizer::stripTags($html, '<p><a><strong>');  // 保留这些，并过滤其属性
$email = Sanitizer::email($raw);              // ?string，无效为 null
$url   = Sanitizer::url($raw);                // ?string，默认只允许 http/https/ftp
$id    = Sanitizer::int($raw);
$name  = Sanitizer::filename($raw);           // 去除路径穿越
```

两点要刻进脑子。第一，它**不是 HTML purifier**——允许标签时，它只保留 `href/src/alt/title/width/height`，
要求 `href`/`src` 使用允许的协议，删掉所有 `on*`、`style`、`srcdoc`；它不解析嵌套。第二，它刻意**不提供**
「这段输入是否危险」的检测函数：输出转义、输入过滤。在入口处识别「坏东西」正是 sanitizer 被绕过的原因。

---

## 4. MiAuth：会话认证

`MiAuth` 掌管登录**状态**。它不校验密码——你调用 `login()` 时，用户已经查到、密码已经验过。`MiAuth`
做的是把这份身份写下来、读回来、清掉。

![MiAuth 生命周期：login 写、getCurrentUser 读、logout 清](auth-flow-zh.svg)

**`login($user, $remember)`**

1. 取出用户 id，然后在碰任何状态之前先检查 remember-me 是否真的可用（有 store，或有加密密钥）。
   失败不能造成「半登录」。
2. 轮换会话 ID（经注入的 callable 调用 `session_regenerate_id(true)`），使登录前被植入的会话无法
   变成已认证会话。
3. 把用户 id 写进会话、在内存里记住 user 对象，并按需签发 remember-me Cookie。

**`getCurrentUser()`** 是两段查找：先试会话；未命中则回退到 remember-me Cookie。走 Cookie 路径时会
重建会话，于是用户重新成为完整登录态。`isLoggedIn()` 就是 `getCurrentUser() !== null`。

**`logout()`** 清除会话键、删除 Cookie，并且——如果进来的 Cookie 带着令牌——让 `RememberMe` 撤销
服务端记录，使被复制的 Cookie 无法重放。

### user 对象的约定

`MiAuth` 从不假定具体的 user 类。它从你给的对象里按顺序尝试 `getId()` → `->id` → `['id']` 取 id，
三者都没有就抛异常。你的领域对象只需暴露其中一个。（参考应用坚持「列名即属性名」的 `user_id`，为这条
约定补了一个极小的 `getId()` 别名。）

### remember-me：两种模式

这一段值得读两遍，因为两种模式的**能力**不同，不只是接线不同：

- **传了 PSR-16 `rememberStore`**——Cookie 携带不透明随机令牌；服务端只存令牌的 SHA-256；每次使用都会
  轮换（带一个短宽限期，使并发请求不会在轮换瞬间被登出）；并且可以撤销。`logout()` 撤销本设备记录；
  `revokeRememberTokens($userId)` 递增每用户 epoch，一次让所有设备失效——改密时调用。
- **不传 store**——Cookie 是自包含的 AES-256-CBC 密文加 HMAC。可移植、无需服务端存储，但**既不能轮换
  也不能撤销**，因此必须提供 `encryptionKey`。

经验法则：**如果「登出所有设备」或「改密让所有人下线」是需求，就必须传 store。**

---

## 5. 接入 migears/web

`migears/security` 不依赖 `migears/web`，也不知道它的存在。集成全在你这一侧，而且很小：一个适配器类、
一次注册、外加资源基类里的一个钩子。

![在组合根注册，在资源 before 钩子里解析身份](web-integration-zh.svg)

### 5.1 接缝在哪里

`migears/web` 恰好提供了本模块需要的三样东西：

| 你需要 | `migears/web` 提供 |
|---|---|
| 处理器之前运行代码的地方 | 资源的 `before(Request): ?Response` |
| 存放已配置认证对象的容器 | `MiRest` **就是** PSR-11 容器（`set` / `has` / `get`） |
| 不依赖超级全局的请求数据 | `Request::$method`、`$request->header(...)`、`$request->body` |

并且它施加了一条约束：**`MiAuth::classic()` 用原生 `session_start()` / `setcookie()`，必须在任何输出
之前运行。** 在 `migears/web` 里，响应体只在最后（`$response->send()`）才写出，而资源的 `before()` 在
动词处理器之前运行——因此在 `before()` 里解析身份，天然满足这条约束。等开始流式输出之后再解析就晚了。

### 5.2 第 1 步——一层薄适配器

不要把 `MiAuth` 调用散落到各个资源里。在你的应用命名空间里包一次（**不要**放进 `resources/`，那是路由树）。
这与参考应用完全同形：

```php
<?php
namespace App\Auth;

use MiGears\Security\MiAuth;
use Psr\SimpleCache\CacheInterface;

final class WebSessionAuth
{
    /** @var MiAuth<object> */
    private readonly MiAuth $auth;

    public function __construct(
        callable $userLoader,
        string $encryptionKey = '',
        ?CacheInterface $rememberStore = null,
        bool $cookieSecure = true,
    ) {
        $this->auth = MiAuth::classic($userLoader, $encryptionKey, [
            'rememberStore' => $rememberStore,
            'cookieSecure'  => $cookieSecure,
        ]);
    }

    public function login(object $user, bool $remember = false): void { $this->auth->login($user, $remember); }
    public function logout(): void { $this->auth->logout(); }
    public function user(): ?object { return $this->auth->getCurrentUser(); }
    public function revokeRememberTokens(string $userId): void { $this->auth->revokeRememberTokens($userId); }
}
```

为什么要包一层而不是直接用 `MiAuth`？三个理由：泛型的 `getCurrentUser(): ?object` 在这一处边界收敛成
你的 user 类型；`classic()` 的选项数组只在一处拼装；你的资源永远看不到安全包的 API，日后替换机制是
改一个文件的事。

### 5.3 第 2 步——在组合根注册

`MiRest` 就是容器，所以注册就是在 bootstrap 里 `set()`。只注册需要配置的东西——认证对象和它的 loader
需要；值对象不需要。

```php
<?php
use MiGears\Web\MiRest;
use MiGears\Web\Request;
use MiGears\Web\Response;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use App\Auth\WebSessionAuth;

$rest = new MiRest(baseDir: __DIR__ . '/resources', namespace: 'App\\Resources');

$rest->set(LoggerInterface::class, fn() => new NullLogger());   // MiRest 必需
$rest->set(PDO::class, fn() => new PDO('mysql:host=localhost;dbname=app', 'user', 'pass'));
$rest->set(UserManager::class, fn() => new UserManager($rest->get(PDO::class)));

// 安全模块在这里接线：一个 loader，一个会话认证对象。
$rest->set(WebSessionAuth::class, fn() => new WebSessionAuth(
    // loader 是唯一知道「id 怎么变成 user」的地方。
    // 按框架约定，它触碰 Manager，绝不直接接触 DAO。
    userLoader:     fn(string $id): ?object => $rest->get(UserManager::class)->findById((int) $id),
    encryptionKey:  getenv('REMEMBER_ME_KEY') ?: '',
    rememberStore:  $rest->has(CacheInterface::class) ? $rest->get(CacheInterface::class) : null,
    cookieSecure:   true,   // 仅本地纯 HTTP 开发时为 false
));

$response = $rest->handle(Request::fromGlobals());
$response->send();
```

关于 `cookieSecure`：HTTPS 下必须是 `true`。本地 HTTP 开发时，浏览器不会回传 `Secure` Cookie，于是登录
「成功」、紧接着的下一个请求却是匿名的——这就是经典的「刚登录就掉线」。请按站点 URL 推断它，而不是写死，
参考应用正是这么做的。

### 5.4 第 3 步——在资源基类里解析身份

在你的应用命名空间放一个基类，让每个资源继承它。身份就在这里、在处理器运行之前，解析一次。

```php
<?php
namespace App;

use MiGears\Web\AbstractResource as WebResource;
use MiGears\Web\Request;
use MiGears\Web\Response;
use Psr\Container\ContainerInterface;
use App\Auth\WebSessionAuth;

abstract class Resource extends WebResource
{
    protected ?object $user = null;

    public function __construct(protected ContainerInterface $container) {}

    protected function before(Request $request): ?Response
    {
        $auth = $this->container->get(WebSessionAuth::class);
        $this->user = $auth instanceof WebSessionAuth ? $auth->user() : null;

        // 这里返回 Response 会短路：动词处理器不再运行。
        // 返回 null 则继续。
        return null;
    }

    protected function requireLogin(): void
    {
        // 真实应用里抛框架的 401 异常。
        if ($this->user === null) {
            throw new \RuntimeException('Unauthorized');
        }
    }
}
```

同时带路径参数的资源要声明自己的构造器，并且**必须把容器转发上去**——这是 `migears/web` 2.3 的契约：
容器是第一个参数，类型写 `ContainerInterface`；通配是其余参数，按名字传入。

```php
<?php
namespace App\Resources\users;

use App\Resource;
use MiGears\Web\Request;
use MiGears\Web\Response;
use Psr\Container\ContainerInterface;

class ___user_id___ extends Resource
{
    public function __construct(ContainerInterface $container, private string $user_id)
    {
        parent::__construct($container);
    }

    public function GET(Request $request): Response
    {
        $this->requireLogin();

        return Response::json(['id' => $this->user_id, 'me' => $this->user?->getId()]);
    }
}
```

### 5.5 第 4 步——登录与登出资源

一个 `sessions` 资源（`resources/sessions.php` → `class sessions`）就是全部登录面。注意密码校验是
**调用方**的活；`MiAuth::login()` 拿到的是已经验过密的 user。

```php
<?php
namespace App\Resources;

use App\Resource;
use MiGears\Security\Password;
use MiGears\Security\Sanitizer;
use MiGears\Web\Request;
use MiGears\Web\Response;
use App\Auth\WebSessionAuth;

class sessions extends Resource
{
    public function POST(Request $request): Response
    {
        $email    = Sanitizer::email((string) ($request->body['email'] ?? ''));
        $password = (string) ($request->body['password'] ?? '');

        if ($email === null || $password === '') {
            return Response::json(['error' => 'invalid credentials'], 401);
        }

        $user = $this->container->get(UserManager::class)->findByEmail($email);
        if ($user === null || !Password::verify($password, $user->passwordHash)) {
            // 两个分支同一句消息：不要泄露邮箱是否存在。
            return Response::json(['error' => 'invalid credentials'], 401);
        }

        $this->container->get(WebSessionAuth::class)
             ->login($user, remember: (bool) ($request->body['remember'] ?? false));

        return Response::json(['id' => $user->getId()]);
    }

    public function DELETE(Request $request): Response
    {
        $this->container->get(WebSessionAuth::class)->logout();

        return Response::empty(204);
    }
}
```

改密时调用 `revokeRememberTokens($userId)`，让每台设备的 Cookie 立即失效。只有配置了 `rememberStore`
时它才起作用——没有 store 时 Cookie 自包含，没有东西可撤销。

### 5.6 第 5 步——对写操作做 CSRF 防护

在渲染表单的页面签发令牌，提交回来，在处理器运行之前校验。由于 `before()` 里的身份解析已经启动了 PHP
会话（`MiAuth::classic()` 在第一次读会话时启动它），会话可用于存放令牌。

```php
// 渲染表单（某个 GET 处理器）：
$csrf = $this->container->get(Csrf::class);
echo $csrf->htmlField(fn(string $k, string $v) => $_SESSION[$k] = $v);
```

```php
// 在基类 before() 中，身份解析之后：
if (in_array($request->method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
    $csrf = $this->container->get(Csrf::class);
    try {
        $csrf->validate(
            userToken: (string) ($request->header('x-csrf-token') ?? $request->body['_csrf'] ?? ''),
            getter:    static fn(string $k): ?string => isset($_SESSION[$k]) ? (string) $_SESSION[$k] : null,
        );
    } catch (\MiGears\Security\Exception\SecurityException) {
        return Response::json(['error' => 'CSRF token invalid'], 419);
    }
}
```

在你自己的闭包里读 `$_SESSION` 完全没问题——「无全局状态」的规矩是给库定的，不是给你的应用定的。库只
看得见你交给它的 callable。

### 5.7 第 6 步——在边界使用 Sanitizer

入口过滤，出口转义。资源边界上：

```php
$id     = Sanitizer::int($request->body['id'] ?? null);        // ?int，无效为 null
$title  = Sanitizer::string((string) ($request->body['title'] ?? ''));
$avatar = Sanitizer::filename((string) ($request->body['avatar'] ?? ''));  // 去除穿越
```

任何用户提供、进入 HTML 模板的内容，用 `Sanitizer::escape()` 转义（或交给模板引擎——`migears/pages`
默认转义；不要重复转义）。

### 5.8 版本说明：`migears/web` 2.1 与 2.3

上面这套安全集成在各版本间**完全相同**——一个 `WebSessionAuth` 适配器、一次容器注册、一个解析身份的
`before()`。变的只是资源拿到容器与路径参数的方式：

| | `migears/web` 2.1–2.2 | `migears/web` ≥ 2.3 |
|---|---|---|
| 资源取容器 | 经 `setRest()` 注入；用 `$this->resolve($id)` 读 | 构造器第一个参数类型写 `ContainerInterface`；用 `$this->container->get($id)` 读 |
| 路径通配 | `$this->params['user_id']` | 构造器参数 `private string $user_id` |

（本工作区里的参考应用 `server/` 钉的是 `^2.1`，因此它的资源仍用 `$this->params` 与 `$this->resolve()`；
它的认证接线其余部分就是这里给出的模式。）安全包本身不关心你在哪个版本——它从来看不到 `Request`、容器或路由。

---

## 6. 常见错误

1. **在输出开始之后解析身份。** `session_start()` 与 `setcookie()` 必须先于任何输出。在 `migears/web`
   里永远在 `before()` 解析，绝不在 `after()` 钩子里、也绝不在已开始流式的响应体之后。
2. **用 `remember: true` 却忘了加密密钥。** `login()` 抛 `SecurityException::missingEncryptionKey()`
   ——这是有意的：半配置的 remember-me 必须大声失败，而不是签发一个无法撤销的凭证。
3. **没有 store 却指望能撤销。** 自包含 Cookie 模式无法撤销。若在意「登出所有设备」，就传 PSR-16
   `rememberStore`。
4. **user 对象没有 `getId()` / `->id` / `['id']`。** `MiAuth` 取 id 时会抛异常。
5. **bcrypt 下密码超过 72 字节。** `Password::hash()` 抛异常；改用 `['algo' => PASSWORD_ARGON2ID]`。
6. **把 `Token::parse()` 当成验证。** 它只校验格式与 TTL。请用 `Token::equals()` 与你存的值比对。
7. **把 `Sanitizer` 当 HTML purifier。** 它不是。输出务必转义。
8. **本地 HTTP 下 `cookieSecure: true`。** Cookie 收不回来；登录看似成功，会话随即消失。

---

## 7. 它刻意不做什么

- **不做用户查询。** `userLoader` 是你的事；约定是触碰 Manager，而非 DAO。
- **不替你选持久化。** 会话、缓存、Cookie 存在哪里由你注入的 callable 决定——本模块绝不假定 `$_SESSION`。
- **不做 Bearer / refresh 令牌认证。** 那是 `migears/security-token-auth`；这里的 `Token` 只是底层原语。
- **不做完整 HTML 净化。** `Sanitizer` 只做剥离与转义，不解析 HTML。
- **不绑定框架。** `MiAuth::classic()` 是给原生 PHP 会话的便捷，不是对 `migears/web` 的依赖。§5 的适配器
  模式适用于任何宿主框架。
