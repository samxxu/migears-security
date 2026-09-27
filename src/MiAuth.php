<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;
use Psr\SimpleCache\CacheInterface;

/**
 * MiAuth — Classic Session authentication + "remember me" Cookie implementation.
 *
 * Session/Cookie I/O is fully abstracted via callables, with no dependency on superglobals.
 * This class owns the session and the user; the remember-me Cookie itself is handled by
 * RememberMe, which works either with a PSR-16 store (opaque, rotating, revocable tokens)
 * or as self-contained encrypted data.
 *
 * @template TUser of object
 * @implements AuthInterface<TUser>
 */
class MiAuth implements AuthInterface
{
    public const VERSION = '2.0.0';

    /** @var string Default session key for the user id */
    private const DEFAULT_SESSION_KEY = '__migears_user_id';
    /** @var string Default remember-me cookie name */
    private const DEFAULT_COOKIE_NAME = '__migears_remember';
    /** @var int Default remember-me TTL in seconds (30 days) */
    private const DEFAULT_REMEMBER_TTL = 2592000;

    /** @var TUser|null */
    private ?object $currentUser = null;
    private bool $resolved = false;
    private readonly RememberMe $remember;

    /**
     * @param callable(string): ?string         $sessionGet
     * @param callable(string, string): void    $sessionSet
     * @param callable(string): void            $sessionRemove
     * @param callable(string): ?string         $cookieGet
     * @param callable(string, string, int): void $cookieSet
     * @param callable(string): void            $cookieRemove
     * @param callable(string): ?TUser          $userLoader
     * @param string                            $encryptionKey     Remember-me encryption key
     *                                                             (only required in the self-contained mode)
     * @param string                            $sessionKey        User ID key name in Session
     * @param string                            $cookieName        Remember-me Cookie name
     * @param int                               $rememberTtl       Remember-me TTL in seconds
     * @param callable(): void|null             $sessionRegenerate Rotates the session ID when a session is established
     *                                                             (e.g. session_regenerate_id(true)). Optional, but
     *                                                             strongly recommended against session fixation.
     * @param CacheInterface|null               $rememberStore     PSR-16 store holding remember-me records. When given,
     *                                                             remember-me tokens become revocable and rotate; when
     *                                                             null, the self-contained encrypted Cookie is used.
     * @param int                               $rememberGrace     Seconds in which an already-consumed token is still
     *                                                             accepted, so parallel requests are not logged out
     *
     * @throws SecurityException If a callback is not callable or a numeric argument is unusable
     */
    public function __construct(
        private readonly mixed $sessionGet,
        private readonly mixed $sessionSet,
        private readonly mixed $sessionRemove,
        private readonly mixed $cookieGet,
        private readonly mixed $cookieSet,
        private readonly mixed $cookieRemove,
        private readonly mixed $userLoader,
        string $encryptionKey = '',
        private readonly string $sessionKey = self::DEFAULT_SESSION_KEY,
        private readonly string $cookieName = self::DEFAULT_COOKIE_NAME,
        int $rememberTtl = self::DEFAULT_REMEMBER_TTL,
        private readonly mixed $sessionRegenerate = null,
        ?CacheInterface $rememberStore = null,
        int $rememberGrace = RememberMe::DEFAULT_GRACE,
    ) {
        self::assertCallable($this->sessionGet, 'sessionGet');
        self::assertCallable($this->sessionSet, 'sessionSet');
        self::assertCallable($this->sessionRemove, 'sessionRemove');
        self::assertCallable($this->cookieGet, 'cookieGet');
        self::assertCallable($this->cookieSet, 'cookieSet');
        self::assertCallable($this->cookieRemove, 'cookieRemove');
        self::assertCallable($this->userLoader, 'userLoader');

        if ($this->sessionRegenerate !== null) self::assertCallable($this->sessionRegenerate, 'sessionRegenerate');

        $this->remember = new RememberMe(
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            cookieName: $this->cookieName,
            ttl: $rememberTtl,
            encryptionKey: $encryptionKey,
            store: $rememberStore,
            grace: $rememberGrace,
        );
    }

    /**
     * Fail fast with a domain exception instead of an Error at first use.
     *
     * Takes mixed on purpose: the constructor documents these arguments as
     * callables, so only an untyped helper can still check them at runtime.
     *
     * @throws SecurityException If the value is not callable
     */
    private static function assertCallable(mixed $value, string $name): void
    {
        if (!is_callable($value)) {
            throw SecurityException::invalidConfiguration($name . ' must be callable.');
        }
    }

    /**
     * Creates a classic implementation using PHP's native $_SESSION + setcookie.
     *
     * Both PHP's own session Cookie and the remember-me Cookie are issued with
     * `Secure`, `HttpOnly` and `SameSite=Lax`; pass `cookieSecure => false` only
     * for local HTTP development. Pass a PSR-16 `rememberStore` to make
     * remember-me tokens revocable and rotating.
     *
     * @param callable(string): ?TUser $userLoader
     * @param array{sessionKey?: string, cookieName?: string, rememberTtl?: int, cookieSecure?: bool, rememberStore?: CacheInterface|null, rememberGrace?: int} $options
     * @return self<TUser>
     */
    public static function classic(callable $userLoader, string $encryptionKey = '', array $options = []): self
    {
        self::assertKnownOptionKeys($options);

        $cookieSecure = $options['cookieSecure'] ?? true;

        $ensureSession = static function () use ($cookieSecure): void {
            if (session_status() === PHP_SESSION_ACTIVE) return;

            // Harden PHP's own session Cookie the same way as the remember-me one
            session_set_cookie_params([
                'path' => '/',
                'secure' => $cookieSecure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);

            session_start();
        };

        return new self(
            sessionGet: static function (string $key) use ($ensureSession): ?string {
                $ensureSession();
                return isset($_SESSION[$key]) ? (string) $_SESSION[$key] : null;
            },
            sessionSet: static function (string $key, string $value) use ($ensureSession): void {
                $ensureSession();
                $_SESSION[$key] = $value;
            },
            sessionRemove: static function (string $key) use ($ensureSession): void {
                $ensureSession();
                unset($_SESSION[$key]);
            },
            cookieGet: static fn(string $name): ?string => isset($_COOKIE[$name]) ? (string) $_COOKIE[$name] : null,
            cookieSet: static function (string $name, string $value, int $expire) use ($cookieSecure): void {
                setcookie($name, $value, [
                    'expires' => $expire,
                    'path' => '/',
                    'secure' => $cookieSecure,
                    'httponly' => true,
                    'samesite' => 'Lax',
                ]);
            },
            cookieRemove: static function (string $name) use ($cookieSecure): void {
                setcookie($name, '', [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'secure' => $cookieSecure,
                    'httponly' => true,
                    'samesite' => 'Lax',
                ]);
            },
            userLoader: $userLoader,
            encryptionKey: $encryptionKey,
            sessionKey: $options['sessionKey'] ?? self::DEFAULT_SESSION_KEY,
            cookieName: $options['cookieName'] ?? self::DEFAULT_COOKIE_NAME,
            rememberTtl: $options['rememberTtl'] ?? self::DEFAULT_REMEMBER_TTL,
            sessionRegenerate: static function () use ($ensureSession): void {
                $ensureSession();
                session_regenerate_id(true);
            },
            rememberStore: $options['rememberStore'] ?? null,
            rememberGrace: $options['rememberGrace'] ?? RememberMe::DEFAULT_GRACE,
        );
    }

    /**
     * Reject misspelled option keys instead of silently falling back to defaults.
     *
     * @param array<string, mixed> $options
     *
     * @throws \InvalidArgumentException If $options contains an unknown key
     */
    private static function assertKnownOptionKeys(array $options): void
    {
        $known = ['sessionKey', 'cookieName', 'rememberTtl', 'cookieSecure', 'rememberStore', 'rememberGrace'];
        $unknown = array_diff(array_keys($options), $known);
        if ($unknown !== []) {
            throw new \InvalidArgumentException('classic() received unknown option(s): ' . implode(', ', $unknown));
        }
    }

    /** @param TUser $user */
    public function login(object $user, bool $remember = false): void
    {
        $userId = $this->extractUserId($user);

        // Validate before touching any state: a failure must not half-login the user
        if ($remember && !$this->remember->isEnabled()) {
            throw SecurityException::missingEncryptionKey();
        }

        $this->regenerateSession();

        ($this->sessionSet)($this->sessionKey, $userId);
        $this->currentUser = $user;
        $this->resolved = true;
        if ($remember) $this->remember->issue($userId);
    }

    /**
     * Log the current user out and revoke their remember-me token.
     *
     * @throws SecurityException If the server-side record could not be dropped
     */
    public function logout(): void
    {
        $token = ($this->cookieGet)($this->cookieName);

        ($this->sessionRemove)($this->sessionKey);
        ($this->cookieRemove)($this->cookieName);
        $this->currentUser = null;
        $this->resolved = true;

        // The local session is already gone; what remains is making sure a copied
        // Cookie cannot be replayed, so a failed revoke is reported rather than hidden.
        if (is_string($token) && $token !== '') $this->remember->revoke($token);
    }

    public function isLoggedIn(): bool
    {
        return $this->getCurrentUser() !== null;
    }

    /** @return TUser|null */
    public function getCurrentUser(): ?object
    {
        if ($this->resolved) return $this->currentUser;
        $this->resolved = true;

        // Try Session
        $userId = ($this->sessionGet)($this->sessionKey);
        if ($userId !== null && $userId !== '') {
            $user = ($this->userLoader)($userId);
            if ($user !== null) {
                $this->currentUser = $user;
                return $user;
            }
            // User no longer exists — drop the stale session key
            ($this->sessionRemove)($this->sessionKey);
        }

        // Fall back to the remember-me Cookie
        if ($this->tryRememberMe()) return $this->currentUser;
        return null;
    }

    private function tryRememberMe(): bool
    {
        $userId = $this->remember->consume();
        if ($userId === null) return false;

        $user = ($this->userLoader)($userId);
        if ($user === null) {
            ($this->cookieRemove)($this->cookieName);
            return false;
        }

        $this->regenerateSession();

        ($this->sessionSet)($this->sessionKey, $userId);
        $this->currentUser = $user;
        return true;
    }

    /**
     * Rotate the session ID so a pre-planted (fixed) session cannot become authenticated.
     *
     * No-op when no regeneration callable was supplied.
     */
    private function regenerateSession(): void
    {
        if ($this->sessionRegenerate !== null) ($this->sessionRegenerate)();
    }

    /**
     * Invalidate every remember-me token of a user, on every device.
     *
     * Bumps the user's remember epoch, so Cookies issued before this call stop
     * resolving. Call it on password change and on "sign out everywhere".
     *
     * @throws SecurityException If no store is configured, or the epoch could not be persisted
     */
    public function revokeRememberTokens(string $userId): void
    {
        $this->remember->revokeForUser($userId);
    }

    /** @throws SecurityException */
    private function extractUserId(object $user): string
    {
        // is_callable() — unlike method_exists() — ignores non-public methods
        if (is_callable([$user, 'getId'])) return (string) $user->getId();
        if (isset($user->id)) return (string) $user->id;
        if ($user instanceof \ArrayAccess && isset($user['id'])) return (string) $user['id'];
        throw new SecurityException('Cannot extract user ID: object must have getId(), ->id, or [\'id\'].');
    }
}
