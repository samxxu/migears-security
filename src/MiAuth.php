<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;
use Psr\SimpleCache\CacheInterface;

/**
 * MiAuth — Classic Session authentication + "remember me" Cookie implementation.
 *
 * Session/Cookie I/O is fully abstracted via callables, with no dependency on superglobals.
 *
 * Remember-me works in one of two modes:
 *
 *  - With a PSR-16 `$rememberStore`, the Cookie carries an opaque token and the server
 *    keeps the matching record keyed by that token's hash. Tokens rotate on every use
 *    and can be revoked: `logout()` drops one record, `revokeRememberTokens()` drops
 *    every device of a user at once.
 *  - Without a store, the Cookie stays self-contained encrypted data. That mode cannot
 *    be revoked and stays replayable until it expires.
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
    /** @var int Default window in which an already-consumed token is tolerated (30 seconds) */
    private const DEFAULT_REMEMBER_GRACE = 30;
    /** @var int Remember-me token length in bytes before hex encoding */
    private const REMEMBER_TOKEN_LENGTH = 32;
    /** @var int Length of the hashed suffix in remember-me cache keys */
    private const KEY_HASH_LENGTH = 32;

    /** @var TUser|null */
    private ?object $currentUser = null;
    private bool $resolved = false;

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
        private readonly string $encryptionKey = '',
        private readonly string $sessionKey = self::DEFAULT_SESSION_KEY,
        private readonly string $cookieName = self::DEFAULT_COOKIE_NAME,
        private readonly int $rememberTtl = self::DEFAULT_REMEMBER_TTL,
        private readonly mixed $sessionRegenerate = null,
        private readonly ?CacheInterface $rememberStore = null,
        private readonly int $rememberGrace = self::DEFAULT_REMEMBER_GRACE,
    ) {
        self::assertCallable($this->sessionGet, 'sessionGet');
        self::assertCallable($this->sessionSet, 'sessionSet');
        self::assertCallable($this->sessionRemove, 'sessionRemove');
        self::assertCallable($this->cookieGet, 'cookieGet');
        self::assertCallable($this->cookieSet, 'cookieSet');
        self::assertCallable($this->cookieRemove, 'cookieRemove');
        self::assertCallable($this->userLoader, 'userLoader');

        if ($this->sessionRegenerate !== null) self::assertCallable($this->sessionRegenerate, 'sessionRegenerate');

        if ($this->rememberTtl < 1) {
            throw SecurityException::invalidConfiguration('rememberTtl must be at least 1 second.');
        }

        if ($this->rememberGrace < 0) {
            throw SecurityException::invalidConfiguration('rememberGrace cannot be negative.');
        }
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
            rememberGrace: $options['rememberGrace'] ?? self::DEFAULT_REMEMBER_GRACE,
        );
    }

    /** @param TUser $user */
    public function login(object $user, bool $remember = false): void
    {
        $userId = $this->extractUserId($user);

        // Validate before touching any state: a failure must not half-login the user
        if ($remember && $this->rememberStore === null && $this->encryptionKey === '') {
            throw SecurityException::missingEncryptionKey();
        }

        $this->regenerateSession();

        ($this->sessionSet)($this->sessionKey, $userId);
        $this->currentUser = $user;
        $this->resolved = true;
        if ($remember) $this->setRememberCookie($userId);
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
        // Cookie cannot be replayed, so a failed delete is reported rather than hidden.
        if ($this->rememberStore !== null && is_string($token) && $token !== '') {
            if (!$this->forgetRememberRecord($token)) {
                throw new SecurityException('Failed to revoke the stored remember-me record.');
            }
        }
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

        // Fall back to remember-me Cookie
        if ($this->tryRememberMe()) return $this->currentUser;
        return null;
    }

    private function tryRememberMe(): bool
    {
        // Without a store or a key there is no way to evaluate the Cookie at all,
        // so it is left untouched rather than deleted on a guess.
        if ($this->rememberStore === null && $this->encryptionKey === '') return false;

        $cookieValue = ($this->cookieGet)($this->cookieName);
        if ($cookieValue === null || $cookieValue === '') return false;

        $userId = $this->rememberStore !== null
            ? $this->resolveStoredToken($cookieValue)
            : $this->resolveEncryptedCookie($cookieValue);

        if ($userId === null) {
            ($this->cookieRemove)($this->cookieName);
            return false;
        }

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

    // --- Remember-me: server-side record mode (PSR-16 store) ---

    /**
     * Resolve an opaque remember-me token, rotating it on first use.
     *
     * @return string|null The user ID, or null when the token must not be honoured
     */
    private function resolveStoredToken(string $token): ?string
    {
        $record = $this->readRememberRecord($token);
        if ($record === null) return null;

        if ((int) $record['exp'] < time()) {
            $this->forgetRememberRecord($token);
            return null;
        }

        $userId = (string) $record['uid'];

        // Bumping the user's epoch revokes every device at once
        if ((int) $record['epoch'] !== $this->rememberEpoch($userId)) {
            $this->forgetRememberRecord($token);
            return null;
        }

        if (($record['rotated_at'] ?? null) !== null) {
            // Already exchanged. A parallel request may legitimately still carry it,
            // so it is honoured inside the grace window and rejected afterwards.
            return (time() - (int) $record['rotated_at']) <= $this->rememberGrace ? $userId : null;
        }

        $this->rotateRememberToken($token, $record);

        return $userId;
    }

    /**
     * Issue a successor token and retire the presented one.
     *
     * Best effort by design: the presented token was valid, so a failed successor
     * write leaves the current Cookie usable rather than logging the user out.
     *
     * @param array<string, mixed> $record
     */
    private function rotateRememberToken(string $token, array $record): void
    {
        $expiresAt = (int) $record['exp'];
        $successor = Token::generate(self::REMEMBER_TOKEN_LENGTH);

        $stored = $this->saveRememberRecord($successor, [
            'uid' => (string) $record['uid'],
            'exp' => $expiresAt,
            'epoch' => (int) $record['epoch'],
            'rotated_at' => null,
        ]);

        if (!$stored) return;

        if ($this->rememberGrace > 0) {
            // Keep the consumed token briefly so parallel requests survive the rotation
            $this->saveRememberRecord($token, [
                'uid' => (string) $record['uid'],
                'exp' => $expiresAt,
                'epoch' => (int) $record['epoch'],
                'rotated_at' => time(),
            ], $this->rememberGrace);
        } else {
            $this->forgetRememberRecord($token);
        }

        ($this->cookieSet)($this->cookieName, $successor, $expiresAt);
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
        if ($this->rememberStore === null) {
            throw SecurityException::invalidConfiguration(
                'Revoking remember-me tokens requires a PSR-16 rememberStore.'
            );
        }

        $stored = $this->rememberStore->set(
            $this->rememberEpochKey($userId),
            $this->rememberEpoch($userId) + 1
        );

        // A silently failed epoch write would leave every old Cookie valid
        if ($stored !== true) {
            throw new SecurityException('Failed to persist the remember-me epoch; no token was revoked.');
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readRememberRecord(string $token): ?array
    {
        $value = $this->rememberStore?->get($this->rememberRecordKey($token));

        return is_array($value) && isset($value['uid'], $value['exp'], $value['epoch']) ? $value : null;
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return bool Whether the record was stored
     */
    private function saveRememberRecord(string $token, array $record, ?int $ttl = null): bool
    {
        $ttl ??= max(1, (int) $record['exp'] - time());

        return $this->rememberStore?->set($this->rememberRecordKey($token), $record, $ttl) === true;
    }

    /**
     * @return bool Whether the record is gone afterwards
     */
    private function forgetRememberRecord(string $token): bool
    {
        return $this->rememberStore?->delete($this->rememberRecordKey($token)) === true;
    }

    private function rememberEpoch(string $userId): int
    {
        $epoch = $this->rememberStore?->get($this->rememberEpochKey($userId));

        return is_int($epoch) ? $epoch : 0;
    }

    /**
     * Cache key for a token record.
     *
     * Keyed by the token's hash, and kept inside the PSR-16 key character set
     * (letters, digits and underscores) at a length implementations accept.
     */
    private function rememberRecordKey(string $token): string
    {
        return '__migears_rem_' . substr(hash('sha256', $token), 0, self::KEY_HASH_LENGTH);
    }

    /**
     * Cache key for a user's remember epoch.
     *
     * Hashed because a user ID may contain characters PSR-16 forbids in a key.
     */
    private function rememberEpochKey(string $userId): string
    {
        return '__migears_remv_' . substr(hash('sha256', $userId), 0, self::KEY_HASH_LENGTH);
    }

    // --- Remember-me: self-contained encrypted Cookie mode ---

    /**
     * Resolve a self-contained encrypted Cookie.
     *
     * @return string|null The user ID, or null when the Cookie must not be honoured
     */
    private function resolveEncryptedCookie(string $cookieValue): ?string
    {
        if ($this->encryptionKey === '') return null;

        try {
            $data = $this->decrypt($cookieValue, $this->encryptionKey);
        } catch (SecurityException) {
            return null;
        }

        $parts = json_decode($data, true);
        if (!is_array($parts) || !isset($parts['uid'], $parts['exp'])) return null;
        if ((int) $parts['exp'] < time()) return null;

        return (string) $parts['uid'];
    }

    /** @throws SecurityException */
    private function setRememberCookie(string $userId): void
    {
        $expiresAt = time() + $this->rememberTtl;

        if ($this->rememberStore !== null) {
            $token = Token::generate(self::REMEMBER_TOKEN_LENGTH);

            $stored = $this->saveRememberRecord($token, [
                'uid' => $userId,
                'exp' => $expiresAt,
                'epoch' => $this->rememberEpoch($userId),
                'rotated_at' => null,
            ]);

            // A Cookie without its record could never resolve again
            if (!$stored) throw new SecurityException('Failed to store the remember-me record.');

            ($this->cookieSet)($this->cookieName, $token, $expiresAt);
            return;
        }

        if ($this->encryptionKey === '') throw SecurityException::missingEncryptionKey();

        $data = json_encode(['uid' => $userId, 'exp' => $expiresAt]);
        if ($data === false) throw new SecurityException('Failed to encode remember-me data.');

        ($this->cookieSet)($this->cookieName, $this->encrypt($data, $this->encryptionKey), $expiresAt);
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

    // --- AES-256-CBC + HMAC encryption utilities ---

    /**
     * Derive the separate AES and MAC keys from the configured secret.
     *
     * Two labels keep one primitive's key out of the other: sharing a single key
     * between the cipher and the MAC couples them for no benefit.
     *
     * @return array{0: string, 1: string}
     */
    private function deriveKeys(string $secret): array
    {
        return [
            hash('sha256', 'migears-remember-enc:' . $secret, true),
            hash('sha256', 'migears-remember-mac:' . $secret, true),
        ];
    }

    /** @throws SecurityException */
    private function encrypt(string $plaintext, string $key): string
    {
        [$encKey, $macKey] = $this->deriveKeys($key);

        try {
            $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        } catch (\Throwable $e) {
            throw new SecurityException('Failed to generate IV for encryption.', 0, $e);
        }

        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $encKey, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) throw new SecurityException('Encryption failed.');

        $mac = hash_hmac('sha256', $iv . $ciphertext, $macKey, true);
        return base64_encode($iv) . '.' . base64_encode($ciphertext) . '.' . base64_encode($mac);
    }

    /** @throws SecurityException */
    private function decrypt(string $payload, string $key): string
    {
        [$encKey, $macKey] = $this->deriveKeys($key);

        $parts = explode('.', $payload);
        if (count($parts) !== 3) throw new SecurityException('Invalid encrypted payload format.');

        $iv = base64_decode($parts[0], true);
        $ciphertext = base64_decode($parts[1], true);
        $mac = base64_decode($parts[2], true);
        if ($iv === false || $ciphertext === false || $mac === false) throw new SecurityException('Invalid encrypted payload encoding.');

        if (!hash_equals(hash_hmac('sha256', $iv . $ciphertext, $macKey, true), $mac)) {
            throw new SecurityException('HMAC verification failed.');
        }

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $encKey, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) throw new SecurityException('Decryption failed.');
        return $plaintext;
    }
}
