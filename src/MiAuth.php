<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;

/**
 * MiAuth — Classic Session authentication + "remember me" Cookie implementation.
 *
 * Session/Cookie I/O is fully abstracted via callables, with no dependency on superglobals.
 *
 * @template TUser of object
 * @implements AuthInterface<TUser>
 */
class MiAuth implements AuthInterface
{
    public const VERSION = '2.0.0';

    private const string DEFAULT_SESSION_KEY = '__migears_user_id';
    private const string DEFAULT_COOKIE_NAME = '__migears_remember';
    private const int DEFAULT_REMEMBER_TTL = 2592000; // 30 days

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
     * @param string                            $encryptionKey  Remember-me encryption key
     * @param string                            $sessionKey     User ID key name in Session
     * @param string                            $cookieName     Remember-me Cookie name
     * @param int                               $rememberTtl    Remember-me TTL in seconds
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
    ) {
    }

    /**
     * Creates a classic implementation using PHP's native $_SESSION + setcookie.
     *
     * @param callable(string): ?TUser $userLoader
     * @param array{sessionKey?: string, cookieName?: string, rememberTtl?: int} $options
     * @return self<TUser>
     */
    public static function classic(callable $userLoader, string $encryptionKey = '', array $options = []): self
    {
        $ensureSession = static function (): void {
            if (session_status() !== PHP_SESSION_ACTIVE) session_start();
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
            cookieSet: static function (string $name, string $value, int $expire): void {
                setcookie($name, $value, ['expires' => $expire, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
            },
            cookieRemove: static function (string $name): void {
                setcookie($name, '', ['expires' => time() - 3600, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
            },
            userLoader: $userLoader,
            encryptionKey: $encryptionKey,
            sessionKey: $options['sessionKey'] ?? self::DEFAULT_SESSION_KEY,
            cookieName: $options['cookieName'] ?? self::DEFAULT_COOKIE_NAME,
            rememberTtl: $options['rememberTtl'] ?? self::DEFAULT_REMEMBER_TTL,
        );
    }

    /** @param TUser $user */
    public function login(object $user, bool $remember = false): void
    {
        $userId = $this->extractUserId($user);
        ($this->sessionSet)($this->sessionKey, $userId);
        $this->currentUser = $user;
        $this->resolved = true;
        if ($remember) $this->setRememberCookie($userId);
    }

    public function logout(): void
    {
        ($this->sessionRemove)($this->sessionKey);
        ($this->cookieRemove)($this->cookieName);
        $this->currentUser = null;
        $this->resolved = true;
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
        if ($this->encryptionKey === '') return false;

        $cookieValue = ($this->cookieGet)($this->cookieName);
        if ($cookieValue === null || $cookieValue === '') return false;

        try {
            $data = $this->decrypt($cookieValue, $this->encryptionKey);
        } catch (SecurityException) {
            ($this->cookieRemove)($this->cookieName);
            return false;
        }

        $parts = json_decode($data, true);
        if (!is_array($parts) || !isset($parts['uid'], $parts['exp'])) {
            ($this->cookieRemove)($this->cookieName);
            return false;
        }

        if ((int) $parts['exp'] < time()) {
            ($this->cookieRemove)($this->cookieName);
            return false;
        }

        $userId = (string) $parts['uid'];
        $user = ($this->userLoader)($userId);
        if ($user === null) {
            ($this->cookieRemove)($this->cookieName);
            return false;
        }

        ($this->sessionSet)($this->sessionKey, $userId);
        $this->currentUser = $user;
        return true;
    }

    /** @throws SecurityException */
    private function setRememberCookie(string $userId): void
    {
        if ($this->encryptionKey === '') throw SecurityException::missingEncryptionKey();

        $data = json_encode(['uid' => $userId, 'exp' => time() + $this->rememberTtl]);
        if ($data === false) throw new SecurityException('Failed to encode remember-me data.');

        ($this->cookieSet)($this->cookieName, $this->encrypt($data, $this->encryptionKey), time() + $this->rememberTtl);
    }

    /** @throws SecurityException */
    private function extractUserId(object $user): string
    {
        if (method_exists($user, 'getId')) return (string) $user->getId();
        if (isset($user->id)) return (string) $user->id;
        if ($user instanceof \ArrayAccess && isset($user['id'])) return (string) $user['id'];
        throw new SecurityException('Cannot extract user ID: object must have getId(), ->id, or [\'id\'].');
    }

    // --- AES-256-CBC + HMAC encryption utilities ---

    /** @throws SecurityException */
    private function encrypt(string $plaintext, string $key): string
    {
        $key = hash('sha256', $key, true);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        if ($iv === false) throw new SecurityException('Failed to generate IV for encryption.');

        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) throw new SecurityException('Encryption failed.');

        $mac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
        return base64_encode($iv) . '.' . base64_encode($ciphertext) . '.' . base64_encode($mac);
    }

    /** @throws SecurityException */
    private function decrypt(string $payload, string $key): string
    {
        $key = hash('sha256', $key, true);
        $parts = explode('.', $payload);
        if (count($parts) !== 3) throw new SecurityException('Invalid encrypted payload format.');

        $iv = base64_decode($parts[0], true);
        $ciphertext = base64_decode($parts[1], true);
        $mac = base64_decode($parts[2], true);
        if ($iv === false || $ciphertext === false || $mac === false) throw new SecurityException('Invalid encrypted payload encoding.');

        if (!hash_equals(hash_hmac('sha256', $iv . $ciphertext, $key, true), $mac)) {
            throw new SecurityException('HMAC verification failed.');
        }

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) throw new SecurityException('Decryption failed.');
        return $plaintext;
    }
}
