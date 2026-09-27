<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;
use Psr\SimpleCache\CacheInterface;

/**
 * "Remember me" Cookie handling, in one of two modes.
 *
 * With a PSR-16 store the Cookie carries an opaque token, only that token's hash is
 * persisted, tokens rotate on every use and can be revoked. Without a store the Cookie
 * stays self-contained encrypted data: portable, but neither rotatable nor revocable.
 *
 * MiAuth owns the session and the user; this class owns the remember-me Cookie.
 */
final class RememberMe
{
    /** @var int Default window in which an already-consumed token is tolerated (30 seconds) */
    public const DEFAULT_GRACE = 30;
    /** @var int Remember-me token length in bytes before hex encoding */
    private const TOKEN_LENGTH = 32;
    /** @var int Length of the hashed suffix in the remember-me cache keys */
    private const KEY_HASH_LENGTH = 32;

    /**
     * @param callable(string): ?string         $cookieGet
     * @param callable(string, string, int): void $cookieSet
     * @param callable(string): void            $cookieRemove
     * @param string                            $cookieName    Remember-me Cookie name
     * @param int                               $ttl           Remember-me TTL in seconds
     * @param string                            $encryptionKey Key for the self-contained mode
     * @param CacheInterface|null               $store         PSR-16 store for the record mode
     * @param int                               $grace         Seconds an already-consumed token is tolerated
     *
     * @throws SecurityException If a callback is not callable or a numeric argument is unusable
     */
    public function __construct(
        private readonly mixed $cookieGet,
        private readonly mixed $cookieSet,
        private readonly mixed $cookieRemove,
        private readonly string $cookieName,
        private readonly int $ttl,
        private readonly string $encryptionKey = '',
        private readonly ?CacheInterface $store = null,
        private readonly int $grace = self::DEFAULT_GRACE,
    ) {
        self::assertCallable($this->cookieGet, 'cookieGet');
        self::assertCallable($this->cookieSet, 'cookieSet');
        self::assertCallable($this->cookieRemove, 'cookieRemove');

        if ($ttl < 1) {
            throw SecurityException::invalidConfiguration('rememberTtl must be at least 1 second.');
        }

        if ($grace < 0) {
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
     * Whether a Cookie can be issued or evaluated at all.
     */
    public function isEnabled(): bool
    {
        return $this->store !== null || $this->encryptionKey !== '';
    }

    /**
     * Issue a remember-me Cookie for a user.
     *
     * @throws SecurityException If the record cannot be stored, or the key is missing
     */
    public function issue(string $userId): void
    {
        $expiresAt = time() + $this->ttl;

        if ($this->store !== null) {
            $token = Token::generate(self::TOKEN_LENGTH);

            $stored = $this->saveRecord($token, [
                'uid' => $userId,
                'exp' => $expiresAt,
                'epoch' => $this->epoch($userId),
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

    /**
     * Evaluate the incoming Cookie.
     *
     * @return string|null The user ID, or null when the Cookie must not be honoured
     */
    public function consume(): ?string
    {
        if (!$this->isEnabled()) return null;

        $cookieValue = ($this->cookieGet)($this->cookieName);
        if ($cookieValue === null || $cookieValue === '') return null;

        $userId = $this->store !== null
            ? $this->consumeStored($cookieValue)
            : $this->consumeEncrypted($cookieValue);

        if ($userId === null) ($this->cookieRemove)($this->cookieName);

        return $userId;
    }

    /**
     * Revoke the record behind a remember-me Cookie token.
     *
     * @throws SecurityException If a stored record could not be dropped
     */
    public function revoke(string $token): void
    {
        if ($this->store === null || $token === '') return;

        // A copied Cookie must not survive, so a failed delete is reported rather than hidden
        if (!$this->forgetRecord($token)) {
            throw new SecurityException('Failed to revoke the stored remember-me record.');
        }
    }

    /**
     * Invalidate every remember-me token of a user, on every device.
     *
     * Bumps the user's epoch, so Cookies issued before this call stop resolving. Call it
     * on password change and on "sign out everywhere".
     *
     * @throws SecurityException If no store is configured, or the epoch could not be persisted
     */
    public function revokeForUser(string $userId): void
    {
        if ($this->store === null) {
            throw SecurityException::invalidConfiguration(
                'Revoking remember-me tokens requires a PSR-16 rememberStore.'
            );
        }

        $stored = $this->store->set($this->epochKey($userId), $this->epoch($userId) + 1);

        // A silently failed epoch write would leave every old Cookie valid
        if ($stored !== true) {
            throw new SecurityException('Failed to persist the remember-me epoch; no token was revoked.');
        }
    }

    // --- Record mode (PSR-16 store) ---

    /**
     * Resolve an opaque token, rotating it on first use.
     */
    private function consumeStored(string $token): ?string
    {
        $record = $this->readRecord($token);
        if ($record === null) return null;

        if ((int) $record['exp'] < time()) {
            $this->forgetRecord($token);
            return null;
        }

        $userId = (string) $record['uid'];

        // Bumping the user's epoch revokes every device at once
        if ((int) $record['epoch'] !== $this->epoch($userId)) {
            $this->forgetRecord($token);
            return null;
        }

        if (($record['rotated_at'] ?? null) !== null) {
            // Already exchanged. A parallel request may legitimately still carry it,
            // so it is honoured inside the grace window and rejected afterwards.
            return (time() - (int) $record['rotated_at']) <= $this->grace ? $userId : null;
        }

        $this->rotate($token, $record);

        return $userId;
    }

    /**
     * Issue a successor token and retire the presented one.
     *
     * Best effort by design: the presented token was valid, so a failed successor write
     * leaves the current Cookie usable rather than logging the user out.
     *
     * @param array<string, mixed> $record
     */
    private function rotate(string $token, array $record): void
    {
        $expiresAt = (int) $record['exp'];
        $successor = Token::generate(self::TOKEN_LENGTH);

        $stored = $this->saveRecord($successor, [
            'uid' => (string) $record['uid'],
            'exp' => $expiresAt,
            'epoch' => (int) $record['epoch'],
            'rotated_at' => null,
        ]);

        if (!$stored) return;

        if ($this->grace > 0) {
            // Keep the consumed token briefly so parallel requests survive the rotation
            $this->saveRecord($token, [
                'uid' => (string) $record['uid'],
                'exp' => $expiresAt,
                'epoch' => (int) $record['epoch'],
                'rotated_at' => time(),
            ], $this->grace);
        } else {
            $this->forgetRecord($token);
        }

        ($this->cookieSet)($this->cookieName, $successor, $expiresAt);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readRecord(string $token): ?array
    {
        $value = $this->store?->get($this->recordKey($token));

        return is_array($value) && isset($value['uid'], $value['exp'], $value['epoch']) ? $value : null;
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return bool Whether the record was stored
     */
    private function saveRecord(string $token, array $record, ?int $ttl = null): bool
    {
        $ttl ??= max(1, (int) $record['exp'] - time());

        return $this->store?->set($this->recordKey($token), $record, $ttl) === true;
    }

    /**
     * @return bool Whether the record is gone afterwards
     */
    private function forgetRecord(string $token): bool
    {
        return $this->store?->delete($this->recordKey($token)) === true;
    }

    private function epoch(string $userId): int
    {
        $epoch = $this->store?->get($this->epochKey($userId));

        return is_int($epoch) ? $epoch : 0;
    }

    /**
     * Cache key for a token record.
     *
     * Keyed by the token's hash, and kept inside the PSR-16 key character set
     * (letters, digits and underscores) at a length implementations accept.
     */
    private function recordKey(string $token): string
    {
        return '__migears_rem_' . substr(hash('sha256', $token), 0, self::KEY_HASH_LENGTH);
    }

    /**
     * Cache key for a user's epoch.
     *
     * Hashed because a user ID may contain characters PSR-16 forbids in a key.
     */
    private function epochKey(string $userId): string
    {
        return '__migears_remv_' . substr(hash('sha256', $userId), 0, self::KEY_HASH_LENGTH);
    }

    // --- Self-contained encrypted Cookie mode ---

    private function consumeEncrypted(string $cookieValue): ?string
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
