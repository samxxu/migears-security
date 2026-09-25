<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;

/**
 * Cryptographically secure token generation and verification.
 *
 * Tokens are generated using random_bytes (CSPRNG) and encoded
 * as hexadecimal strings. Supports optional expiration via
 * timestamped tokens.
 */
final class Token
{
    /**
     * Default token length in bytes (before hex encoding).
     *
     * @var int
     */
    private const DEFAULT_LENGTH = 32;

    /**
     * Separator used in timestamped tokens: "token:timestamp".
     *
     * @var string
     */
    private const SEPARATOR = '.';

    /**
     * Generate a cryptographically secure random token.
     *
     * @param int $length Token length in bytes (before hex encoding)
     *
     * @throws SecurityException If token generation fails
     */
    public static function generate(int $length = self::DEFAULT_LENGTH): string
    {
        if ($length < 16) {
            $length = self::DEFAULT_LENGTH;
        }

        try {
            return bin2hex(random_bytes($length));
        } catch (\Exception $e) {
            throw new SecurityException('Token generation failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Generate a timestamped token that can be verified with a TTL.
     *
     * Format: hexToken.expiresAt
     *
     * @param int $ttlSeconds Time-to-live in seconds
     * @param int $length     Token length in bytes
     *
     * @return string The timestamped token
     */
    public static function generateWithTtl(int $ttlSeconds, int $length = self::DEFAULT_LENGTH): string
    {
        $token = self::generate($length);
        $expiresAt = time() + $ttlSeconds;

        return $token . self::SEPARATOR . $expiresAt;
    }

    /**
     * Verify a timestamped token's format and expiration.
     *
     * Note: This only validates the token format and TTL.
     * It does NOT compare against a stored token value —
     * that is the caller's responsibility.
     *
     * @param string $timestampedToken The timestamped token string
     *
     * @throws SecurityException If token is malformed or expired
     *
     * @return string The raw token part (without timestamp)
     */
    public static function parse(string $timestampedToken): string
    {
        $parts = explode(self::SEPARATOR, $timestampedToken);

        if (count($parts) !== 2) {
            throw SecurityException::invalidToken();
        }

        [$token, $expiresAt] = $parts;

        if (!ctype_xdigit($token) || !ctype_digit($expiresAt)) {
            throw SecurityException::invalidToken();
        }

        if ((int) $expiresAt < time()) {
            throw SecurityException::expiredToken();
        }

        return $token;
    }

    /**
     * Timing-safe string comparison.
     *
     * Use this when comparing user-supplied tokens against
     * stored values to prevent timing attacks.
     */
    public static function equals(string $known, string $user): bool
    {
        return hash_equals($known, $user);
    }
}
