<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;

/**
 * Password hashing and verification utility.
 *
 * Wraps PHP's built-in password_hash / password_verify functions
 * with sensible defaults and a clean API.
 */
final class Password
{
    /**
     * Default hashing algorithm.
     *
     * @var string
     */
    private const ALGORITHM = PASSWORD_BCRYPT;

    /**
     * Default bcrypt cost factor.
     *
     * @var int
     */
    private const COST = 12;

    /**
     * Longest password bcrypt takes into account.
     *
     * bcrypt hashes at most 72 bytes and ignores the rest, so two different
     * long passwords sharing a 72-byte prefix would verify against each other.
     * Longer input is rejected instead of silently truncated.
     *
     * @var int
     */
    private const BCRYPT_MAX_BYTES = 72;

    /**
     * Hash a plain-text password.
     *
     * @param string $password Plain-text password
     * @param array<string, mixed> $options Hashing options (e.g. ['cost' => 12]).
     *                                      Pass ['algo' => PASSWORD_ARGON2ID] to override the default algorithm.
     *
     * @throws SecurityException If the algorithm or options are rejected, or the
     *                          password exceeds the bcrypt limit
     */
    public static function hash(string $password, array $options = []): string
    {
        [$algo, $options] = self::splitAlgo($options);

        if ($algo === PASSWORD_BCRYPT && strlen($password) > self::BCRYPT_MAX_BYTES) {
            throw SecurityException::passwordTooLong(self::BCRYPT_MAX_BYTES);
        }

        try {
            return password_hash($password, $algo, $options);
        } catch (\Throwable $e) {
            throw SecurityException::invalidPasswordHash();
        }
    }

    /**
     * Verify a plain-text password against a hash.
     *
     * @param string $password Plain-text password
     * @param string $hash     Stored password hash
     */
    public static function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Determine if the password hash needs to be rehashed.
     *
     * Returns true when the hash was created with a different
     * algorithm or cost factor than the current defaults.
     *
     * @param string $hash    Stored password hash
     * @param array<string, mixed> $options Hashing options to compare against
     *                                      (same shape as hash(), including the optional 'algo' key)
     *
     * @throws SecurityException If the algorithm or options are rejected
     */
    public static function needsRehash(string $hash, array $options = []): bool
    {
        [$algo, $options] = self::splitAlgo($options);

        try {
            return password_needs_rehash($hash, $algo, $options);
        } catch (\Throwable $e) {
            throw SecurityException::invalidPasswordHash();
        }
    }

    /**
     * Get information about a password hash.
     *
     * @return array{algo: string|null, algoName: string, options: array<string, mixed>}
     */
    public static function info(string $hash): array
    {
        return password_get_info($hash);
    }

    /**
     * Pull the optional 'algo' override out of the options array, applying the
     * bcrypt cost default only when bcrypt is actually used.
     *
     * The algorithm is validated here instead of being delegated: password_hash()
     * rejects an unknown algorithm, but password_needs_rehash() silently returns
     * false for it.
     *
     * @param array<string, mixed> $options
     *
     * @return array{0: string|int, 1: array<string, mixed>}
     *
     * @throws SecurityException If the algorithm is not supported
     */
    private static function splitAlgo(array $options): array
    {
        $algo = $options['algo'] ?? self::ALGORITHM;
        unset($options['algo']);

        if (!in_array($algo, self::supportedAlgos(), true)) throw SecurityException::invalidPasswordHash();

        if ($algo === self::ALGORITHM) $options = array_merge(['cost' => self::COST], $options);

        return [$algo, $options];
    }

    /**
     * Algorithms this wrapper accepts. argon2 is listed only when the running
     * PHP build actually provides it.
     *
     * @return array<int, string|int>
     */
    private static function supportedAlgos(): array
    {
        $algos = [PASSWORD_BCRYPT, PASSWORD_DEFAULT];

        if (defined('PASSWORD_ARGON2I')) $algos[] = PASSWORD_ARGON2I;
        if (defined('PASSWORD_ARGON2ID')) $algos[] = PASSWORD_ARGON2ID;

        return array_values(array_unique($algos));
    }
}
