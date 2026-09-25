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
     * Hash a plain-text password.
     *
     * @param string $password Plain-text password
     * @param array  $options  Hashing options (e.g. ['cost' => 12])
     *
     * @throws SecurityException If hashing fails
     */
    public static function hash(string $password, array $options = []): string
    {
        $options = array_merge(['cost' => self::COST], $options);

        $hash = password_hash($password, self::ALGORITHM, $options);

        if ($hash === false) {
            throw SecurityException::invalidPasswordHash();
        }

        return $hash;
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
     * @param array  $options Hashing options to compare against
     */
    public static function needsRehash(string $hash, array $options = []): bool
    {
        $options = array_merge(['cost' => self::COST], $options);

        return password_needs_rehash($hash, self::ALGORITHM, $options);
    }

    /**
     * Get information about a password hash.
     *
     * @return array{algo: int, algoName: string, options: array}
     */
    public static function info(string $hash): array
    {
        return password_get_info($hash);
    }
}
