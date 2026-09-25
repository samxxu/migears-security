<?php

declare(strict_types=1);

namespace MiGears\Security;

use MiGears\Security\Exception\SecurityException;

/**
 * CSRF (Cross-Site Request Forgery) protection.
 *
 * Generates and validates CSRF tokens. Token storage is
 * abstracted via a simple array-access / closure pattern
 * so the caller controls persistence (session, cache, etc.).
 *
 * Usage:
 *   $csrf = new Csrf(session_storage: [$session, 'get'], ...);
 *   $token = $csrf->generate();
 *   $csrf->validate($userSubmittedToken);
 */
final class Csrf
{
    /**
     * Default CSRF token key used in storage.
     *
     * @var string
     */
    private const DEFAULT_KEY = '_csrf_token';

    /**
     * @param string $tokenKey   Key used to store the token in the session/storage
     * @param int    $tokenLength Token length in bytes (before hex encoding)
     */
    public function __construct(
        private readonly string $tokenKey = self::DEFAULT_KEY,
        private readonly int $tokenLength = 32,
    ) {
    }

    /**
     * Generate a new CSRF token and store it via the provided setter.
     *
     * @param callable $setter function(string $key, string $token): void
     *
     * @return string The generated token
     */
    public function generate(callable $setter): string
    {
        $token = Token::generate($this->tokenLength);
        $setter($this->tokenKey, $token);

        return $token;
    }

    /**
     * Validate a user-supplied CSRF token against the stored one.
     *
     * @param string   $userToken The token submitted by the user
     * @param callable $getter    function(string $key): ?string
     *
     * @throws SecurityException If validation fails
     */
    public function validate(string $userToken, callable $getter): void
    {
        $storedToken = $getter($this->tokenKey);

        if (!is_string($storedToken) || $storedToken === '') {
            throw SecurityException::csrfValidationFailed();
        }

        if (!Token::equals($storedToken, $userToken)) {
            throw SecurityException::csrfValidationFailed();
        }
    }

    /**
     * Generate a CSRF token and return the HTML hidden input field.
     *
     * @param callable $setter function(string $key, string $token): void
     */
    public function htmlField(callable $setter): string
    {
        $token = $this->generate($setter);

        return sprintf(
            '<input type="hidden" name="%s" value="%s">',
            htmlspecialchars($this->tokenKey, ENT_QUOTES, 'UTF-8'),
            htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
        );
    }

    /**
     * Get the token storage key.
     */
    public function getTokenKey(): string
    {
        return $this->tokenKey;
    }
}
