<?php

declare(strict_types=1);

namespace MiGears\Security\Exception;

/**
 * Security domain exception.
 *
 * All security-related exceptions extend this base class,
 * allowing callers to catch security errors uniformly.
 */
class SecurityException extends \RuntimeException
{
    /**
     * Create a new exception for an invalid password hash.
     */
    public static function invalidPasswordHash(): self
    {
        return new self('Invalid password hash algorithm or options.');
    }

    /**
     * Create a new exception for an invalid token.
     */
    public static function invalidToken(): self
    {
        return new self('Invalid or malformed token.');
    }

    /**
     * Create a new exception for an expired token.
     */
    public static function expiredToken(): self
    {
        return new self('Token has expired.');
    }

    /**
     * Create a new exception for CSRF validation failure.
     */
    public static function csrfValidationFailed(): self
    {
        return new self('CSRF token validation failed.');
    }

    /**
     * Create a new exception for missing encryption key.
     */
    public static function missingEncryptionKey(): self
    {
        return new self('Encryption key is required for remember-me cookies.');
    }

    /**
     * Create a new exception for authentication failure.
     */
    public static function authenticationFailed(string $reason = ''): self
    {
        $message = 'Authentication failed.';
        if ($reason !== '') {
            $message .= ' ' . $reason;
        }

        return new self(trim($message));
    }
}
