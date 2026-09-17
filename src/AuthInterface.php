<?php

declare(strict_types=1);

namespace MiGears\Security;

/**
 * Authentication interface.
 *
 * Defines the contract for authentication implementations.
 * Users can implement this interface to integrate with any
 * authentication backend (database, LDAP, OAuth, etc.).
 *
 * @template TUser of object
 */
interface AuthInterface
{
    /**
     * Log a user in.
     *
     * @param TUser   $user     The user object to authenticate
     * @param bool    $remember Whether to enable "remember me"
     */
    public function login(object $user, bool $remember = false): void;

    /**
     * Log the current user out.
     */
    public function logout(): void;

    /**
     * Check if a user is currently logged in.
     */
    public function isLoggedIn(): bool;

    /**
     * Get the currently authenticated user.
     *
     * @return TUser|null The user object, or null if not authenticated
     */
    public function getCurrentUser(): ?object;
}
