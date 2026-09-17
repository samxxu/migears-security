<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\Exception\SecurityException;

final class SecurityExceptionTest extends TestCase
{
    public function testInvalidPasswordHash(): void
    {
        $e = SecurityException::invalidPasswordHash();

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertInstanceOf(\RuntimeException::class, $e);
        self::assertStringContainsString('Invalid password hash', $e->getMessage());
    }

    public function testInvalidToken(): void
    {
        $e = SecurityException::invalidToken();

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertStringContainsString('Invalid or malformed token', $e->getMessage());
    }

    public function testExpiredToken(): void
    {
        $e = SecurityException::expiredToken();

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertStringContainsString('expired', $e->getMessage());
    }

    public function testCsrfValidationFailed(): void
    {
        $e = SecurityException::csrfValidationFailed();

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertStringContainsString('CSRF', $e->getMessage());
    }

    public function testMissingEncryptionKey(): void
    {
        $e = SecurityException::missingEncryptionKey();

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertStringContainsString('Encryption key', $e->getMessage());
    }

    public function testAuthenticationFailedWithoutReason(): void
    {
        $e = SecurityException::authenticationFailed();

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertStringContainsString('Authentication failed', $e->getMessage());
        self::assertStringEndsWith('.', $e->getMessage());
    }

    public function testAuthenticationFailedWithReason(): void
    {
        $e = SecurityException::authenticationFailed('Wrong password.');

        self::assertInstanceOf(SecurityException::class, $e);
        self::assertStringContainsString('Authentication failed', $e->getMessage());
        self::assertStringContainsString('Wrong password', $e->getMessage());
    }

    public function testAllStaticFactoriesReturnSecurityException(): void
    {
        $factories = [
            'invalidPasswordHash' => [],
            'invalidToken' => [],
            'expiredToken' => [],
            'csrfValidationFailed' => [],
            'missingEncryptionKey' => [],
            'authenticationFailed' => ['test'],
        ];

        foreach ($factories as $method => $args) {
            $e = SecurityException::$method(...$args);
            self::assertInstanceOf(SecurityException::class, $e, "Failed asserting $method returns SecurityException");
        }
    }
}
