<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\Csrf;
use MiGears\Security\Exception\SecurityException;

final class CsrfTest extends TestCase
{
    public function testGenerateReturnsHexToken(): void
    {
        $csrf = new Csrf();
        $storage = [];

        $setter = function (string $key, string $token) use (&$storage): void {
            $storage[$key] = $token;
        };

        $token = $csrf->generate($setter);

        self::assertIsString($token);
        self::assertTrue(ctype_xdigit($token));
        self::assertArrayHasKey('_csrf_token', $storage);
        self::assertSame($token, $storage['_csrf_token']);
    }

    public function testGenerateWithCustomKey(): void
    {
        $csrf = new Csrf(tokenKey: 'my_csrf');
        $storage = [];

        $setter = function (string $key, string $token) use (&$storage): void {
            $storage[$key] = $token;
        };

        $csrf->generate($setter);

        self::assertArrayHasKey('my_csrf', $storage);
        self::assertArrayNotHasKey('_csrf_token', $storage);
    }

    public function testValidateValidToken(): void
    {
        $csrf = new Csrf();
        $storage = [];

        $setter = function (string $key, string $token) use (&$storage): void {
            $storage[$key] = $token;
        };

        $getter = function (string $key) use (&$storage): ?string {
            return $storage[$key] ?? null;
        };

        $token = $csrf->generate($setter);

        // Should not throw
        $csrf->validate($token, $getter);
        self::assertTrue(true);
    }

    public function testValidateInvalidTokenThrows(): void
    {
        $csrf = new Csrf();
        $storage = [];

        $setter = function (string $key, string $token) use (&$storage): void {
            $storage[$key] = $token;
        };

        $getter = function (string $key) use (&$storage): ?string {
            return $storage[$key] ?? null;
        };

        $csrf->generate($setter);

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('CSRF');

        $csrf->validate('wrong-token', $getter);
    }

    public function testValidateEmptyStorageThrows(): void
    {
        $csrf = new Csrf();

        $getter = function (string $key): ?string {
            return null;
        };

        $this->expectException(SecurityException::class);

        $csrf->validate('sometoken', $getter);
    }

    public function testHtmlFieldReturnsHiddenInput(): void
    {
        $csrf = new Csrf();
        $storage = [];

        $setter = function (string $key, string $token) use (&$storage): void {
            $storage[$key] = $token;
        };

        $html = $csrf->htmlField($setter);

        self::assertStringContainsString('<input', $html);
        self::assertStringContainsString('type="hidden"', $html);
        self::assertStringContainsString('name="_csrf_token"', $html);
        self::assertStringContainsString('value="', $html);
    }

    public function testHtmlFieldWithCustomKey(): void
    {
        $csrf = new Csrf(tokenKey: 'custom_key');
        $storage = [];

        $setter = function (string $key, string $token) use (&$storage): void {
            $storage[$key] = $token;
        };

        $html = $csrf->htmlField($setter);

        self::assertStringContainsString('name="custom_key"', $html);
    }

    public function testGetTokenKey(): void
    {
        $csrf = new Csrf(tokenKey: 'my_key');

        self::assertSame('my_key', $csrf->getTokenKey());
    }

    public function testGenerateProducesUniqueTokens(): void
    {
        $csrf = new Csrf();
        $storage1 = [];
        $storage2 = [];

        $token1 = $csrf->generate(function (string $key, string $token) use (&$storage1): void {
            $storage1[$key] = $token;
        });

        $token2 = $csrf->generate(function (string $key, string $token) use (&$storage2): void {
            $storage2[$key] = $token;
        });

        self::assertNotSame($token1, $token2);
    }
}
