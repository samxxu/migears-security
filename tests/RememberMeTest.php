<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\RememberMe;
use MiGears\Security\Exception\SecurityException;

final class RememberMeTest extends TestCase
{
    /** @var array<string, string> */
    private array $cookies = [];

    private function create(string $encryptionKey = '', ?TestCache $store = null, int $ttl = 2592000, int $grace = 30): RememberMe
    {
        $cookies = &$this->cookies;

        return new RememberMe(
            cookieGet: static function (string $name) use (&$cookies): ?string {
                return $cookies[$name] ?? null;
            },
            cookieSet: static function (string $name, string $value, int $expire) use (&$cookies): void {
                $cookies[$name] = $value;
            },
            cookieRemove: static function (string $name) use (&$cookies): void {
                unset($cookies[$name]);
            },
            cookieName: 'remember',
            ttl: $ttl,
            encryptionKey: $encryptionKey,
            store: $store,
            grace: $grace,
        );
    }

    public function testDisabledWithoutStoreAndKey(): void
    {
        $remember = $this->create();

        self::assertFalse($remember->isEnabled());
    }

    public function testEnabledByAnEncryptionKeyAlone(): void
    {
        self::assertTrue($this->create(encryptionKey: 'secret')->isEnabled());
    }

    public function testEnabledByAStoreAlone(): void
    {
        self::assertTrue($this->create(store: new TestCache())->isEnabled());
    }

    public function testConsumeReturnsNullWhenDisabled(): void
    {
        $this->cookies['remember'] = 'anything';

        // Nothing can evaluate the Cookie, and it must be left alone rather than deleted
        self::assertNull($this->create()->consume());
        self::assertArrayHasKey('remember', $this->cookies);
    }

    public function testIssueRequiresAKeyInTheEncryptedMode(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Encryption key');

        $this->create()->issue('1');
    }

    public function testEncryptedModeRoundTrip(): void
    {
        $remember = $this->create(encryptionKey: 'secret');
        $remember->issue('42');

        self::assertArrayHasKey('remember', $this->cookies);
        self::assertSame('42', $remember->consume());
    }

    public function testRevokeIsANoOpForTheEncryptedMode(): void
    {
        $this->expectNotToPerformAssertions();

        $this->create(encryptionKey: 'secret')->revoke('some-token');
    }

    public function testRevokeForUserWithoutAStoreThrows(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('rememberStore');

        $this->create(encryptionKey: 'secret')->revokeForUser('1');
    }

    public function testConstructorRejectsANonCallableCookieCallable(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('cookieGet');

        new RememberMe(
            cookieGet: 'not-callable',
            cookieSet: static function (): void {
            },
            cookieRemove: static function (): void {
            },
            cookieName: 'remember',
            ttl: 100,
        );
    }

    public function testConstructorRejectsNonPositiveTtl(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('rememberTtl');

        $this->create(ttl: 0);
    }

    public function testConstructorRejectsNegativeGrace(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('rememberGrace');

        $this->create(grace: -1);
    }
}
