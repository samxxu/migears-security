<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\Token;
use MiGears\Security\Exception\SecurityException;

final class TokenTest extends TestCase
{
    public function testGenerateReturnsHexString(): void
    {
        $token = Token::generate();

        self::assertIsString($token);
        self::assertTrue(ctype_xdigit($token));
    }

    public function testGenerateDefaultLength(): void
    {
        $token = Token::generate();

        // 32 bytes = 64 hex chars
        self::assertSame(64, strlen($token));
    }

    public function testGenerateCustomLength(): void
    {
        $token = Token::generate(16);

        // 16 bytes = 32 hex chars
        self::assertSame(32, strlen($token));
    }

    public function testGenerateMinimumLengthEnforced(): void
    {
        // Length < 16 should be bumped to default (32 bytes = 64 hex chars)
        $token = Token::generate(8);

        self::assertSame(64, strlen($token));
    }

    public function testGenerateIsUnique(): void
    {
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            $tokens[] = Token::generate();
        }

        self::assertCount(100, array_unique($tokens));
    }

    public function testGenerateWithTtlFormat(): void
    {
        $token = Token::generateWithTtl(3600);
        $parts = explode('.', $token);

        self::assertCount(2, $parts);
        self::assertTrue(ctype_xdigit($parts[0]));
        self::assertTrue(ctype_digit($parts[1]));
    }

    public function testGenerateWithTtlExpirationInFuture(): void
    {
        $token = Token::generateWithTtl(3600);
        $parts = explode('.', $token);
        $expiresAt = (int) $parts[1];

        self::assertGreaterThan(time(), $expiresAt);
        self::assertLessThanOrEqual(time() + 3600, $expiresAt);
    }

    public function testParseValidToken(): void
    {
        $timestamped = Token::generateWithTtl(3600);
        $rawToken = Token::parse($timestamped);
        $parts = explode('.', $timestamped);

        self::assertSame($parts[0], $rawToken);
    }

    public function testParseMalformedTokenThrows(): void
    {
        $this->expectException(SecurityException::class);

        Token::parse('not-a-valid-token');
    }

    public function testParseExpiredTokenThrows(): void
    {
        $rawToken = bin2hex(random_bytes(16));
        $expired = $rawToken . '.' . (time() - 100);

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('expired');

        Token::parse($expired);
    }

    public function testParseNonHexTokenThrows(): void
    {
        $this->expectException(SecurityException::class);

        Token::parse('nothex!' . '.' . (time() + 3600));
    }

    public function testEqualsSameString(): void
    {
        self::assertTrue(Token::equals('abc123', 'abc123'));
    }

    public function testEqualsDifferentStrings(): void
    {
        self::assertFalse(Token::equals('abc123', 'abc124'));
    }

    public function testEqualsDifferentLengths(): void
    {
        self::assertFalse(Token::equals('abc', 'abcd'));
    }

    public function testEqualsEmptyStrings(): void
    {
        self::assertTrue(Token::equals('', ''));
    }
}
