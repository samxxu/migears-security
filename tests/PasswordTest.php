<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\Password;
use MiGears\Security\Exception\SecurityException;

final class PasswordTest extends TestCase
{
    public function testHashProducesValidBcryptHash(): void
    {
        $hash = Password::hash('mysecretpassword');

        self::assertStringStartsWith('$2y$', $hash);
        self::assertGreaterThan(50, strlen($hash));
    }

    public function testHashWithCustomCost(): void
    {
        $hash = Password::hash('test', ['cost' => 10]);
        $info = Password::info($hash);

        self::assertSame('bcrypt', $info['algoName']);
        self::assertSame(10, $info['options']['cost']);
    }

    public function testVerifyCorrectPassword(): void
    {
        $hash = Password::hash('correcthorsebatterystaple');

        self::assertTrue(Password::verify('correcthorsebatterystaple', $hash));
    }

    public function testVerifyWrongPassword(): void
    {
        $hash = Password::hash('correcthorsebatterystaple');

        self::assertFalse(Password::verify('wrongpassword', $hash));
    }

    public function testVerifyEmptyPassword(): void
    {
        $hash = Password::hash('notempty');

        self::assertFalse(Password::verify('', $hash));
    }

    public function testNeedsRehashWithDifferentCost(): void
    {
        $hash = Password::hash('test', ['cost' => 10]);

        self::assertTrue(Password::needsRehash($hash, ['cost' => 12]));
        self::assertFalse(Password::needsRehash($hash, ['cost' => 10]));
    }

    public function testNeedsRehashDefaultCost(): void
    {
        $hash = Password::hash('test');

        self::assertFalse(Password::needsRehash($hash));
    }

    public function testInfoReturnsArray(): void
    {
        $hash = Password::hash('test');
        $info = Password::info($hash);

        self::assertIsArray($info);
        self::assertArrayHasKey('algo', $info);
        self::assertArrayHasKey('algoName', $info);
        self::assertArrayHasKey('options', $info);
    }

    public function testHashIsUniqueEachTime(): void
    {
        $password = 'samepassword';
        $hash1 = Password::hash($password);
        $hash2 = Password::hash($password);

        self::assertNotSame($hash1, $hash2);
        self::assertTrue(Password::verify($password, $hash1));
        self::assertTrue(Password::verify($password, $hash2));
    }

    public function testVeryLongPassword(): void
    {
        $longPassword = str_repeat('a', 1000);
        $hash = Password::hash($longPassword);

        self::assertTrue(Password::verify($longPassword, $hash));
    }
}
