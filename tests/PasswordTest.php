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

    public function testVeryLongPasswordIsRejectedInsteadOfTruncated(): void
    {
        // bcrypt ignores everything past 72 bytes, so accepting a longer password
        // would let two different passwords verify against each other
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('72-byte');

        Password::hash(str_repeat('a', 1000));
    }

    public function testHashAcceptsExactlyTheBcryptLimit(): void
    {
        $password = str_repeat('a', 72);

        self::assertTrue(Password::verify($password, Password::hash($password)));
    }

    public function testHashRejectsAPasswordOneByteOverTheLimit(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('72-byte');

        Password::hash(str_repeat('a', 73));
    }

    public function testHashRejectsAMultibytePasswordOverTheByteLimit(): void
    {
        // 25 three-byte characters = 75 bytes
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('72-byte');

        Password::hash(str_repeat('密', 25));
    }

    public function testHashAllowsLongPasswordsWithArgon2(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) self::markTestSkipped('argon2id is not available in this PHP build.');

        $password = str_repeat('a', 100);

        self::assertTrue(Password::verify($password, Password::hash($password, ['algo' => PASSWORD_ARGON2ID])));
    }

    public function testHashHonorsAlgoOverride(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) self::markTestSkipped('argon2id is not available in this PHP build.');

        $hash = Password::hash('test', ['algo' => PASSWORD_ARGON2ID]);

        self::assertSame('argon2id', Password::info($hash)['algoName']);
        self::assertTrue(Password::verify('test', $hash));
    }

    public function testBcryptCostDefaultIsNotAppliedToOtherAlgos(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) self::markTestSkipped('argon2id is not available in this PHP build.');

        $info = Password::info(Password::hash('test', ['algo' => PASSWORD_ARGON2ID]));

        self::assertArrayNotHasKey('cost', $info['options']);
    }

    public function testHashRejectsUnknownAlgo(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Invalid password hash');

        Password::hash('test', ['algo' => 'not-an-algorithm']);
    }

    public function testHashRejectsNonScalarAlgo(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Invalid password hash');

        Password::hash('test', ['algo' => ['bcrypt']]);
    }

    public function testNeedsRehashHonorsAlgoOverride(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) self::markTestSkipped('argon2id is not available in this PHP build.');

        $hash = Password::hash('test', ['algo' => PASSWORD_ARGON2ID]);

        self::assertFalse(Password::needsRehash($hash, ['algo' => PASSWORD_ARGON2ID]));
        // Default is still bcrypt, so an argon2id hash does need rehashing
        self::assertTrue(Password::needsRehash($hash));
    }

    public function testNeedsRehashRejectsUnknownAlgo(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Invalid password hash');

        Password::needsRehash(Password::hash('test'), ['algo' => 'not-an-algorithm']);
    }
}
