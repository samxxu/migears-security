<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use PHPUnit\Framework\TestCase;
use MiGears\Security\MiAuth;
use MiGears\Security\Exception\SecurityException;

/**
 * A simple user stub for testing.
 */
final class TestUser
{
    public function __construct(
        public readonly string $id,
        public readonly string $name = '',
    ) {
    }

    public function getId(): string
    {
        return $this->id;
    }
}

/**
 * User stub without getId() method — uses public $id property.
 */
final class TestUserWithProperty
{
    public function __construct(
        public string $id,
    ) {
    }
}

final class MiAuthTest extends TestCase
{
    private array $session = [];
    private array $cookies = [];

    /**
     * @var callable(string): ?string
     */
    private $sessionGet;

    /**
     * @var callable(string, string): void
     */
    private $sessionSet;

    /**
     * @var callable(string): void
     */
    private $sessionRemove;

    /**
     * @var callable(string): ?string
     */
    private $cookieGet;

    /**
     * @var callable(string, string, int): void
     */
    private $cookieSet;

    /**
     * @var callable(string): void
     */
    private $cookieRemove;

    /**
     * @var callable(string): ?TestUser
     */
    private $userLoader;

    /** @var array<int, TestUser> */
    private array $users = [];

    protected function setUp(): void
    {
        $this->session = [];
        $this->cookies = [];
        $this->users = [
            '1' => new TestUser('1', 'Alice'),
            '2' => new TestUser('2', 'Bob'),
        ];

        $sessionRef = &$this->session;
        $cookiesRef = &$this->cookies;
        $usersRef = &$this->users;

        $this->sessionGet = static function (string $key) use (&$sessionRef): ?string {
            return isset($sessionRef[$key]) ? (string) $sessionRef[$key] : null;
        };

        $this->sessionSet = static function (string $key, string $value) use (&$sessionRef): void {
            $sessionRef[$key] = $value;
        };

        $this->sessionRemove = static function (string $key) use (&$sessionRef): void {
            unset($sessionRef[$key]);
        };

        $this->cookieGet = static function (string $name) use (&$cookiesRef): ?string {
            return isset($cookiesRef[$name]) ? (string) $cookiesRef[$name] : null;
        };

        $this->cookieSet = static function (string $name, string $value, int $expire) use (&$cookiesRef): void {
            $cookiesRef[$name] = $value;
        };

        $this->cookieRemove = static function (string $name) use (&$cookiesRef): void {
            unset($cookiesRef[$name]);
        };

        $this->userLoader = static function (string $id) use (&$usersRef): ?TestUser {
            return $usersRef[$id] ?? null;
        };
    }

    private function createAuth(string $encryptionKey = 'test-secret-key'): MiAuth
    {
        return new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            encryptionKey: $encryptionKey,
        );
    }

    public function testLoginStoresUserIdInSession(): void
    {
        $auth = $this->createAuth();
        $user = $this->users['1'];

        $auth->login($user);

        self::assertArrayHasKey('__tinyauth_user_id', $this->session);
        self::assertSame('1', $this->session['__tinyauth_user_id']);
    }

    public function testIsLoggedInAfterLogin(): void
    {
        $auth = $this->createAuth();

        self::assertFalse($auth->isLoggedIn());

        $auth->login($this->users['1']);

        self::assertTrue($auth->isLoggedIn());
    }

    public function testGetCurrentUserAfterLogin(): void
    {
        $auth = $this->createAuth();
        $user = $this->users['1'];

        $auth->login($user);

        $currentUser = $auth->getCurrentUser();
        self::assertNotNull($currentUser);
        self::assertSame('1', $currentUser->getId());
        self::assertSame('Alice', $currentUser->name);
    }

    public function testLogoutClearsSession(): void
    {
        $auth = $this->createAuth();
        $auth->login($this->users['1']);

        self::assertTrue($auth->isLoggedIn());

        $auth->logout();

        self::assertFalse($auth->isLoggedIn());
        self::assertArrayNotHasKey('__tinyauth_user_id', $this->session);
    }

    public function testLogoutClearsRememberCookie(): void
    {
        $auth = $this->createAuth();
        $auth->login($this->users['1'], remember: true);

        self::assertArrayHasKey('__tinyauth_remember', $this->cookies);

        $auth->logout();

        self::assertArrayNotHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testGetCurrentUserReturnsNullBeforeLogin(): void
    {
        $auth = $this->createAuth();

        self::assertNull($auth->getCurrentUser());
        self::assertFalse($auth->isLoggedIn());
    }

    public function testLoginWithRememberSetsCookie(): void
    {
        $auth = $this->createAuth();

        $auth->login($this->users['1'], remember: true);

        self::assertArrayHasKey('__tinyauth_remember', $this->cookies);
        self::assertNotEmpty($this->cookies['__tinyauth_remember']);
    }

    public function testLoginWithoutRememberDoesNotSetCookie(): void
    {
        $auth = $this->createAuth();

        $auth->login($this->users['1'], remember: false);

        self::assertArrayNotHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testLoginRememberWithoutKeyThrows(): void
    {
        $auth = $this->createAuth('');

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Encryption key');

        $auth->login($this->users['1'], remember: true);
    }

    public function testRememberMeRestoresSession(): void
    {
        $auth1 = $this->createAuth();
        $auth1->login($this->users['1'], remember: true);

        // Simulate a new request: clear session, keep cookie
        $this->session = [];

        $auth2 = $this->createAuth();
        $user = $auth2->getCurrentUser();

        self::assertNotNull($user);
        self::assertSame('1', $user->getId());
        self::assertTrue($auth2->isLoggedIn());
        // Session should be restored
        self::assertArrayHasKey('__tinyauth_user_id', $this->session);
    }

    public function testRememberMeWithInvalidCookie(): void
    {
        // Set a garbage cookie
        $this->cookies['__tinyauth_remember'] = 'invalid.cookie.value';

        $auth = $this->createAuth();
        $user = $auth->getCurrentUser();

        self::assertNull($user);
        self::assertFalse($auth->isLoggedIn());
        // Cookie should be cleaned up
        self::assertArrayNotHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testRememberMeWithTamperedCookie(): void
    {
        // Create a valid auth and cookie first
        $auth1 = $this->createAuth('secret-key-a');
        $auth1->login($this->users['1'], remember: true);

        $cookieValue = $this->cookies['__tinyauth_remember'];

        // Now try to use that cookie with a different key (simulating tampering)
        $this->session = [];
        $this->cookies = ['__tinyauth_remember' => $cookieValue];

        $auth2 = $this->createAuth('different-key');
        $user = $auth2->getCurrentUser();

        self::assertNull($user);
        self::assertArrayNotHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testRememberMeWithDeletedUser(): void
    {
        $auth1 = $this->createAuth();
        $auth1->login($this->users['1'], remember: true);

        // Delete the user
        unset($this->users['1']);
        $this->session = [];

        $auth2 = $this->createAuth();
        $user = $auth2->getCurrentUser();

        self::assertNull($user);
        self::assertArrayNotHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testRememberMeNoKeySkipsCookieCheck(): void
    {
        // Set some cookie value
        $this->cookies['__tinyauth_remember'] = 'somevalue';

        $auth = $this->createAuth('');
        $user = $auth->getCurrentUser();

        self::assertNull($user);
        // Cookie should NOT be removed (we didn't even try)
        self::assertArrayHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testUserWithIdProperty(): void
    {
        $auth = $this->createAuth();
        $user = new TestUserWithProperty('42');

        $auth->login($user);

        self::assertSame('42', $this->session['__tinyauth_user_id']);
    }

    public function testUserWithoutIdThrows(): void
    {
        $auth = $this->createAuth();
        $user = new \stdClass();

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Cannot extract user ID');

        $auth->login($user);
    }

    public function testCustomSessionKey(): void
    {
        $auth = new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            encryptionKey: 'test',
            sessionKey: 'custom_user_id',
        );

        $auth->login($this->users['1']);

        self::assertArrayHasKey('custom_user_id', $this->session);
        self::assertArrayNotHasKey('__tinyauth_user_id', $this->session);
    }

    public function testCustomCookieName(): void
    {
        $auth = new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            encryptionKey: 'test',
            cookieName: 'remember_me',
        );

        $auth->login($this->users['1'], remember: true);

        self::assertArrayHasKey('remember_me', $this->cookies);
        self::assertArrayNotHasKey('__tinyauth_remember', $this->cookies);
    }

    public function testSessionUserNotFound(): void
    {
        // Set a session for a non-existent user
        $this->session['__tinyauth_user_id'] = '999';

        $auth = $this->createAuth();
        $user = $auth->getCurrentUser();

        self::assertNull($user);
        self::assertFalse($auth->isLoggedIn());
    }

    public function testMultipleLoginCalls(): void
    {
        $auth = $this->createAuth();

        $auth->login($this->users['1']);
        self::assertSame('1', $auth->getCurrentUser()?->getId());

        $auth->login($this->users['2']);
        self::assertSame('2', $auth->getCurrentUser()?->getId());
    }

    public function testLoginThenLogoutThenLogin(): void
    {
        $auth = $this->createAuth();

        $auth->login($this->users['1']);
        self::assertTrue($auth->isLoggedIn());

        $auth->logout();
        self::assertFalse($auth->isLoggedIn());

        $auth->login($this->users['2']);
        self::assertTrue($auth->isLoggedIn());
        self::assertSame('2', $auth->getCurrentUser()?->getId());
    }

    public function testGetCurrentUserCachesResult(): void
    {
        $callCount = 0;
        $userLoader = function (string $id) use (&$callCount): ?TestUser {
            $callCount++;
            return $this->users[$id] ?? null;
        };

        $auth = new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $userLoader,
            encryptionKey: 'test',
        );

        $auth->login($this->users['1']);

        // Call multiple times
        $auth->getCurrentUser();
        $auth->getCurrentUser();
        $auth->getCurrentUser();

        // After login, the user is cached, so loader should not be called
        self::assertSame(0, $callCount);
    }
}
