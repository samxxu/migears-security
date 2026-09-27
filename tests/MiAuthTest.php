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

/**
 * User stub whose getId() is not public — must NOT be invoked; falls back to the public property.
 */
final class TestUserWithPrivateGetter
{
    public function __construct(
        public string $id,
    ) {
    }

    private function getId(): string
    {
        return 'should-not-be-used';
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

    private function createAuth(string $encryptionKey = 'test-secret-key', ?callable $sessionRegenerate = null): MiAuth
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
            sessionRegenerate: $sessionRegenerate,
        );
    }

    public function testLoginStoresUserIdInSession(): void
    {
        $auth = $this->createAuth();
        $user = $this->users['1'];

        $auth->login($user);

        self::assertArrayHasKey('__migears_user_id', $this->session);
        self::assertSame('1', $this->session['__migears_user_id']);
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
        self::assertArrayNotHasKey('__migears_user_id', $this->session);
    }

    public function testLogoutClearsRememberCookie(): void
    {
        $auth = $this->createAuth();
        $auth->login($this->users['1'], remember: true);

        self::assertArrayHasKey('__migears_remember', $this->cookies);

        $auth->logout();

        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
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

        self::assertArrayHasKey('__migears_remember', $this->cookies);
        self::assertNotEmpty($this->cookies['__migears_remember']);
    }

    public function testLoginWithoutRememberDoesNotSetCookie(): void
    {
        $auth = $this->createAuth();

        $auth->login($this->users['1'], remember: false);

        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
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
        self::assertArrayHasKey('__migears_user_id', $this->session);
    }

    public function testRememberMeWithInvalidCookie(): void
    {
        // Set a garbage cookie
        $this->cookies['__migears_remember'] = 'invalid.cookie.value';

        $auth = $this->createAuth();
        $user = $auth->getCurrentUser();

        self::assertNull($user);
        self::assertFalse($auth->isLoggedIn());
        // Cookie should be cleaned up
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
    }

    public function testRememberMeWithTamperedCookie(): void
    {
        // Create a valid auth and cookie first
        $auth1 = $this->createAuth('secret-key-a');
        $auth1->login($this->users['1'], remember: true);

        $cookieValue = $this->cookies['__migears_remember'];

        // Now try to use that cookie with a different key (simulating tampering)
        $this->session = [];
        $this->cookies = ['__migears_remember' => $cookieValue];

        $auth2 = $this->createAuth('different-key');
        $user = $auth2->getCurrentUser();

        self::assertNull($user);
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
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
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
    }

    public function testRememberMeNoKeySkipsCookieCheck(): void
    {
        // Set some cookie value
        $this->cookies['__migears_remember'] = 'somevalue';

        $auth = $this->createAuth('');
        $user = $auth->getCurrentUser();

        self::assertNull($user);
        // Cookie should NOT be removed (we didn't even try)
        self::assertArrayHasKey('__migears_remember', $this->cookies);
    }

    public function testUserWithIdProperty(): void
    {
        $auth = $this->createAuth();
        $user = new TestUserWithProperty('42');

        $auth->login($user);

        self::assertSame('42', $this->session['__migears_user_id']);
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
        self::assertArrayNotHasKey('__migears_user_id', $this->session);
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
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
    }

    public function testSessionUserNotFound(): void
    {
        // Set a session for a non-existent user
        $this->session['__migears_user_id'] = '999';

        $auth = $this->createAuth();
        $user = $auth->getCurrentUser();

        self::assertNull($user);
        self::assertFalse($auth->isLoggedIn());
        // Stale session key for the deleted user should be cleaned up
        self::assertArrayNotHasKey('__migears_user_id', $this->session);
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

    public function testLoginRegeneratesSession(): void
    {
        $regenerated = 0;
        $auth = $this->createAuth(sessionRegenerate: function () use (&$regenerated): void {
            $regenerated++;
        });

        $auth->login($this->users['1']);

        self::assertSame(1, $regenerated);
    }

    public function testLoginRotatesSessionBeforeWritingUserId(): void
    {
        $order = [];
        $sessionRef = &$this->session;

        $auth = new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: static function (string $key, string $value) use (&$sessionRef, &$order): void {
                $order[] = 'set';
                $sessionRef[$key] = $value;
            },
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            encryptionKey: 'test',
            sessionRegenerate: static function () use (&$order): void {
                $order[] = 'regenerate';
            },
        );

        $auth->login($this->users['1']);

        // The ID must be rotated first, so the new session ID carries the authenticated state
        self::assertSame(['regenerate', 'set'], $order);
    }

    public function testWithoutRegenerateCallableLoginStillWorks(): void
    {
        $auth = $this->createAuth();

        $auth->login($this->users['1']);

        self::assertSame('1', $auth->getCurrentUser()?->getId());
    }

    public function testLoginRememberWithoutKeyLeavesSessionUntouched(): void
    {
        $auth = $this->createAuth('');

        try {
            $auth->login($this->users['1'], remember: true);
            self::fail('Expected SecurityException to be thrown.');
        } catch (SecurityException) {
            // expected
        }

        // A failed login must not leave the user half-logged-in
        self::assertArrayNotHasKey('__migears_user_id', $this->session);
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
        self::assertFalse($auth->isLoggedIn());
    }

    public function testRememberMeRestoreRegeneratesSession(): void
    {
        $auth1 = $this->createAuth();
        $auth1->login($this->users['1'], remember: true);

        $this->session = [];

        $regenerated = 0;
        $auth2 = $this->createAuth(sessionRegenerate: function () use (&$regenerated): void {
            $regenerated++;
        });

        self::assertNotNull($auth2->getCurrentUser());
        self::assertSame(1, $regenerated);
    }

    public function testNonPublicGetIdIsNotInvoked(): void
    {
        $auth = $this->createAuth();

        $auth->login(new TestUserWithPrivateGetter('7'));

        self::assertSame('7', $this->session['__migears_user_id']);
    }

    // --- remember-me with a PSR-16 store ---

    /**
     * @param TestCache $cache
     */
    private function createStoreAuth(
        TestCache $cache,
        string $encryptionKey = '',
        int $rememberTtl = 2592000,
        int $rememberGrace = 30,
    ): MiAuth {
        return new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            encryptionKey: $encryptionKey,
            rememberTtl: $rememberTtl,
            rememberStore: $cache,
            rememberGrace: $rememberGrace,
        );
    }

    private function recordKey(string $token): string
    {
        return '__migears_rem_' . substr(hash('sha256', $token), 0, 32);
    }

    public function testStoreModeIssuesAnOpaqueTokenBackedByARecord(): void
    {
        $cache = new TestCache();
        $auth = $this->createStoreAuth($cache);

        $auth->login($this->users['1'], remember: true);

        $token = $this->cookies['__migears_remember'];
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
        self::assertSame(1, $cache->count());

        $record = $cache->get($this->recordKey($token));
        self::assertIsArray($record);
        self::assertSame('1', $record['uid']);
        self::assertSame(0, $record['epoch']);
        self::assertNull($record['rotated_at']);
    }

    public function testStoreModeDoesNotRequireAnEncryptionKey(): void
    {
        $cache = new TestCache();

        $this->createStoreAuth($cache, encryptionKey: '')->login($this->users['1'], remember: true);

        self::assertArrayHasKey('__migears_remember', $this->cookies);
    }

    public function testStoreModeRestoresTheSession(): void
    {
        $cache = new TestCache();
        $this->createStoreAuth($cache)->login($this->users['1'], remember: true);

        $this->session = [];

        $auth = $this->createStoreAuth($cache);
        $user = $auth->getCurrentUser();

        self::assertNotNull($user);
        self::assertSame('Alice', $user->name);
        self::assertArrayHasKey('__migears_user_id', $this->session);
    }

    public function testStoreModeRotatesTheTokenOnEveryUse(): void
    {
        $cache = new TestCache();
        $this->createStoreAuth($cache)->login($this->users['1'], remember: true);
        $first = $this->cookies['__migears_remember'];

        $this->session = [];
        self::assertNotNull($this->createStoreAuth($cache)->getCurrentUser());
        $second = $this->cookies['__migears_remember'];

        self::assertNotSame($first, $second);

        // The consumed token is kept, marked as rotated, for the grace window
        $consumed = $cache->get($this->recordKey($first));
        self::assertIsArray($consumed);
        self::assertNotNull($consumed['rotated_at']);

        // The successor is the one that still works
        $this->session = [];
        $this->cookies = ['__migears_remember' => $second];
        self::assertSame('1', $this->createStoreAuth($cache)->getCurrentUser()?->getId());
    }

    public function testConsumedTokenIsHonouredInsideTheGraceWindow(): void
    {
        $cache = new TestCache();
        $this->createStoreAuth($cache)->login($this->users['1'], remember: true);
        $consumed = $this->cookies['__migears_remember'];

        $this->session = [];
        self::assertNotNull($this->createStoreAuth($cache)->getCurrentUser());

        // A parallel request still carrying the consumed token must not be logged out
        $this->session = [];
        $this->cookies = ['__migears_remember' => $consumed];

        self::assertSame('1', $this->createStoreAuth($cache)->getCurrentUser()?->getId());
    }

    public function testConsumedTokenIsRejectedWithAZeroGraceWindow(): void
    {
        $cache = new TestCache();
        $this->createStoreAuth($cache, rememberGrace: 0)->login($this->users['1'], remember: true);
        $consumed = $this->cookies['__migears_remember'];

        $this->session = [];
        self::assertNotNull($this->createStoreAuth($cache, rememberGrace: 0)->getCurrentUser());

        $this->session = [];
        $this->cookies = ['__migears_remember' => $consumed];

        self::assertNull($this->createStoreAuth($cache, rememberGrace: 0)->getCurrentUser());
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
    }

    public function testUnknownStoredTokenIsRejected(): void
    {
        $cache = new TestCache();
        $this->cookies['__migears_remember'] = bin2hex(random_bytes(32));

        self::assertNull($this->createStoreAuth($cache)->getCurrentUser());
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
    }

    public function testExpiredStoredRecordIsRejectedAndDropped(): void
    {
        $cache = new TestCache();
        $token = bin2hex(random_bytes(32));
        $cache->set($this->recordKey($token), [
            'uid' => '1',
            'exp' => time() - 10,
            'epoch' => 0,
            'rotated_at' => null,
        ]);
        $this->cookies['__migears_remember'] = $token;

        self::assertNull($this->createStoreAuth($cache)->getCurrentUser());
        self::assertSame(0, $cache->count());
    }

    public function testRecordFromAStaleEpochIsRejected(): void
    {
        $cache = new TestCache();
        $token = bin2hex(random_bytes(32));
        $cache->set($this->recordKey($token), [
            'uid' => '1',
            'exp' => time() + 3600,
            'epoch' => 5,
            'rotated_at' => null,
        ]);
        $this->cookies['__migears_remember'] = $token;

        self::assertNull($this->createStoreAuth($cache)->getCurrentUser());
        self::assertSame(0, $cache->count());
    }

    public function testRevokeRememberTokensInvalidatesEveryDeviceOfThatUser(): void
    {
        $cache = new TestCache();
        $auth = $this->createStoreAuth($cache);

        $auth->login($this->users['1'], remember: true);
        $deviceA = $this->cookies['__migears_remember'];
        $auth->login($this->users['1'], remember: true);
        $deviceB = $this->cookies['__migears_remember'];
        $auth->login($this->users['2'], remember: true);
        $otherUser = $this->cookies['__migears_remember'];

        $auth->revokeRememberTokens('1');

        foreach ([$deviceA, $deviceB] as $token) {
            $this->session = [];
            $this->cookies = ['__migears_remember' => $token];
            self::assertNull($this->createStoreAuth($cache)->getCurrentUser());
        }

        $this->session = [];
        $this->cookies = ['__migears_remember' => $otherUser];
        self::assertSame('2', $this->createStoreAuth($cache)->getCurrentUser()?->getId());
    }

    public function testRevokeRememberTokensWithoutAStoreThrows(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('rememberStore');

        $this->createAuth()->revokeRememberTokens('1');
    }

    public function testLogoutRevokesTheStoredRecord(): void
    {
        $cache = new TestCache();
        $auth = $this->createStoreAuth($cache);
        $auth->login($this->users['1'], remember: true);
        $token = $this->cookies['__migears_remember'];

        $auth->logout();

        self::assertSame(0, $cache->count());

        $this->session = [];
        $this->cookies = ['__migears_remember' => $token];
        self::assertNull($this->createStoreAuth($cache)->getCurrentUser());
    }

    public function testStoreModeDropsTheCookieWhenTheUserIsGone(): void
    {
        $cache = new TestCache();
        $this->createStoreAuth($cache)->login($this->users['1'], remember: true);

        unset($this->users['1']);
        $this->session = [];

        self::assertNull($this->createStoreAuth($cache)->getCurrentUser());
        self::assertArrayNotHasKey('__migears_remember', $this->cookies);
    }

    public function testStoreModeSessionIsRotatedWhenRestored(): void
    {
        $cache = new TestCache();
        $this->createStoreAuth($cache)->login($this->users['1'], remember: true);

        $this->session = [];

        $regenerated = 0;
        $auth = new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            rememberStore: $cache,
            sessionRegenerate: function () use (&$regenerated): void {
                $regenerated++;
            },
        );

        self::assertNotNull($auth->getCurrentUser());
        self::assertSame(1, $regenerated);
    }

    // --- constructor validation ---

    public function testConstructorRejectsANonCallableCallback(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('sessionGet');

        new MiAuth(
            sessionGet: 'definitely-not-callable',
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
        );
    }

    public function testConstructorRejectsANonCallableSessionRegenerate(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('sessionRegenerate');

        new MiAuth(
            sessionGet: $this->sessionGet,
            sessionSet: $this->sessionSet,
            sessionRemove: $this->sessionRemove,
            cookieGet: $this->cookieGet,
            cookieSet: $this->cookieSet,
            cookieRemove: $this->cookieRemove,
            userLoader: $this->userLoader,
            sessionRegenerate: 'nope',
        );
    }

    public function testConstructorRejectsNonPositiveRememberTtl(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('rememberTtl');

        $this->createStoreAuth(new TestCache(), rememberTtl: 0);
    }

    public function testConstructorRejectsNegativeRememberGrace(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('rememberGrace');

        $this->createStoreAuth(new TestCache(), rememberGrace: -1);
    }
}
