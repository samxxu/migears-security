<?php

declare(strict_types=1);

namespace MiGears\Security\Tests;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

/**
 * Raised by TestCache when a PSR-16 key rule is broken.
 */
final class TestCacheKeyException extends \InvalidArgumentException implements InvalidArgumentException
{
}

/**
 * In-memory PSR-16 cache used by the MiAuth remember-me tests.
 *
 * It enforces the PSR-16 key rules, so these tests also prove that MiAuth
 * derives legal cache keys. TTLs are accepted but not enforced: record expiry is
 * asserted through the records' own timestamps instead.
 */
final class TestCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        $this->assertValidKey($key);

        return $this->items[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->assertValidKey($key);
        $this->items[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        $this->assertValidKey($key);
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];

        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        $this->assertValidKey($key);

        return array_key_exists($key, $this->items);
    }

    /**
     * Number of stored entries.
     */
    public function count(): int
    {
        return count($this->items);
    }

    /**
     * @return list<string>
     */
    public function keys(): array
    {
        return array_keys($this->items);
    }

    /**
     * @throws TestCacheKeyException
     */
    private function assertValidKey(string $key): void
    {
        if ($key === '' || strpbrk($key, '{}()/\\@:') !== false) {
            throw new TestCacheKeyException('Illegal PSR-16 cache key: ' . $key);
        }
    }
}
