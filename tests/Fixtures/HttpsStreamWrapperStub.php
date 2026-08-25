<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Fixtures;

/**
 * Stands in for the built-in `https://` stream wrapper so the default transport
 * can be exercised without a network.
 *
 * `RemoteCertificateResolver` normally fetches through `file_get_contents()`,
 * and that path — the one every merchant who does not inject their own client
 * relies on — is otherwise untestable. Registering this in its place makes the
 * real call, real stream context and all, and records what was asked for.
 *
 * Install with {@see install()} and always undo it in `tearDown()`; the
 * registration is process-global.
 */
final class HttpsStreamWrapperStub
{
    /** Body served for the next request, or null to fail the open. */
    public static ?string $body = null;

    /** @var list<string> every URL requested while installed */
    public static array $requested = [];

    /** @var array<string, mixed> the stream context options the resolver built */
    public static array $contextOptions = [];

    /** @var resource|null set by PHP when a context is supplied */
    public $context;

    private int $position = 0;

    public static function install(?string $body): void
    {
        self::$body = $body;
        self::$requested = [];
        self::$contextOptions = [];

        stream_wrapper_unregister('https');
        stream_wrapper_register('https', self::class);
    }

    public static function uninstall(): void
    {
        stream_wrapper_restore('https');

        self::$body = null;
        self::$requested = [];
        self::$contextOptions = [];
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        self::$requested[] = $path;

        if (is_resource($this->context)) {
            self::$contextOptions = stream_context_get_options($this->context);
        }

        $this->position = 0;

        return self::$body !== null;
    }

    public function stream_read(int $count): string
    {
        $chunk = substr((string) self::$body, $this->position, $count);
        $this->position += strlen($chunk);

        return $chunk;
    }

    public function stream_eof(): bool
    {
        return $this->position >= strlen((string) self::$body);
    }

    /** @return array<string, int> */
    public function stream_stat(): array
    {
        return ['size' => strlen((string) self::$body)];
    }

    public function stream_close(): void
    {
    }
}
