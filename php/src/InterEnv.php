<?php

declare(strict_types=1);

namespace InterEnv;

use RuntimeException;

/**
 * InterEnv PHP SDK v1.0.0
 * Hardware-Enclave Protected Secrets for PHP & Laravel Applications.
 * Built by Interlayer.
 */
class InterEnv
{
    private static ?array $cachedSecrets = null;

    /**
     * Locate the native interenv executable.
     */
    public static function discoverBinary(): string
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $exeName = $isWindows ? 'interenv.exe' : 'interenv';

        $envBin = getenv('INTERENV_BIN');
        if ($envBin && file_exists($envBin)) {
            return $envBin;
        }

        $home = getenv('HOME') ?: (getenv('USERPROFILE') ?: '');
        $candidates = [
            $home . DIRECTORY_SEPARATOR . '.interenv' . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . $exeName,
            dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'target' . DIRECTORY_SEPARATOR . 'release' . DIRECTORY_SEPARATOR . $exeName,
            $exeName,
        ];

        foreach ($candidates as $candidate) {
            if (file_exists($candidate)) {
                return $candidate;
            }
        }

        return $exeName;
    }

    /**
     * Load hardware-enclave secrets into $_ENV, $_SERVER, and putenv().
     * Zero plaintext .env files are created or read from physical disk.
     */
    public static function load(?string $binaryPath = null, bool $override = true): array
    {
        $bin = $binaryPath ?? self::discoverBinary();

        $descriptorSpec = [
            0 => ['pipe', 'r'], // stdin
            1 => ['pipe', 'w'], // stdout
            2 => ['pipe', 'w'], // stderr
        ];

        $env = [
            'PATH' => getenv('PATH') ?: '',
            'HOME' => getenv('HOME') ?: '',
            'USERPROFILE' => getenv('USERPROFILE') ?: '',
            'LANG' => getenv('LANG') ?: 'C.UTF-8',
            'INTERENV_CI' => '1',
        ];

        foreach (['DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR', 'XDG_SESSION_ID', 'INTERENV_PASSPHRASE'] as $key) {
            if ($val = getenv($key)) {
                $env[$key] = $val;
            }
        }

        $process = proc_open([$bin, 'show', '--reveal', '--json'], $descriptorSpec, $pipes, null, $env);
        if (!is_resource($process)) {
            throw new RuntimeException("Failed to execute InterEnv binary: {$bin}");
        }

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);
        if ($exitCode !== 0) {
            throw new RuntimeException("InterEnv failed (exit {$exitCode}): " . trim($stderr ?: $stdout));
        }

        $secrets = json_decode(trim($stdout), true);
        if (!is_array($secrets)) {
            throw new RuntimeException("Invalid JSON received from InterEnv: {$stdout}");
        }

        self::$cachedSecrets = $secrets;

        foreach ($secrets as $key => $value) {
            if ($override || !isset($_ENV[$key])) {
                $_ENV[$key] = (string)$value;
                $_SERVER[$key] = (string)$value;
                putenv("{$key}={$value}");
            }
        }

        return $secrets;
    }

    /**
     * Get a specific vaulted secret.
     */
    public static function get(string $key, ?string $default = null): ?string
    {
        if (self::$cachedSecrets === null) {
            self::load();
        }
        return self::$cachedSecrets[$key] ?? (getenv($key) ?: $default);
    }

    /**
     * Get all currently vaulted secrets as an associative array.
     */
    public static function all(): array
    {
        if (self::$cachedSecrets === null) {
            self::load();
        }
        return self::$cachedSecrets ?? [];
    }
}
