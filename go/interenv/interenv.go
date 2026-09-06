// Package interenv provides in-memory hardware-enclave protected secrets for Go applications.
// Zero plaintext .env files are ever created or read from physical disk.
package interenv

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// discoverBinary locates the native interenv executable.
func discoverBinary() string {
	exeName := "interenv"
	if runtime.GOOS == "windows" {
		exeName = "interenv.exe"
	}

	if envBin := os.Getenv("INTERENV_BIN"); envBin != "" {
		if _, err := os.Stat(envBin); err == nil {
			return envBin
		}
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".interenv", "bin", exeName),
		filepath.Join("..", "target", "release", exeName),
		filepath.Join(".", "target", "release", exeName),
		filepath.Join("..", "..", "target", "release", exeName),
		exeName,
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return exeName
}

// buildCleanEnv constructs a clean execution environment for the native CLI.
func buildCleanEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"LANG=" + os.Getenv("LANG"),
		"INTERENV_CI=1",
	}
	passthrough := []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_SESSION_ID", "INTERENV_PASSPHRASE"}
	for _, key := range passthrough {
		if val := os.Getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}
	return env
}

// All retrieves all secrets from the local project lockfile as a key-value map.
func All() (map[string]string, error) {
	bin := discoverBinary()
	cmd := exec.Command(bin, "show", "--reveal", "--json")
	cmd.Env = buildCleanEnv()

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("interenv show failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to run interenv binary '%s' (install via 'cargo install interenv' or https://github.com/Bharathcoorg/interenv/releases): %w", bin, err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(output, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse interenv secrets JSON: %w", err)
	}

	return secrets, nil
}

// Load reads vaulted secrets and populates os.Setenv directly into memory.
func Load() error {
	secrets, err := All()
	if err != nil {
		return err
	}

	for k, v := range secrets {
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("failed to set env var '%s': %w", k, err)
		}
	}

	return nil
}

// Get returns the value of an environment secret, loading the vault if not present.
func Get(key string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	_ = Load()
	return os.Getenv(key)
}

// Run executes an external command with vaulted secrets in memory.
func Run(name string, args ...string) error {
	bin := discoverBinary()
	fullArgs := append([]string{"run", name}, args...)
	cmd := exec.Command(bin, fullArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run interenv binary '%s' (install via 'cargo install interenv' or https://github.com/Bharathcoorg/interenv/releases): %w", bin, err)
	}
	return nil
}
