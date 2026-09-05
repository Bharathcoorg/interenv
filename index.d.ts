/**
 * InterEnv TypeScript Definitions
 */

export interface InterEnvConfigOptions {
  /** Optional custom path to the interenv executable */
  binaryPath?: string;
}

export interface InterEnvConfigResult {
  parsed?: Record<string, string>;
  error?: Error;
}

/**
 * Loads hardware-enclave protected secrets into Node's process.env directly from memory.
 * No plaintext .env file is ever touched or created on disk.
 */
export function config(options?: InterEnvConfigOptions): InterEnvConfigResult;
