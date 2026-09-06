/**
 * InterEnv JavaScript / TypeScript SDK v1.0.0
 * Hardware-Enclave Protected Secrets for Terminal & Node.js by Interlayer
 */

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

function findBinaryPath() {
  const isWin = process.platform === "win32";
  const binaryName = isWin ? "interenv.exe" : "interenv";
  const platformArch = `${process.platform}-${process.arch}`;

  const prebuildPath = path.join(__dirname, "prebuilds", platformArch, binaryName);
  const releasePath = path.join(__dirname, "target", "release", binaryName);
  const debugPath = path.join(__dirname, "target", "debug", binaryName);

  if (fs.existsSync(prebuildPath)) return prebuildPath;
  if (fs.existsSync(releasePath)) return releasePath;
  if (fs.existsSync(debugPath)) return debugPath;
  return "interenv";
}

/**
 * Loads hardware-enclave protected secrets into Node's process.env directly from memory.
 * No plaintext .env file is ever touched or created on disk.
 */
function config(options = {}) {
  try {
    let bin = options.binaryPath || findBinaryPath();

    // Validate binaryPath security: refuse relative paths that wander outside package
    if (options.binaryPath) {
      const resolved = path.resolve(options.binaryPath);
      if (!path.isAbsolute(options.binaryPath) && !resolved.startsWith(__dirname)) {
        throw new Error("Security exception: options.binaryPath must be an absolute path or inside package directory");
      }
      bin = resolved;
    }

    const args = ["show", "--reveal", "--json"];

    // Minimal environment hygiene
    const cleanEnv = {
      PATH: process.env.PATH || "",
      HOME: process.env.HOME || "",
      USERPROFILE: process.env.USERPROFILE || "",
      LANG: process.env.LANG || "C.UTF-8",
      LC_ALL: process.env.LC_ALL || "C.UTF-8",
      INTERENV_CI: "1", // Allows non-interactive passphrase reading if supplied
    };

    // Forward Linux keyring DBus vars if present
    if (process.env.DBUS_SESSION_BUS_ADDRESS) {
      cleanEnv.DBUS_SESSION_BUS_ADDRESS = process.env.DBUS_SESSION_BUS_ADDRESS;
    }
    if (process.env.XDG_RUNTIME_DIR) {
      cleanEnv.XDG_RUNTIME_DIR = process.env.XDG_RUNTIME_DIR;
    }
    if (process.env.XDG_SESSION_ID) {
      cleanEnv.XDG_SESSION_ID = process.env.XDG_SESSION_ID;
    }
    if (process.env.INTERENV_PASSPHRASE) {
      cleanEnv.INTERENV_PASSPHRASE = process.env.INTERENV_PASSPHRASE;
    }

    const output = execFileSync(bin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: cleanEnv,
    });

    const parsed = JSON.parse(output.trim());
    for (const [k, v] of Object.entries(parsed)) {
      process.env[k] = v;
    }

    return { parsed };
  } catch (err) {
    return { error: err };
  }
}

module.exports = { config };
