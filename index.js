/**
 * InterEnv JavaScript / TypeScript SDK v0.1.0
 * Hardware-Enclave Protected Secrets for Terminal & Node.js by Interlayer
 */

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

function findBinaryPath() {
  const isWin = process.platform === "win32";
  const binaryName = isWin ? "interenv.exe" : "interenv";
  const releasePath = path.join(__dirname, "target", "release", binaryName);
  const debugPath = path.join(__dirname, "target", "debug", binaryName);

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
    const bin = options.binaryPath || findBinaryPath();
    const args = ["show", "--reveal", "--raw"];
    
    const output = execFileSync(bin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });

    const parsed = {};
    for (const line of output.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const idx = trimmed.indexOf("=");
      if (idx !== -1) {
        const key = trimmed.slice(0, idx).trim();
        let val = trimmed.slice(idx + 1).trim();
        if (val.startsWith('"') && val.endsWith('"')) {
          val = val.slice(1, -1);
        }
        process.env[key] = val;
        parsed[key] = val;
      }
    }

    return { parsed };
  } catch (err) {
    return { error: err };
  }
}

module.exports = { config };
