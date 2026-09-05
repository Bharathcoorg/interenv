#!/usr/bin/env node
/**
 * InterEnv CLI - Node.js Binary Shim
 * Automatically resolves the native Rust binary or invokes via Cargo if building from source.
 */

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

function findBinary() {
  const isWin = process.platform === "win32";
  const binaryName = isWin ? "interenv.exe" : "interenv";

  // Check target/release
  const releasePath = path.join(__dirname, "..", "target", "release", binaryName);
  if (fs.existsSync(releasePath)) {
    return { cmd: releasePath, args: process.argv.slice(2) };
  }

  // Check target/debug
  const debugPath = path.join(__dirname, "..", "target", "debug", binaryName);
  if (fs.existsSync(debugPath)) {
    return { cmd: debugPath, args: process.argv.slice(2) };
  }

  // Fall back to cargo run
  const cargoToml = path.join(__dirname, "..", "Cargo.toml");
  if (fs.existsSync(cargoToml)) {
    return {
      cmd: "cargo",
      args: ["run", "--quiet", "--manifest-path", cargoToml, "--", ...process.argv.slice(2)]
    };
  }

  // Try global PATH
  return { cmd: "interenv", args: process.argv.slice(2) };
}

const { cmd, args } = findBinary();

const child = spawn(cmd, args, {
  stdio: "inherit",
  env: process.env,
  shell: process.platform === "win32" && cmd === "cargo"
});

child.on("error", (err) => {
  console.error("❌ Failed to launch interenv:", err.message);
  process.exit(1);
});

child.on("close", (code) => {
  process.exit(code === null ? 1 : code);
});
