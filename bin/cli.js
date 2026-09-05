#!/usr/bin/env node
/**
 * InterEnv CLI - Node.js Binary Shim
 * Automatically resolves the native Rust prebuilt binary or target/release build.
 */

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

function findBinary() {
  const isWin = process.platform === "win32";
  const binaryName = isWin ? "interenv.exe" : "interenv";
  const platformArch = `${process.platform}-${process.arch}`;

  // 1. Check prebuilds directory
  const prebuildPath = path.join(__dirname, "..", "prebuilds", platformArch, binaryName);
  if (fs.existsSync(prebuildPath)) {
    return { cmd: prebuildPath, args: process.argv.slice(2) };
  }

  // 2. Check local target/release
  const releasePath = path.join(__dirname, "..", "target", "release", binaryName);
  if (fs.existsSync(releasePath)) {
    return { cmd: releasePath, args: process.argv.slice(2) };
  }

  // 3. Check local target/debug
  const debugPath = path.join(__dirname, "..", "target", "debug", binaryName);
  if (fs.existsSync(debugPath)) {
    return { cmd: debugPath, args: process.argv.slice(2) };
  }

  // 4. Try global PATH
  return { cmd: "interenv", args: process.argv.slice(2) };
}

const { cmd, args } = findBinary();

const child = spawn(cmd, args, {
  stdio: "inherit",
  env: process.env,
});

child.on("error", (err) => {
  console.error("❌ Failed to launch interenv:", err.message);
  console.error("💡 If installing from source, please run 'npm run build:rust' first.");
  process.exit(1);
});

child.on("close", (code) => {
  process.exit(code === null ? 1 : code);
});
