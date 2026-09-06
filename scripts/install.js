const path = require("path");
const fs = require("fs");

const isWin = process.platform === "win32";
const binaryName = isWin ? "interenv.exe" : "interenv";
const platformArch = `${process.platform}-${process.arch}`;

const prebuildPath = path.join(__dirname, "..", "prebuilds", platformArch, binaryName);
const releasePath = path.join(__dirname, "..", "target", "release", binaryName);
const debugPath = path.join(__dirname, "..", "target", "debug", binaryName);

let foundBinary = null;
if (fs.existsSync(prebuildPath)) {
  foundBinary = prebuildPath;
} else if (fs.existsSync(releasePath)) {
  foundBinary = releasePath;
} else if (fs.existsSync(debugPath)) {
  foundBinary = debugPath;
}

if (foundBinary) {
  if (!isWin) {
    try {
      fs.accessSync(foundBinary, fs.constants.X_OK);
    } catch {
      try {
        fs.chmodSync(foundBinary, 0o755);
      } catch (err) {
        console.warn(`⚠️  InterEnv: Unable to set executable permissions on ${foundBinary}: ${err.message}`);
      }
    }
  }
  process.exit(0);
}

// Check if interenv is already available in PATH
try {
  const { execSync } = require("child_process");
  const checkCmd = isWin ? "where interenv" : "command -v interenv";
  execSync(checkCmd, { stdio: "ignore" });
  process.exit(0);
} catch {
  // Not found in PATH
}

console.warn(`⚠️  InterEnv: Native binary not bundled for ${platformArch}.`);
console.warn(`   Please install the CLI via Cargo or download a release binary:`);
console.warn(`     cargo install interenv`);
console.warn(`     https://github.com/Bharathcoorg/interenv/releases`);
console.warn(`   The Node.js SDK will use 'interenv' from your system PATH.`);
process.exit(0);

