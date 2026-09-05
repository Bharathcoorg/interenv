/**
 * InterEnv postinstall script
 * Verifies binary presence or guides the user on building from source.
 */

const path = require("path");
const fs = require("fs");

const isWin = process.platform === "win32";
const binaryName = isWin ? "interenv.exe" : "interenv";
const platformArch = `${process.platform}-${process.arch}`;

const prebuildPath = path.join(__dirname, "..", "prebuilds", platformArch, binaryName);
const releasePath = path.join(__dirname, "..", "target", "release", binaryName);

if (fs.existsSync(prebuildPath) || fs.existsSync(releasePath)) {
  // Prebuilt binary found
  process.exit(0);
}

// Otherwise inform user
console.log("ℹ️  InterEnv: Installed via npm. To compile release binary locally, run 'npm run build:rust'.");
