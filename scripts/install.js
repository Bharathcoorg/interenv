const path = require("path");
const fs = require("fs");

const isWin = process.platform === "win32";
const binaryName = isWin ? "interenv.exe" : "interenv";
const platformArch = `${process.platform}-${process.arch}`;

const prebuildPath = path.join(__dirname, "..", "prebuilds", platformArch, binaryName);
const releasePath = path.join(__dirname, "..", "target", "release", binaryName);

let foundBinary = null;
if (fs.existsSync(prebuildPath)) {
  foundBinary = prebuildPath;
} else if (fs.existsSync(releasePath)) {
  foundBinary = releasePath;
}

if (foundBinary) {
  if (!isWin) {
    try {
      fs.accessSync(foundBinary, fs.constants.X_OK);
    } catch {
      try {
        fs.chmodSync(foundBinary, 0o755);
      } catch (err) {
        console.warn(`⚠️ InterEnv: Unable to set executable permissions on ${foundBinary}: ${err.message}`);
      }
    }
  }
  process.exit(0);
}

console.error(`InterEnv: no prebuilt binary found for ${platformArch}. Run 'npm run build:rust' or download a release from https://github.com/Bharathcoorg/interenv/releases.`);
process.exit(1);
