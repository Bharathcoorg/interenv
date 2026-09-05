const path = require("path");
const fs = require("fs");

const isWin = process.platform === "win32";
const binaryName = isWin ? "interenv.exe" : "interenv";
const platformArch = `${process.platform}-${process.arch}`;

const prebuildPath = path.join(__dirname, "..", "prebuilds", platformArch, binaryName);
const releasePath = path.join(__dirname, "..", "target", "release", binaryName);

if (fs.existsSync(prebuildPath) || fs.existsSync(releasePath)) {
  process.exit(0);
}

if (fs.existsSync(path.join(__dirname, "..", "Cargo.toml"))) {
  console.log("ℹ️  InterEnv: Source repository detected. Run 'npm run build:rust' to compile local release binary.");
  process.exit(0);
} else {
  console.error("❌ InterEnv: Missing native prebuilt binary for " + platformArch + ".");
  console.error("Please download the release binary from https://github.com/Bharathcoorg/interenv/releases or compile via 'npm run build:rust'.");
  process.exit(1);
}
