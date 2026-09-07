const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const {
  packExtension,
  buildZipBuffer,
  collectProductionFiles,
  toDosTime,
  INCLUDED_PATTERNS,
  EXCLUDED_PATTERNS
} = require("../scripts/pack.js");

describe("Distribution Packager (scripts/pack.js)", () => {
  describe("toDosTime helper", () => {
    it("converts Date to valid 16-bit MS-DOS date and time integers", () => {
      const date = new Date("2026-09-07T12:30:40Z");
      const { dosTime, dosDate } = toDosTime(date);

      assert.equal(typeof dosTime, "number");
      assert.equal(typeof dosDate, "number");
      assert.ok(dosTime >= 0 && dosTime <= 0xffff);
      assert.ok(dosDate >= 0 && dosDate <= 0xffff);
    });

    it("handles invalid or missing dates gracefully by defaulting to now", () => {
      const resNull = toDosTime(null);
      assert.ok(resNull.dosDate > 0);

      const resInvalid = toDosTime(new Date("invalid"));
      assert.ok(resInvalid.dosDate > 0);
    });
  });

  describe("buildZipBuffer binary generator", () => {
    it("builds a binary ZIP buffer with standard local, central, and EOCD records", () => {
      const files = [
        { name: "test.txt", data: Buffer.from("Hello OSN Guard Test Content", "utf8") },
        { name: "nested/file.json", data: Buffer.from(JSON.stringify({ active: true }), "utf8") }
      ];

      const zipBuf = buildZipBuffer(files);
      assert.ok(Buffer.isBuffer(zipBuf));
      assert.ok(zipBuf.length > 50);

      // Verify Local File Header signature (PK\x03\x04 = 0x04034b50)
      assert.equal(zipBuf.readUInt32LE(0), 0x04034b50);

      // Verify EOCD signature (PK\x05\x06 = 0x06054b50) at the end
      const eocdOffset = zipBuf.length - 22;
      assert.equal(zipBuf.readUInt32LE(eocdOffset), 0x06054b50);
      assert.equal(zipBuf.readUInt16LE(eocdOffset + 8), 2); // 2 records on disk
      assert.equal(zipBuf.readUInt16LE(eocdOffset + 10), 2); // 2 total records
    });

    it("stores uncompressible small payloads without error", () => {
      const files = [
        { name: "empty.txt", data: Buffer.alloc(0) }
      ];

      const zipBuf = buildZipBuffer(files);
      assert.ok(zipBuf.length >= 30 + 9 + 46 + 9 + 22);
      assert.equal(zipBuf.readUInt32LE(0), 0x04034b50);
    });
  });

  describe("collectProductionFiles collector", () => {
    const rootDir = path.resolve(__dirname, "..");

    it("collects required production files and ignores test/dev artifacts", () => {
      const files = collectProductionFiles(rootDir);
      const relativePaths = files.map(f => f.relativePath);

      // Must include production extension files
      assert.ok(relativePaths.includes("manifest.json"), "manifest.json missing");
      assert.ok(relativePaths.includes("background.js"), "background.js missing");
      assert.ok(relativePaths.includes("content.js"), "content.js missing");
      assert.ok(relativePaths.includes("content.css"), "content.css missing");
      assert.ok(relativePaths.includes("core/url-analyzer.js"), "url-analyzer.js missing");
      assert.ok(relativePaths.includes("core/pii-analyzer.js"), "pii-analyzer.js missing");
      assert.ok(relativePaths.includes("core/scam-analyzer.js"), "scam-analyzer.js missing");
      assert.ok(relativePaths.includes("popup/popup.html"), "popup.html missing");
      assert.ok(relativePaths.includes("options/options.html"), "options.html missing");
      assert.ok(relativePaths.includes("assets/icons/icon-128.png"), "icon-128.png missing");

      // Must strictly exclude non-production files
      assert.ok(!relativePaths.some(p => p.startsWith("tests/")), "tests/ was not excluded");
      assert.ok(!relativePaths.some(p => p.startsWith(".github/")), ".github/ was not excluded");
      assert.ok(!relativePaths.some(p => p.startsWith("docs/")), "docs/ was not excluded");
      assert.ok(!relativePaths.some(p => p.startsWith("scripts/")), "scripts/ was not excluded");
      assert.ok(!relativePaths.includes("test-page.html"), "test-page.html was not excluded");
      assert.ok(!relativePaths.includes("package.json"), "package.json was not excluded");
      assert.ok(!relativePaths.includes(".gitignore"), ".gitignore was not excluded");
    });
  });

  describe("packExtension workflow", () => {
    const rootDir = path.resolve(__dirname, "..");
    const testDistDir = path.join(rootDir, "dist", "test-pack-run");

    it("generates a valid zip archive file and returns complete metadata", () => {
      const result = packExtension({
        rootDir,
        outputDir: testDistDir,
        zipFileName: "test-package.zip"
      });

      assert.ok(fs.existsSync(result.zipPath));
      assert.ok(result.totalFiles >= 15);
      assert.ok(result.uncompressedBytes > 0);
      assert.ok(result.compressedBytes > 0);
      assert.ok(result.compressedBytes < result.uncompressedBytes);

      // Clean up test artifact
      fs.unlinkSync(result.zipPath);
      fs.rmdirSync(testDistDir);
    });
  });
});
