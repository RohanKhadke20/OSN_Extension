/**
 * OSN Guard - Production Distribution Packager
 *
 * Compresses production extension assets into a clean, standalone ZIP archive
 * ready for Chrome Web Store submission without requiring third-party npm dependencies.
 *
 * Uses Node.js built-in 'node:fs', 'node:path', and 'node:zlib' (Raw Deflate + CRC-32).
 */

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

// Files and directories included in production build
const INCLUDED_PATTERNS = [
  "manifest.json",
  "background.js",
  "content.js",
  "content.css",
  "README.md",
  "core",
  "popup",
  "options",
  "assets"
];

// Explicit exclusions
const EXCLUDED_PATTERNS = [
  "node_modules",
  ".git",
  ".github",
  ".agents",
  ".gemini",
  ".vscode",
  ".idea",
  "docs",
  "tests",
  "scripts",
  "dist",
  "test-page.html",
  ".gitignore",
  "package.json",
  "package-lock.json",
  ".DS_Store",
  "Thumbs.db",
  "ehthumbs.db"
];

/**
 * Encodes a Date object into standard MS-DOS 16-bit time and date values.
 * @param {Date} date
 * @returns {{ dosTime: number, dosDate: number }}
 */
function toDosTime(date) {
  const d = date instanceof Date && !isNaN(date.getTime()) ? date : new Date();
  const year = d.getFullYear();
  const dosYear = year < 1980 ? 0 : year - 1980;
  const dosDate = (dosYear << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (Math.floor(d.getSeconds() / 2));
  return { dosTime, dosDate };
}

/**
 * Creates a standard PKZIP archive Buffer from an array of file entries.
 * @param {Array<{ name: string, data: Buffer, mtime?: Date }>} files
 * @returns {Buffer}
 */
function buildZipBuffer(files) {
  const localChunks = [];
  const centralChunks = [];
  let offset = 0;

  for (const file of files) {
    // Force standard ZIP forward-slash paths
    const normalizedName = file.name.replace(/\\/g, "/").replace(/^\/+/, "");
    const nameBuf = Buffer.from(normalizedName, "utf8");
    const content = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data || "", "utf8");
    const uncompressedSize = content.length;
    const crc = zlib.crc32(content);

    // Compress using raw Deflate (no zlib wrapper)
    const compressed = zlib.deflateRawSync(content, { level: 9 });
    const compressedSize = compressed.length;

    // Use Deflate (8) unless uncompressed is smaller or empty
    const useDeflate = compressedSize < uncompressedSize && uncompressedSize > 0;
    const method = useDeflate ? 8 : 0;
    const dataToWrite = useDeflate ? compressed : content;
    const finalCompressedSize = dataToWrite.length;

    const { dosTime, dosDate } = toDosTime(file.mtime);

    // --- Local File Header (30 bytes + nameBuf.length) ---
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // Local header signature (PK\x03\x04)
    localHeader.writeUInt16LE(20, 4);          // Minimum version needed to extract (2.0)
    localHeader.writeUInt16LE(0x0800, 6);       // Bit flag: UTF-8 filename encoding (Bit 11)
    localHeader.writeUInt16LE(method, 8);       // Compression method (0 = Store, 8 = Deflate)
    localHeader.writeUInt16LE(dosTime, 10);     // File modification time
    localHeader.writeUInt16LE(dosDate, 12);     // File modification date
    localHeader.writeUInt32LE(crc, 14);         // CRC-32 checksum
    localHeader.writeUInt32LE(finalCompressedSize, 18); // Compressed size
    localHeader.writeUInt32LE(uncompressedSize, 22);    // Uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26);      // File name length
    localHeader.writeUInt16LE(0, 28);                  // Extra field length

    const localOffset = offset;
    localChunks.push(localHeader, nameBuf, dataToWrite);
    offset += localHeader.length + nameBuf.length + dataToWrite.length;

    // --- Central Directory File Header (46 bytes + nameBuf.length) ---
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // Central directory signature (PK\x01\x02)
    centralHeader.writeUInt16LE(0x0314, 4);     // Version made by: UNIX (0x03) + 2.0 (0x14)
    centralHeader.writeUInt16LE(20, 6);         // Minimum version needed
    centralHeader.writeUInt16LE(0x0800, 8);      // UTF-8 filename flag
    centralHeader.writeUInt16LE(method, 10);     // Compression method
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(crc, 16);        // CRC-32
    centralHeader.writeUInt32LE(finalCompressedSize, 20);
    centralHeader.writeUInt32LE(uncompressedSize, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);         // Extra field length
    centralHeader.writeUInt16LE(0, 32);         // File comment length
    centralHeader.writeUInt16LE(0, 34);         // Disk number start
    centralHeader.writeUInt16LE(0, 36);         // Internal attributes
    centralHeader.writeUInt32LE(0x81a40000, 38); // External attributes (regular file 0644)
    centralHeader.writeUInt32LE(localOffset, 42); // Relative offset of local header

    centralChunks.push(centralHeader, nameBuf);
  }

  const centralDirOffset = offset;
  const centralDirSize = centralChunks.reduce((acc, c) => acc + c.length, 0);

  // --- End of Central Directory Record (EOCD, 22 bytes) ---
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature (PK\x05\x06)
  eocd.writeUInt16LE(0, 4);          // Disk number
  eocd.writeUInt16LE(0, 6);          // Start disk
  eocd.writeUInt16LE(files.length, 8); // Number of records on this disk
  eocd.writeUInt16LE(files.length, 10); // Total number of central dir records
  eocd.writeUInt32LE(centralDirSize, 12); // Central directory size in bytes
  eocd.writeUInt32LE(centralDirOffset, 16); // Central directory starting offset
  eocd.writeUInt16LE(0, 20);         // Comment length

  return Buffer.concat([...localChunks, ...centralChunks, eocd]);
}

/**
 * Recursively scans directory paths and returns a flat list of matching files.
 * @param {string} rootDir
 * @param {string[]} includes
 * @param {string[]} excludes
 * @returns {Array<{ relativePath: string, fullPath: string, mtime: Date, size: number }>}
 */
function collectProductionFiles(rootDir, includes = INCLUDED_PATTERNS, excludes = EXCLUDED_PATTERNS) {
  const collected = [];

  function shouldExclude(relPath) {
    const segments = relPath.replace(/\\/g, "/").split("/");
    return excludes.some(ex => segments.includes(ex) || relPath === ex || relPath.startsWith(ex + "/"));
  }

  function walk(currentDir, baseRel = "") {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const relPath = baseRel ? `${baseRel}/${entry.name}` : entry.name;
      const fullPath = path.join(currentDir, entry.name);

      if (shouldExclude(relPath)) continue;

      if (entry.isDirectory()) {
        walk(fullPath, relPath);
      } else if (entry.isFile()) {
        const stat = fs.statSync(fullPath);
        collected.push({
          relativePath: relPath.replace(/\\/g, "/"),
          fullPath,
          mtime: stat.mtime,
          size: stat.size
        });
      }
    }
  }

  for (const item of includes) {
    const fullItemPath = path.join(rootDir, item);
    if (!fs.existsSync(fullItemPath)) continue;

    const stat = fs.statSync(fullItemPath);
    if (stat.isDirectory()) {
      walk(fullItemPath, item);
    } else if (stat.isFile() && !shouldExclude(item)) {
      collected.push({
        relativePath: item.replace(/\\/g, "/"),
        fullPath: fullItemPath,
        mtime: stat.mtime,
        size: stat.size
      });
    }
  }

  // Deduplicate and sort alphabetically for reproducible builds
  const uniqueMap = new Map();
  collected.forEach(f => uniqueMap.set(f.relativePath, f));
  return Array.from(uniqueMap.values()).sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}

/**
 * Packages the extension into a distribution ZIP archive.
 * @param {Object} options
 * @param {string} [options.rootDir] - Extension root directory
 * @param {string} [options.outputDir] - Destination folder for zip
 * @param {string} [options.zipFileName] - Optional explicit filename
 * @returns {{ zipPath: string, totalFiles: number, uncompressedBytes: number, compressedBytes: number, files: string[] }}
 */
function packExtension(options = {}) {
  const rootDir = options.rootDir || path.resolve(__dirname, "..");
  const outputDir = options.outputDir || path.join(rootDir, "dist");

  // Read manifest for extension identity & version
  const manifestPath = path.join(rootDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest.json not found in root directory: ${rootDir}`);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const extensionName = (manifest.name || "osn-guard").toLowerCase().replace(/[^a-z0-9_-]/g, "-").replace(/-+/g, "-");
  const extensionVersion = manifest.version || "1.0.0";
  const defaultZipName = `${extensionName}-v${extensionVersion}.zip`;
  const zipFileName = options.zipFileName || defaultZipName;

  // Ensure output directory exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Collect files
  const fileEntries = collectProductionFiles(rootDir);
  if (fileEntries.length === 0) {
    throw new Error("No production files found to package.");
  }

  // Load buffer for each file
  const zipInput = fileEntries.map(entry => ({
    name: entry.relativePath,
    data: fs.readFileSync(entry.fullPath),
    mtime: entry.mtime
  }));

  const zipBuffer = buildZipBuffer(zipInput);
  const zipPath = path.join(outputDir, zipFileName);
  fs.writeFileSync(zipPath, zipBuffer);

  const totalUncompressed = fileEntries.reduce((acc, f) => acc + f.size, 0);

  return {
    zipPath,
    totalFiles: fileEntries.length,
    uncompressedBytes: totalUncompressed,
    compressedBytes: zipBuffer.length,
    files: fileEntries.map(f => f.relativePath)
  };
}

// CLI Execution Handler
if (require.main === module) {
  try {
    console.log("==================================================");
    console.log(" OSN Guard - Production Extension Packager");
    console.log("==================================================");

    const result = packExtension();

    console.log(`\nPackaged ${result.totalFiles} production files:`);
    result.files.forEach(f => console.log(`  + ${f}`));

    const savings = ((1 - result.compressedBytes / result.uncompressedBytes) * 100).toFixed(1);
    console.log("\nDistribution Archive Created:");
    console.log(`  Output:       ${result.zipPath}`);
    console.log(`  Raw Size:     ${(result.uncompressedBytes / 1024).toFixed(2)} KB`);
    console.log(`  Archive Size: ${(result.compressedBytes / 1024).toFixed(2)} KB (${savings}% compression)`);
    console.log("\nSuccess: Ready for Chrome Web Store upload.\n");
  } catch (err) {
    console.error("\nPackaging Failed:", err.message);
    process.exit(1);
  }
}

module.exports = {
  packExtension,
  buildZipBuffer,
  collectProductionFiles,
  toDosTime,
  INCLUDED_PATTERNS,
  EXCLUDED_PATTERNS
};
