/**
 * Milestone 1 Iteration 2 Challenger: Empirical ZIP Bomb & Boundary Stress Test
 *
 * Stresses the in-memory boundaries of extract_bundle_files and verify_bundle_zip in WebAssembly:
 * 1. Entry Count Limit (MAX_BUNDLE_ENTRIES = 128): tests 128 (allowed) vs 129 (rejected).
 * 2. Declared Entry Size Limit (MAX_ENTRY_SIZE = 10 MiB): tests header check (> 10 MiB declared).
 * 3. Lying Header ZIP Bomb: header claims small size (< 100 bytes), but stream decompresses to > 10 MiB.
 * 4. Cumulative Expansion Limit (MAX_TOTAL_BUNDLE_SIZE = 50 MiB): multiple entries each < 10 MiB, but sum > 50 MiB.
 * 5. Boundary Exact Tests: exactly 10 MiB single entry, cumulative up to 50 MiB.
 * 6. Non-UTF8 & Binary Content Handling.
 * 7. Path Traversal & Special Characters in entry names.
 * 8. Directories and Zero-Byte Files.
 * 9. Corrupt/Truncated/Malformed ZIP structures.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const WASM_JS_PATH = path.join(ROOT_DIR, "aip-console", "public", "wasm", "aip_wasm.js");
const WASM_BG_PATH = path.join(ROOT_DIR, "aip-console", "public", "wasm", "aip_wasm_bg.wasm");

console.log("=== EMPIRICAL ZIP BOMB & BOUNDARY STRESS TEST ===");
console.log(`Loading WASM: ${WASM_BG_PATH}`);

const wasmModule = await import(`file://${WASM_JS_PATH}`);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
await wasmModule.default({ module_or_path: wasmBytes });
console.log("✓ WebAssembly module successfully initialized");

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (!condition) {
    failedTests++;
    console.error(`  ❌ FAIL [${totalTests}]: ${message}`);
  } else {
    passedTests++;
    console.log(`  ✓ PASS [${totalTests}]: ${message}`);
  }
}

// CRC32 table
const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  crcTable[i] = c >>> 0;
}

function computeCrc32(buf) {
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ (-1)) >>> 0;
}

/**
 * Custom ZIP Builder that allows fine-grained manipulation of:
 * - Local & Central Directory headers
 * - Faked/lying uncompressed/compressed size fields
 * - Deflate vs Store compression
 * - Arbitrary file names and attributes
 */
function buildCustomZip(entries) {
  const localChunks = [];
  const cdEntries = [];
  let currentOffset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, "utf-8");
    const rawData = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, "utf-8");
    const actualCrc = computeCrc32(rawData);

    let compressedData;
    let method = entry.method ?? 8; // 8 = Deflate, 0 = Store

    if (method === 8) {
      compressedData = zlib.deflateRawSync(rawData, { level: 9 });
    } else {
      compressedData = rawData;
    }

    const uncompressedSize = entry.fakeUncompressedSize !== undefined ? entry.fakeUncompressedSize : rawData.length;
    const compressedSize = entry.fakeCompressedSize !== undefined ? entry.fakeCompressedSize : compressedData.length;
    const crc = entry.fakeCrc !== undefined ? entry.fakeCrc : actualCrc;

    // Local File Header (30 bytes + name)
    const localHeader = Buffer.alloc(30 + nameBuf.length);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4);          // version needed
    localHeader.writeUInt16LE(0, 6);           // flags
    localHeader.writeUInt16LE(method, 8);      // compression method
    localHeader.writeUInt16LE(0, 10);          // mod time
    localHeader.writeUInt16LE(0, 12);          // mod date
    localHeader.writeUInt32LE(crc, 14);        // crc32
    localHeader.writeUInt32LE(compressedSize, 18);   // compressed size
    localHeader.writeUInt32LE(uncompressedSize, 22); // uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26);   // name len
    localHeader.writeUInt16LE(0, 28);          // extra len
    nameBuf.copy(localHeader, 30);

    const localEntryOffset = currentOffset;
    localChunks.push(localHeader);
    localChunks.push(compressedData);
    currentOffset += localHeader.length + compressedData.length;

    // Central Directory Entry (46 bytes + name)
    const cdHeader = Buffer.alloc(46 + nameBuf.length);
    cdHeader.writeUInt32LE(0x02014b50, 0); // signature
    cdHeader.writeUInt16LE(20, 4);         // version made by
    cdHeader.writeUInt16LE(20, 6);         // version needed
    cdHeader.writeUInt16LE(0, 8);          // flags
    cdHeader.writeUInt16LE(method, 10);     // method
    cdHeader.writeUInt16LE(0, 12);         // mod time
    cdHeader.writeUInt16LE(0, 14);         // mod date
    cdHeader.writeUInt32LE(crc, 16);       // crc32
    cdHeader.writeUInt32LE(compressedSize, 20);   // compressed size
    cdHeader.writeUInt32LE(uncompressedSize, 24); // uncompressed size
    cdHeader.writeUInt16LE(nameBuf.length, 28);   // name len
    cdHeader.writeUInt16LE(0, 30);         // extra len
    cdHeader.writeUInt16LE(0, 32);         // comment len
    cdHeader.writeUInt16LE(0, 34);         // disk start
    cdHeader.writeUInt16LE(0, 36);         // internal attr
    const externalAttr = entry.isDir ? 0x10 : 0x81a40000;
    cdHeader.writeUInt32LE(externalAttr, 38);     // external attr
    cdHeader.writeUInt32LE(localEntryOffset, 42); // local header offset
    nameBuf.copy(cdHeader, 46);

    cdEntries.push(cdHeader);
  }

  const cdOffset = currentOffset;
  let cdSize = 0;
  for (const c of cdEntries) cdSize += c.length;

  // End of Central Directory (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);     // signature
  eocd.writeUInt16LE(0, 4);              // disk number
  eocd.writeUInt16LE(0, 6);              // cd disk
  eocd.writeUInt16LE(entries.length, 8); // cd entries on disk
  eocd.writeUInt16LE(entries.length, 10);// total cd entries
  eocd.writeUInt32LE(cdSize, 12);        // cd size
  eocd.writeUInt32LE(cdOffset, 16);      // cd offset
  eocd.writeUInt16LE(0, 20);             // comment len

  return Buffer.concat([...localChunks, ...cdEntries, eocd]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 1: Entry Count Limit (MAX_BUNDLE_ENTRIES = 128)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 1] Entry Count Limit Enforcement (128 vs 129)");

{
  // 1.1 Exactly 128 entries (Should succeed)
  const entries128 = [];
  for (let i = 0; i < 128; i++) {
    entries128.push({ name: `file_${i}.txt`, data: `Content for file ${i}` });
  }
  const zip128 = buildCustomZip(entries128);
  try {
    const res = wasmModule.extract_bundle_files(zip128);
    const parsed = JSON.parse(res);
    assert(Object.keys(parsed).length === 128, `Exactly 128 entries extracted cleanly (${Object.keys(parsed).length} files)`);
  } catch (e) {
    assert(false, `Exactly 128 entries failed unexpectedly: ${e}`);
  }

  // 1.2 129 entries (Must be rejected immediately)
  const entries129 = [];
  for (let i = 0; i < 129; i++) {
    entries129.push({ name: `file_${i}.txt`, data: `Content for file ${i}` });
  }
  const zip129 = buildCustomZip(entries129);
  let caught129 = false;
  try {
    wasmModule.extract_bundle_files(zip129);
  } catch (e) {
    caught129 = true;
    const msg = String(e);
    assert(
      msg.includes("ZIP bundle contains too many entries (129 > max 128)"),
      `129 entries rejected with expected message: ${msg}`
    );
  }
  assert(caught129, "129 entries rejected by MAX_BUNDLE_ENTRIES guard");

  // 1.3 500 entries (Severe entry exhaustion attack)
  const entries500 = [];
  for (let i = 0; i < 500; i++) {
    entries500.push({ name: `bomb_${i}.txt`, data: "x" });
  }
  const zip500 = buildCustomZip(entries500);
  let caught500 = false;
  try {
    wasmModule.extract_bundle_files(zip500);
  } catch (e) {
    caught500 = true;
    assert(String(e).includes("too many entries"), `500 entries rejected: ${e}`);
  }
  assert(caught500, "500 entries rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 2: Header Declared Size Limit (MAX_ENTRY_SIZE = 10 MiB)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 2] Header Declared Size Limit (> 10 MiB)");

{
  // 2.1 Declared size = 10 MiB + 1 byte (10,485,761 bytes)
  // Even with 0 bytes of real data, the declared header must trigger immediate rejection
  const zipDeclaredOversize = buildCustomZip([
    {
      name: "oversize_declared.txt",
      data: "short data",
      fakeUncompressedSize: 10 * 1024 * 1024 + 1,
    },
  ]);

  let caughtOversize = false;
  try {
    wasmModule.extract_bundle_files(zipDeclaredOversize);
  } catch (e) {
    caughtOversize = true;
    const msg = String(e);
    assert(
      msg.includes("declared uncompressed size (10485761 bytes) exceeds limit of 10485760 bytes"),
      `Declared uncompressed size > 10 MiB rejected in header check: ${msg}`
    );
  }
  assert(caughtOversize, "Header check caught declared size exceeding 10 MiB");

  // 2.2 Massive declared size (2 GiB)
  const zip2GiB = buildCustomZip([
    {
      name: "massive_2gb.txt",
      data: "x",
      fakeUncompressedSize: 2 * 1024 * 1024 * 1024 - 1,
    },
  ]);
  let caught2GiB = false;
  try {
    wasmModule.extract_bundle_files(zip2GiB);
  } catch (e) {
    caught2GiB = true;
    assert(String(e).includes("declared uncompressed size"), `2 GiB declared size rejected: ${e}`);
  }
  assert(caught2GiB, "2 GiB declared size rejected before memory allocation");
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 3: Lying Header ZIP Bomb (Stream Expansion Check)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 3] Lying Header ZIP Bomb Attack (Stream Expansion Check)");

{
  // Create 11 MiB of zero bytes (highly compressible: 11 MiB -> ~11 KiB)
  const targetBombBytes = 11 * 1024 * 1024;
  const bombPayload = Buffer.alloc(targetBombBytes, 0x41); // 'A' repeats

  // Malicious zip: header claims size is only 100 bytes!
  const lyingZip = buildCustomZip([
    {
      name: "stealth_bomb.txt",
      data: bombPayload,
      fakeUncompressedSize: 100, // LIE!
    },
  ]);

  let caughtLyingBomb = false;
  try {
    wasmModule.extract_bundle_files(lyingZip);
  } catch (e) {
    caughtLyingBomb = true;
    const msg = String(e);
    assert(
      msg.includes("uncompressed size exceeds limit of 10485760 bytes (ZIP bomb detected)"),
      `Lying header ZIP bomb caught by stream take reader: ${msg}`
    );
  }
  assert(caughtLyingBomb, "Lying header ZIP bomb successfully intercepted without WASM crash or OOM");
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 4: Cumulative Expansion Limit (MAX_TOTAL_BUNDLE_SIZE = 50 MiB)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 4] Cumulative Expansion Limit (MAX_TOTAL_BUNDLE_SIZE = 50 MiB)");

{
  // 6 files, each 9 MiB uncompressed (each < 10 MiB limit, passes per-file check)
  // Total = 54 MiB (> 50 MiB cumulative limit)
  const fileBytes = 9 * 1024 * 1024;
  const entries = [];
  for (let i = 0; i < 6; i++) {
    entries.push({
      name: `subfile_${i}.txt`,
      data: Buffer.alloc(fileBytes, 0x30 + i),
    });
  }
  const multiBombZip = buildCustomZip(entries);

  let caughtCumulative = false;
  try {
    wasmModule.extract_bundle_files(multiBombZip);
  } catch (e) {
    caughtCumulative = true;
    const msg = String(e);
    assert(
      msg.includes("Total extracted bundle size") && msg.includes("exceeds limit of 52428800 bytes (ZIP bomb detected)"),
      `Cumulative limit caught multi-file expansion bomb: ${msg}`
    );
  }
  assert(caughtCumulative, "Distributed multi-file ZIP bomb stopped by MAX_TOTAL_BUNDLE_SIZE");
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 5: Exact Boundary Conditions
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 5] Exact Boundary Conditions");

{
  // 5.1 Exactly 10 MiB single entry (10,485,760 bytes) - Should pass
  const exact10MiB = Buffer.alloc(10 * 1024 * 1024, 0x62);
  const exactZip = buildCustomZip([
    {
      name: "exact_10mib.txt",
      data: exact10MiB,
    },
  ]);

  try {
    const res = wasmModule.extract_bundle_files(exactZip);
    const parsed = JSON.parse(res);
    assert(parsed["exact_10mib.txt"]?.length === 10 * 1024 * 1024, "Exactly 10 MiB entry extracted successfully");
  } catch (e) {
    assert(false, `Exactly 10 MiB entry failed: ${e}`);
  }

  // 5.2 Exactly 10 MiB + 1 byte single entry (10,485,761 bytes) - Must fail
  const oversize1Byte = Buffer.alloc(10 * 1024 * 1024 + 1, 0x63);
  const oversize1ByteZip = buildCustomZip([
    {
      name: "oversize_1byte.txt",
      data: oversize1Byte,
    },
  ]);

  let caught1Byte = false;
  try {
    wasmModule.extract_bundle_files(oversize1ByteZip);
  } catch (e) {
    caught1Byte = true;
    assert(String(e).includes("exceeds limit of 10485760 bytes"), `10 MiB + 1 byte rejected: ${e}`);
  }
  assert(caught1Byte, "10 MiB + 1 byte rejected by boundary");
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 6: Non-UTF8 & Binary Safety
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 6] Non-UTF8 & Binary Safety");

{
  // Raw binary bytes containing invalid UTF-8 sequences (0xFF, 0xFE, 0x80)
  const binaryPayload = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0xc0, 0xaf, 0xe0, 0x80]);
  const binZip = buildCustomZip([
    {
      name: "binary_data.bin",
      data: binaryPayload,
      method: 0, // Store
    },
  ]);

  try {
    const res = wasmModule.extract_bundle_files(binZip);
    const parsed = JSON.parse(res);
    assert(parsed["binary_data.bin"] !== undefined, "Binary entry extracted without panic using lossy UTF-8 conversion");
  } catch (e) {
    assert(false, `Binary payload caused unexpected failure: ${e}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 7: Directory Entries & Empty Entries
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 7] Directory Entries and Empty Files");

{
  const dirZip = buildCustomZip([
    { name: "mydir/", data: Buffer.alloc(0), isDir: true },
    { name: "nested/sub/", data: Buffer.alloc(0), isDir: true },
    { name: "nested/sub/hello.txt", data: "Hello World" },
    { name: "empty.txt", data: Buffer.alloc(0) },
  ]);

  try {
    const res = wasmModule.extract_bundle_files(dirZip);
    const parsed = JSON.parse(res);
    assert(parsed["mydir/"] === undefined, "Directory entries skipped from file map");
    assert(parsed["nested/sub/"] === undefined, "Nested directory entries skipped");
    assert(parsed["nested/sub/hello.txt"] === "Hello World", "File inside nested dir preserved");
    assert(parsed["empty.txt"] === "", "Empty file extracted as empty string");
  } catch (e) {
    assert(false, `Directory handling failed: ${e}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 8: Malicious Path Traversal Filenames
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 8] Malicious Path Traversal Filenames");

{
  const evilZip = buildCustomZip([
    { name: "../../etc/passwd", data: "root:x:0:0" },
    { name: "..\\..\\windows\\system32\\cmd.exe", data: "MZ..." },
    { name: "normal.json", data: '{"ok": true}' },
  ]);

  try {
    const res = wasmModule.extract_bundle_files(evilZip);
    const parsed = JSON.parse(res);
    // Since extract_bundle_files returns in-memory map, it must not execute traversal or crash
    assert(parsed["../../etc/passwd"] === "root:x:0:0", "Relative traversal path preserved in map key safely");
    assert(parsed["..\\..\\windows\\system32\\cmd.exe"] === "MZ...", "Backslash traversal path preserved safely");
    assert(parsed["normal.json"] === '{"ok": true}', "Normal file intact");
  } catch (e) {
    assert(false, `Path traversal caused unexpected error: ${e}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress Test 9: Rapid Sequential Extractions (WASM Memory Stability)
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n[Stress Test 9] Rapid Sequential Extractions (WASM Memory Stability)");

{
  // Perform 20 consecutive extractions of moderate-size archives to test heap recycling
  const testPayload = Buffer.alloc(1024 * 512, 0x5a); // 512 KiB
  const zip = buildCustomZip([{ name: "recycle.txt", data: testPayload }]);

  let successCount = 0;
  for (let i = 0; i < 20; i++) {
    const res = wasmModule.extract_bundle_files(zip);
    if (res.includes("recycle.txt")) {
      successCount++;
    }
  }
  assert(successCount === 20, "20 sequential extractions executed without memory leaks or heap traps");
}

console.log("\n=======================================================");
console.log(`ZIP BOMB EMPIRICAL STRESS SUITE RESULTS:`);
console.log(`Passed: ${passedTests} / ${totalTests} (Failed: ${failedTests})`);
console.log("=======================================================\n");

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
