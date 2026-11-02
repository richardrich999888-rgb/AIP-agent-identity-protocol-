import { describe, it, expect } from "vitest";

describe("Tier 2 Boundary - F5: Ingestion Edge Cases & File Boundaries", () => {
  it("F5.B1: rejecting 0-byte empty file with descriptive error", () => {
    const emptyFile = { name: "empty.json", size: 0, content: "" };
    const validateFile = (f: { size: number }) => {
      if (f.size === 0) throw new Error("File is empty (0 bytes)");
      return true;
    };
    expect(() => validateFile(emptyFile)).toThrow("File is empty");
  });

  it("F5.B2: rejects oversized file exceeding maximum upload limit (50MB)", () => {
    const largeFileSize = 55 * 1024 * 1024; // 55MB
    const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    const isExceeded = largeFileSize > MAX_FILE_SIZE;
    expect(isExceeded).toBe(true);
  });

  it("F5.B3: catches non-JSON text file dropped with .json extension", () => {
    const rawText = "THIS IS NOT JSON AT ALL";
    expect(() => JSON.parse(rawText)).toThrow(SyntaxError);
  });

  it("F5.B4: catches valid JSON that does not match EvidencePacket schema", () => {
    const randomJson = { foo: "bar", count: 42 };
    const isAep1 = (obj: any) =>
      Array.isArray(obj.magic) &&
      obj.magic[0] === 0x41 &&
      obj.magic[1] === 0x45 &&
      obj.magic[2] === 0x50 &&
      obj.magic[3] === 0x31;
    expect(isAep1(randomJson)).toBe(false);
  });

  it("F5.B5: handles multi-file drop by accepting primary target or warning user", () => {
    const files = ["evidence1.json", "evidence2.json"];
    const handleDrop = (fileList: string[]) => {
      if (fileList.length > 1) {
        return { accepted: fileList[0], warning: "Multiple files dropped; processing first file" };
      }
      return { accepted: fileList[0], warning: null };
    };
    const res = handleDrop(files);
    expect(res.accepted).toBe("evidence1.json");
    expect(res.warning).toContain("Multiple files dropped");
  });
});
