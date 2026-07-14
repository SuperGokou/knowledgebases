import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import {
  REQUIRED_DOCUMENT_EXTENSIONS,
  loadDocumentFixtures,
} from "../e2e/support/document-fixtures";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function fixturePayload(extension: string, token: string): Buffer {
  if ([".doc", ".xls", ".ppt"].includes(extension)) {
    const payload = Buffer.alloc(1024);
    Buffer.from("d0cf11e0a1b11ae1", "hex").copy(payload);
    Buffer.from("feff", "hex").copy(payload, 24);
    payload.writeUInt16LE(9, 30);
    payload.writeUInt16LE(6, 32);
    payload.write(`REAL ${token}`, 512, "ascii");
    return payload;
  }
  if ([".docx", ".xlsx", ".pptx"].includes(extension)) {
    const entry = extension === ".docx"
      ? "word/document.xml"
      : extension === ".xlsx"
        ? "xl/worksheets/sheet1.xml"
        : "ppt/slides/slide1.xml";
    return Buffer.from(`PK [Content_Types].xml ${entry} REAL ${token}`);
  }
  if (extension === ".pdf") return Buffer.from(`%PDF-1.4\n${token}\n%%EOF\n`);
  return Buffer.from(`REAL ORIGINAL ${token}\n`);
}

function buildFixtureSet() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kb-document-fixtures-"));
  roots.push(root);
  fs.mkdirSync(path.join(root, "golden"));
  const fixtures = REQUIRED_DOCUMENT_EXTENSIONS.map((extension) => {
    const token = `KB-E2E-GOLDEN-${extension.slice(1).toUpperCase()}-2026-A71C`;
    const relativePath = `golden/fixture${extension}`;
    const payload = fixturePayload(extension, token);
    fs.writeFileSync(path.join(root, relativePath), payload);
    return {
      extension,
      relative_path: relativePath,
      token,
      expected_source_locations: [extension === ".pdf" ? "page:1" : "document"],
      generator: [".doc", ".xls", ".ppt"].includes(extension) ? "libreoffice" : "stdlib",
      sha256: createHash("sha256").update(payload).digest("hex"),
      bytes: payload.length,
    };
  });
  const manifestPath = path.join(root, "document-fixtures-v1.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify({
      schema_version: 1,
      fixture_set: "heyi-enterprise-document-acceptance-v1",
      license: "CC0-1.0",
      content_origin: "original-synthetic-test-data",
      network_required: false,
      fixtures,
    }),
  );
  return { root, manifestPath, fixtures };
}

describe("enterprise nine-format document fixtures", () => {
  test("loads exactly nine hashed real fixtures in canonical extension order", () => {
    const { root, manifestPath } = buildFixtureSet();
    const loaded = loadDocumentFixtures(root, manifestPath);

    expect(loaded.map((fixture) => fixture.extension)).toEqual(REQUIRED_DOCUMENT_EXTENSIONS);
    expect(new Set(loaded.map((fixture) => fixture.token)).size).toBe(9);
    expect(loaded.every((fixture) => fixture.expectedSourceLocations.length > 0)).toBe(true);
  });

  test("blocks missing, tampered, placeholder, duplicate and out-of-root fixtures", () => {
    expect(() =>
      loadDocumentFixtures(
        path.join(os.tmpdir(), "definitely-missing-kb-fixtures"),
        path.join(os.tmpdir(), "definitely-missing-kb-fixtures", "manifest.json"),
      ),
    ).toThrow(/E2E_BLOCKED.*root is missing/);

    const { root, manifestPath, fixtures } = buildFixtureSet();
    fs.appendFileSync(path.join(root, fixtures[0].relative_path), "tampered");
    expect(() => loadDocumentFixtures(root, manifestPath)).toThrow(/E2E_BLOCKED.*hash or size/);

    const rebuilt = buildFixtureSet();
    const duplicate = JSON.parse(fs.readFileSync(rebuilt.manifestPath, "utf8")) as {
      fixtures: Array<Record<string, unknown>>;
    };
    duplicate.fixtures[1].extension = duplicate.fixtures[0].extension;
    fs.writeFileSync(rebuilt.manifestPath, JSON.stringify(duplicate));
    expect(() => loadDocumentFixtures(rebuilt.root, rebuilt.manifestPath)).toThrow(
      /E2E_BLOCKED.*extensions/,
    );
  });
});
