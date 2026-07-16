import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const REQUIRED_DOCUMENT_EXTENSIONS = [
  ".txt",
  ".csv",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".pdf",
  ".ppt",
  ".pptx",
] as const;

export type DocumentExtension = (typeof REQUIRED_DOCUMENT_EXTENSIONS)[number];

export type DocumentFixture = {
  readonly extension: DocumentExtension;
  readonly relativePath: string;
  readonly absolutePath: string;
  readonly filename: string;
  readonly token: string;
  readonly expectedSourceLocations: readonly string[];
  readonly sha256: string;
  readonly bytes: number;
};

type RawFixture = {
  readonly extension?: unknown;
  readonly relative_path?: unknown;
  readonly token?: unknown;
  readonly expected_source_locations?: unknown;
  readonly generator?: unknown;
  readonly sha256?: unknown;
  readonly bytes?: unknown;
};

type RawManifest = {
  readonly schema_version?: unknown;
  readonly fixture_set?: unknown;
  readonly license?: unknown;
  readonly content_origin?: unknown;
  readonly network_required?: unknown;
  readonly fixtures?: unknown;
};

function blocked(reason: string): never {
  throw new Error(`E2E_BLOCKED: document fixture ${reason}`);
}

function sha256(payload: Buffer): string {
  return createHash("sha256").update(payload).digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function safeRegularFile(filePath: string, label: string) {
  let metadata: fs.Stats;
  try {
    metadata = fs.lstatSync(filePath);
  } catch {
    blocked(`${label} is missing`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    blocked(`${label} must be a regular non-symlink file`);
  }
  return metadata;
}

function safeDirectory(directoryPath: string, label: string) {
  let metadata: fs.Stats;
  try {
    metadata = fs.lstatSync(directoryPath);
  } catch {
    blocked(`${label} is missing`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    blocked(`${label} must be a non-symlink directory`);
  }
}

function validateMagic(extension: DocumentExtension, payload: Buffer) {
  const ole = Buffer.from("d0cf11e0a1b11ae1", "hex");
  if ([".doc", ".xls", ".ppt"].includes(extension)) {
    if (
      payload.length < 512 ||
      !payload.subarray(0, 8).equals(ole) ||
      !payload.subarray(24, 26).equals(Buffer.from("feff", "hex")) ||
      payload.readUInt16LE(30) !== 9 ||
      payload.readUInt16LE(32) !== 6
    ) {
      blocked(`${extension} is not a real legacy Office compound document`);
    }
  }
  const ooxmlEntries: Partial<Record<DocumentExtension, string>> = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/worksheets/sheet1.xml",
    ".pptx": "ppt/slides/slide1.xml",
  };
  const requiredOoxmlEntry = ooxmlEntries[extension];
  if (
    requiredOoxmlEntry &&
    (payload.subarray(0, 2).toString() !== "PK" ||
      !payload.includes(Buffer.from("[Content_Types].xml")) ||
      !payload.includes(Buffer.from(requiredOoxmlEntry)))
  ) {
    blocked(`${extension} is not a real OOXML package`);
  }
  if (extension === ".pdf" && (!payload.subarray(0, 5).equals(Buffer.from("%PDF-")) || !payload.includes(Buffer.from("%%EOF")))) {
    blocked(".pdf is not a real PDF document");
  }
}

export function loadDocumentFixtures(
  fixtureRoot: string,
  manifestPath: string,
): readonly DocumentFixture[] {
  if (!path.isAbsolute(fixtureRoot) || !path.isAbsolute(manifestPath)) {
    blocked("root and manifest paths must be absolute");
  }
  safeDirectory(fixtureRoot, "root");
  safeRegularFile(manifestPath, "manifest");
  const root = fs.realpathSync(fixtureRoot);
  const manifestRealPath = fs.realpathSync(manifestPath);
  safeRegularFile(manifestRealPath, "manifest");
  if (path.dirname(manifestRealPath) !== root) {
    blocked("manifest must be directly beneath the explicit fixture root");
  }

  let manifest: RawManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestRealPath, "utf8")) as RawManifest;
  } catch {
    blocked("manifest is not valid JSON");
  }
  if (
    !isRecord(manifest) ||
    manifest.schema_version !== 1 ||
    manifest.fixture_set !== "heyi-enterprise-document-acceptance-v1" ||
    manifest.license !== "CC0-1.0" ||
    manifest.content_origin !== "original-synthetic-test-data" ||
    manifest.network_required !== false ||
    !Array.isArray(manifest.fixtures)
  ) {
    blocked("manifest contract is invalid");
  }

  const expected = new Set<string>(REQUIRED_DOCUMENT_EXTENSIONS);
  const seen = new Set<string>();
  const fixtures = manifest.fixtures.map((unknownItem): DocumentFixture => {
    if (!isRecord(unknownItem)) blocked("manifest contains a non-object fixture");
    const item = unknownItem as RawFixture;
    const extension = item.extension;
    if (typeof extension !== "string" || !expected.has(extension) || seen.has(extension)) {
      blocked("manifest extensions are missing, duplicated, or unsupported");
    }
    seen.add(extension);
    if (
      typeof item.relative_path !== "string" ||
      path.isAbsolute(item.relative_path) ||
      !item.relative_path.replaceAll("\\", "/").startsWith("golden/")
    ) {
      blocked(`${extension} has an unsafe relative path`);
    }
    const absolutePath = path.resolve(root, item.relative_path);
    if (path.relative(root, absolutePath).startsWith("..")) {
      blocked(`${extension} escapes the fixture root`);
    }
    const metadata = safeRegularFile(absolutePath, extension);
    const canonicalFile = fs.realpathSync(absolutePath);
    if (path.relative(root, canonicalFile).startsWith("..")) {
      blocked(`${extension} resolves outside the fixture root`);
    }
    const payload = fs.readFileSync(canonicalFile);
    const token = item.token;
    const locations = item.expected_source_locations;
    if (
      typeof token !== "string" ||
      !/^KB-E2E-GOLDEN-[A-Z0-9]+-2026-[A-Z0-9]+$/.test(token) ||
      !Array.isArray(locations) ||
      locations.length === 0 ||
      !locations.every((location) => typeof location === "string" && location.length > 0) ||
      typeof item.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(item.sha256) ||
      typeof item.bytes !== "number" ||
      !Number.isSafeInteger(item.bytes) ||
      item.bytes <= 0
    ) {
      blocked(`${extension} metadata is invalid`);
    }
    const expectedGenerator = [".doc", ".xls", ".ppt"].includes(extension)
      ? "libreoffice"
      : "stdlib";
    if (item.generator !== expectedGenerator) {
      blocked(`${extension} generator provenance is invalid`);
    }
    if (metadata.size !== item.bytes || payload.length !== item.bytes || sha256(payload) !== item.sha256) {
      blocked(`${extension} hash or size does not match the manifest`);
    }
    const lowered = payload.toString("latin1").toLowerCase();
    if (["placeholder", "lorem ipsum", "dummy", "todo"].some((marker) => lowered.includes(marker))) {
      blocked(`${extension} contains forbidden placeholder content`);
    }
    validateMagic(extension as DocumentExtension, payload);
    return {
      extension: extension as DocumentExtension,
      relativePath: item.relative_path,
      absolutePath: canonicalFile,
      filename: path.basename(canonicalFile),
      token,
      expectedSourceLocations: locations as string[],
      sha256: item.sha256,
      bytes: item.bytes,
    };
  });

  if (seen.size !== expected.size || [...expected].some((extension) => !seen.has(extension))) {
    blocked("manifest must contain each of the nine required extensions exactly once");
  }
  return REQUIRED_DOCUMENT_EXTENSIONS.map((extension) => {
    const fixture = fixtures.find((item) => item.extension === extension);
    if (!fixture) blocked(`manifest is missing ${extension}`);
    return fixture;
  });
}
