import {
  createHash,
  generateKeyPairSync,
  verify,
} from "node:crypto";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  EVIDENCE_COLLECTOR,
  EVIDENCE_ID,
  EVIDENCE_KEY_ID,
  REQUIRED_CHECKS,
  buildCompleteEvidence,
  canonicalEvidenceDigest,
  parseEvidenceChallenge,
  protectedFileMetadataIsValid,
  signaturePayload,
  type EvidenceArtifact,
} from "../e2e/support/evidence-reporter";
import { resolvePlaywrightProfile } from "../e2e/support/playwright-profile";
import { inspectEnterpriseConfig } from "../e2e/support/enterprise-config";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

describe("enterprise Playwright profile", () => {
  test("keeps smoke as the default and requires an explicit enterprise profile", () => {
    const smoke = resolvePlaywrightProfile({}, path.resolve("C:/repo/web"));
    expect(smoke.enterprise).toBe(false);
    expect(smoke.grep).toBeUndefined();
    expect(smoke.grepInvert?.test("@enterprise protected scenario")).toBe(true);
    expect(smoke.projects.map((project) => project.name)).toEqual([
      "desktop-chromium",
      "mobile-chromium",
    ]);

    const enterprise = resolvePlaywrightProfile(
      {
        KB_E2E_PROFILE: "enterprise",
        KB_E2E_BASE_URL: "https://kb.invalid",
        KB_E2E_SIGNING_KEY_PATH: "C:/trust/browser-e2e.pem",
        KB_E2E_CHALLENGE_PATH: "C:/trust/browser-challenge.json",
      },
      path.resolve("C:/repo/web"),
    );
    expect(enterprise.enterprise).toBe(true);
    expect(enterprise.grep?.test("@enterprise protected scenario")).toBe(true);
    expect(enterprise.grepInvert).toBeUndefined();
    expect(enterprise.projects.map((project) => project.name)).toEqual([
      "enterprise-desktop",
      "enterprise-mobile",
    ]);
    expect(enterprise.signingKeyPath).toBe("C:/trust/browser-e2e.pem");
    expect(enterprise.challengePath).toBe("C:/trust/browser-challenge.json");
    expect(
      enterprise.evidenceOutput
        .replaceAll("\\", "/")
        .endsWith("/artifacts/acceptance/functional/browser-e2e.json"),
    ).toBe(true);
  });

  test("rejects unknown profile names instead of silently running smoke", () => {
    expect(() =>
      resolvePlaywrightProfile({ KB_E2E_PROFILE: "entperrise" }, path.resolve("C:/repo/web")),
    ).toThrow(/KB_E2E_PROFILE/);
  });

  test("blocks a topology without an explicit bounded multipart payload", () => {
    const base = {
      KB_E2E_BASE_URL: "https://web.invalid",
      KB_E2E_PUBLIC_API_ORIGIN: "https://api.invalid",
      KB_E2E_ADMIN_EMAIL: "synthetic@example.invalid",
      KB_E2E_ADMIN_PASSWORD: "not-a-real-secret",
      KB_E2E_FAULT_CONTROL_ORIGIN: "https://fault.invalid",
      KB_E2E_FAULT_CONTROL_TOKEN: "not-a-real-token",
      KB_E2E_SEEDED_KNOWLEDGE_BASE_ID: "seeded",
      KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID: "unscoped",
      KB_E2E_SIGNING_KEY_PATH: "C:/trust/browser-e2e.pem",
      KB_E2E_CHALLENGE_PATH: "C:/trust/browser-challenge.json",
      KB_E2E_DOCUMENT_FIXTURE_ROOT: "C:/trust/document-fixtures",
      KB_E2E_DOCUMENT_FIXTURE_MANIFEST: "C:/trust/document-fixtures/document-fixtures-v1.json",
    };
    expect(inspectEnterpriseConfig(base).missing).toContain("KB_E2E_MULTIPART_BYTES");
    expect(
      inspectEnterpriseConfig({ ...base, KB_E2E_MULTIPART_BYTES: "104857599" }).invalid,
    ).toContain("KB_E2E_MULTIPART_BYTES");
    expect(
      inspectEnterpriseConfig({ ...base, KB_E2E_MULTIPART_BYTES: "104857600" }),
    ).toEqual({ missing: [], invalid: [] });
  });
});

describe("enterprise evidence schema v2", () => {
  test("binds every required check to immutable artifacts and a verifiable chain", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const artifacts: EvidenceArtifact[] = REQUIRED_CHECKS.map((check, index) => {
      const body = `${check}-${index}`;
      return {
        id: `artifact-${check}`,
        path: `e2e-artifacts/${check}.json`,
        sha256: sha256(body),
        bytes: Buffer.byteLength(body),
      };
    });
    const checks = Object.fromEntries(
      REQUIRED_CHECKS.map((check) => [
        check,
        { status: "passed" as const, artifact_ids: [`artifact-${check}`] },
      ]),
    );
    const target = {
        git_head: "a".repeat(40),
        content_fingerprint: "b".repeat(64),
    };
    const evidence = buildCompleteEvidence({
      target,
      collectedAt: "2026-07-13T12:00:00.000Z",
      artifacts,
      checks,
      signing: {
        privateKey,
        challenge: {
          schema_version: 1,
          challenge_id: "browser-challenge-20260713",
          evidence_id: EVIDENCE_ID as typeof EVIDENCE_ID,
          nonce: "n".repeat(48),
          issued_at: "2026-07-13T11:55:00.000Z",
          expires_at: "2026-07-13T12:55:00.000Z",
          status: "issued",
          target,
        },
      },
    });

    expect(Object.keys(evidence).sort()).toEqual([
      "artifacts",
      "attestation",
      "checks",
      "collected_at",
      "collector",
      "evidence_id",
      "schema_version",
      "status",
      "target",
    ]);
    expect(evidence.schema_version).toBe(2);
    expect(evidence.evidence_id).toBe(EVIDENCE_ID);
    expect(evidence.collector).toEqual(EVIDENCE_COLLECTOR);
    expect(evidence.status).toBe("complete");
    expect(Object.keys(evidence.checks).sort()).toEqual([...REQUIRED_CHECKS].sort());
    expect(evidence.attestation).toEqual({
      type: "ed25519-challenge-v1",
      key_id: EVIDENCE_KEY_ID,
      challenge_id: "browser-challenge-20260713",
      challenge_nonce: "n".repeat(48),
      signature: expect.stringMatching(/^[A-Za-z0-9+/]{86}==$/),
    });
    expect(
      verify(
        null,
        signaturePayload(evidence, {
          keyId: EVIDENCE_KEY_ID,
          challengeId: evidence.attestation.challenge_id,
          challengeNonce: evidence.attestation.challenge_nonce,
        }),
        publicKey,
        Buffer.from(evidence.attestation.signature, "base64"),
      ),
    ).toBe(true);
    expect(canonicalEvidenceDigest(evidence)).toMatch(/^[0-9a-f]{64}$/);

    const tampered = {
      ...evidence,
      target: { ...evidence.target, content_fingerprint: "c".repeat(64) },
    };
    expect(
      verify(
        null,
        signaturePayload(tampered, {
          keyId: EVIDENCE_KEY_ID,
          challengeId: evidence.attestation.challenge_id,
          challengeNonce: evidence.attestation.challenge_nonce,
        }),
        publicKey,
        Buffer.from(evidence.attestation.signature, "base64"),
      ),
    ).toBe(false);
  });

  test("refuses incomplete, dangling, duplicated, or hash-invalid evidence", () => {
    const validArtifact: EvidenceArtifact = {
      id: "artifact-one",
      path: "e2e-artifacts/one.json",
      sha256: "c".repeat(64),
      bytes: 10,
    };
    const completeChecks = Object.fromEntries(
      REQUIRED_CHECKS.map((check) => [
        check,
        { status: "passed" as const, artifact_ids: [validArtifact.id] },
      ]),
    );
    const { privateKey } = generateKeyPairSync("ed25519");
    const target = { git_head: "a".repeat(40), content_fingerprint: "b".repeat(64) };
    const base = {
      target,
      collectedAt: "2026-07-13T12:00:00.000Z",
      signing: {
        privateKey,
        challenge: {
          schema_version: 1 as const,
          challenge_id: "browser-challenge-20260713",
          evidence_id: EVIDENCE_ID as typeof EVIDENCE_ID,
          nonce: "n".repeat(48),
          issued_at: "2026-07-13T11:55:00.000Z",
          expires_at: "2026-07-13T12:55:00.000Z",
          status: "issued" as const,
          target,
        },
      },
    };

    expect(() => buildCompleteEvidence({ ...base, artifacts: [], checks: completeChecks })).toThrow();
    expect(() =>
      buildCompleteEvidence({
        ...base,
        artifacts: [validArtifact, validArtifact],
        checks: completeChecks,
      }),
    ).toThrow();
    expect(() =>
      buildCompleteEvidence({
        ...base,
        artifacts: [validArtifact],
        checks: {
          ...completeChecks,
          [REQUIRED_CHECKS[0]]: { status: "passed", artifact_ids: ["missing"] },
        },
      }),
    ).toThrow();
    expect(() =>
      buildCompleteEvidence({
        ...base,
        artifacts: [{ ...validArtifact, sha256: "not-a-hash" }],
        checks: completeChecks,
      }),
    ).toThrow();
  });

  test("validates one-time challenge scope, expiry and target binding", () => {
    const target = { git_head: "a".repeat(40), content_fingerprint: "b".repeat(64) };
    const challenge = {
      schema_version: 1,
      challenge_id: "browser-challenge-20260713",
      evidence_id: EVIDENCE_ID,
      nonce: "n".repeat(48),
      issued_at: "2026-07-13T11:55:00.000Z",
      expires_at: "2026-07-13T12:55:00.000Z",
      status: "issued",
      target,
    };
    expect(
      parseEvidenceChallenge(challenge, target, new Date("2026-07-13T12:00:00.000Z")),
    ).toEqual(challenge);
    expect(() =>
      parseEvidenceChallenge(
        { ...challenge, evidence_id: "EXT-OTHER-001" },
        target,
        new Date("2026-07-13T12:00:00.000Z"),
      ),
    ).toThrow();
    expect(() =>
      parseEvidenceChallenge(
        challenge,
        { ...target, content_fingerprint: "c".repeat(64) },
        new Date("2026-07-13T12:00:00.000Z"),
      ),
    ).toThrow();
    expect(() =>
      parseEvidenceChallenge(challenge, target, new Date("2026-07-13T13:00:00.000Z")),
    ).toThrow();
  });

  test("requires Linux root ownership, regular files, no symlink and mode 0400/0600", () => {
    expect(
      protectedFileMetadataIsValid({
        platform: "linux",
        uid: 0,
        mode: 0o100400,
        isFile: true,
        isSymbolicLink: false,
      }),
    ).toBe(true);
    for (const invalid of [
      { platform: "win32", uid: 0, mode: 0o100400, isFile: true, isSymbolicLink: false },
      { platform: "linux", uid: 1000, mode: 0o100400, isFile: true, isSymbolicLink: false },
      { platform: "linux", uid: 0, mode: 0o100644, isFile: true, isSymbolicLink: false },
      { platform: "linux", uid: 0, mode: 0o100400, isFile: false, isSymbolicLink: false },
      { platform: "linux", uid: 0, mode: 0o120400, isFile: false, isSymbolicLink: true },
    ]) {
      expect(protectedFileMetadataIsValid(invalid)).toBe(false);
    }
  });
});
