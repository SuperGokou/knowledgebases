import {
  createHash,
  generateKeyPairSync,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  DEFAULT_ENTERPRISE_TEST_TIMEOUT_MS,
  resolveEnterpriseTestTimeoutMs,
} from "../playwright.config";
import {
  EVIDENCE_COLLECTOR,
  EVIDENCE_ID,
  EVIDENCE_KEY_ID,
  REQUIRED_CHECKS,
  REQUIRED_PROJECTS,
  buildCompleteEvidence,
  canonicalEvidenceDigest,
  parseEvidenceChallenge,
  protectedFileMetadataIsValid,
  signaturePayload,
  type EvidenceArtifact,
} from "../e2e/support/evidence-reporter";
import { resolvePlaywrightProfile } from "../e2e/support/playwright-profile";
import {
  REQUIRED_ENTERPRISE_ENV,
  inspectEnterpriseConfig,
  requireEnterpriseConfig,
  validateObjectDownloadUrl,
} from "../e2e/support/enterprise-config";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const enterpriseFixtures = readFileSync(
  path.join(process.cwd(), "e2e/support/enterprise-fixtures.ts"),
  "utf8",
);
const enterpriseBusinessSpec = readFileSync(
  path.join(process.cwd(), "e2e/enterprise-business.spec.ts"),
  "utf8",
);

type BrowserCollectionPolicy = {
  readonly expected_collected_tests: number;
  readonly required_projects: readonly string[];
  readonly required_test_titles: readonly string[];
};

function readFormalBrowserCollectionContracts(): readonly BrowserCollectionPolicy[] {
  const repositoryRoot = path.resolve(process.cwd(), "..");
  const policy = JSON.parse(
    readFileSync(path.join(repositoryRoot, "docs/functional_acceptance_policy.json"), "utf8"),
  ) as {
    readonly external_test_collections: Readonly<Record<string, BrowserCollectionPolicy>>;
  };
  const manifest = JSON.parse(
    readFileSync(path.join(repositoryRoot, "docs/functional_acceptance_manifest.json"), "utf8"),
  ) as {
    readonly external_evidence: readonly {
      readonly id: string;
      readonly collection?: BrowserCollectionPolicy;
    }[];
  };
  const manifestContract = manifest.external_evidence.find(
    (item) => item.id === "EXT-BROWSER-E2E-001",
  )?.collection;
  const policyContract = policy.external_test_collections["EXT-BROWSER-E2E-001"];
  if (!manifestContract || !policyContract) {
    throw new Error("formal browser collection contract is incomplete");
  }
  return [manifestContract, policyContract];
}

describe("enterprise Playwright profile", () => {
  test("searches the complete reader knowledge catalog before selecting the chat scope", () => {
    expect(enterpriseBusinessSpec).toContain('getByLabel("搜索可问答知识库")');
    expect(enterpriseBusinessSpec).toContain('parameters.get("minimum_access_level") === "reader"');
    expect(enterpriseBusinessSpec).toContain('parameters.get("q") === knowledgeBaseName');
    expect(enterpriseBusinessSpec).toContain('getByLabel("选择知识库").selectOption(knowledgeBaseId)');
  });

  test("drives the API key lifecycle through browser controls and clears one-time secrets", () => {
    expect(enterpriseBusinessSpec).toContain('getByRole("button", { name: "生成 API Key" })');
    expect(enterpriseBusinessSpec).toContain('getByRole("button", { name: `轮换 ${keyName}` })');
    expect(enterpriseBusinessSpec).toContain('getByRole("button", { name: `撤销 ${keyName}` })');
    expect(enterpriseBusinessSpec).toContain('getByRole("button", { name: "我已保存，关闭明文" })');
    expect(enterpriseBusinessSpec).toContain("await expect(issuedPanel).toHaveCount(0)");
  });

  test("masks one-time credentials and password fields in mandatory evidence screenshots", () => {
    expect(enterpriseFixtures).toContain('[data-sensitive="true"], input[type="password"]');
    expect(enterpriseFixtures).toContain("mask: [sensitiveContent]");
  });

  test("uses a long-running default timeout and accepts an explicit validated override", () => {
    expect(resolveEnterpriseTestTimeoutMs({})).toBe(DEFAULT_ENTERPRISE_TEST_TIMEOUT_MS);
    expect(DEFAULT_ENTERPRISE_TEST_TIMEOUT_MS).toBe(30 * 60_000);
    expect(
      resolveEnterpriseTestTimeoutMs({ KB_E2E_TEST_TIMEOUT_MS: "3600000" }),
    ).toBe(3_600_000);
    expect(() =>
      resolveEnterpriseTestTimeoutMs({ KB_E2E_TEST_TIMEOUT_MS: "59999" }),
    ).toThrow(/KB_E2E_TEST_TIMEOUT_MS/);
    expect(() =>
      resolveEnterpriseTestTimeoutMs({ KB_E2E_TEST_TIMEOUT_MS: "not-a-number" }),
    ).toThrow(/KB_E2E_TEST_TIMEOUT_MS/);
  });

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

  test("keeps formal collection policy, runtime profile, and evidence reporter projects aligned", () => {
    const enterprise = resolvePlaywrightProfile(
      { KB_E2E_PROFILE: "enterprise" },
      path.resolve(process.cwd()),
    );
    const runtimeProjects = enterprise.projects.map((project) => project.name);
    const reporterProjects = [...REQUIRED_PROJECTS];

    for (const contract of readFormalBrowserCollectionContracts()) {
      expect(contract.expected_collected_tests).toBe(22);
      expect(contract.required_projects).toEqual(runtimeProjects);
      expect(contract.required_projects).toEqual(reporterProjects);
    }
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
      KB_E2E_OBJECTS_ORIGIN: "https://objects.invalid",
      KB_E2E_ADMIN_EMAIL: "synthetic@example.invalid",
      KB_E2E_ADMIN_PASSWORD: "not-a-real-secret",
      KB_E2E_FAULT_CONTROL_ORIGIN: "https://fault.invalid",
      KB_E2E_FAULT_CONTROL_TOKEN: "not-a-real-token",
      KB_E2E_SEEDED_KNOWLEDGE_BASE_ID: "seeded",
      KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID: "unscoped",
      KB_E2E_SIGNING_KEY_PATH: "C:/trust/browser-e2e.pem",
      KB_E2E_CHALLENGE_PATH: "C:/trust/browser-challenge.json",
      KB_E2E_RUN_ID: "acceptance-run-20260714",
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

  test("requires one exact object origin and rejects unsafe signed download URLs", () => {
    const env = {
      KB_E2E_BASE_URL: "https://web.invalid",
      KB_E2E_PUBLIC_API_ORIGIN: "https://api.invalid",
      KB_E2E_OBJECTS_ORIGIN: "https://objects.invalid",
      KB_E2E_ADMIN_EMAIL: "synthetic@example.invalid",
      KB_E2E_ADMIN_PASSWORD: "not-a-real-secret",
      KB_E2E_FAULT_CONTROL_ORIGIN: "https://fault.invalid",
      KB_E2E_FAULT_CONTROL_TOKEN: "not-a-real-token",
      KB_E2E_SEEDED_KNOWLEDGE_BASE_ID: "seeded",
      KB_E2E_UNSCOPED_KNOWLEDGE_BASE_ID: "unscoped",
      KB_E2E_MULTIPART_BYTES: "104857600",
      KB_E2E_SIGNING_KEY_PATH: "C:/trust/browser-e2e.pem",
      KB_E2E_CHALLENGE_PATH: "C:/trust/browser-challenge.json",
      KB_E2E_RUN_ID: "acceptance-run-20260714",
      KB_E2E_DOCUMENT_FIXTURE_ROOT: "C:/trust/document-fixtures",
      KB_E2E_DOCUMENT_FIXTURE_MANIFEST:
        "C:/trust/document-fixtures/document-fixtures-v1.json",
    };
    expect(REQUIRED_ENTERPRISE_ENV).toContain("KB_E2E_OBJECTS_ORIGIN");
    expect(REQUIRED_ENTERPRISE_ENV).toContain("KB_E2E_RUN_ID");
    expect(
      inspectEnterpriseConfig({ ...env, KB_E2E_OBJECTS_ORIGIN: undefined }).missing,
    ).toContain("KB_E2E_OBJECTS_ORIGIN");
    expect(inspectEnterpriseConfig(env)).toEqual({ missing: [], invalid: [] });
    expect(requireEnterpriseConfig(env).runId).toBe("acceptance-run-20260714");
    expect(
      inspectEnterpriseConfig({ ...env, KB_E2E_RUN_ID: "short" }).invalid,
    ).toContain("KB_E2E_RUN_ID");
    expect(requireEnterpriseConfig(env).objectsOrigin).toBe("https://objects.invalid");

    for (const unsafeOrigin of [
      "ftp://objects.invalid",
      "https://user:password@objects.invalid",
      "https://objects.invalid/path",
      "https://objects.invalid?",
      "https://objects.invalid#",
    ]) {
      expect(
        inspectEnterpriseConfig({ ...env, KB_E2E_OBJECTS_ORIGIN: unsafeOrigin }).invalid,
      ).toContain("KB_E2E_OBJECTS_ORIGIN");
    }

    expect(
      validateObjectDownloadUrl(
        "https://objects.invalid/bucket/report.pdf?signature=synthetic",
        env.KB_E2E_OBJECTS_ORIGIN,
      ),
    ).toBe("https://objects.invalid/bucket/report.pdf?signature=synthetic");
    for (const unsafeDownload of [
      "https://user:password@objects.invalid/bucket/report.pdf?signature=synthetic",
      "https://objects.invalid/bucket/report.pdf?signature=synthetic#fragment",
      "https://metadata.invalid/latest/meta-data",
      "file:///etc/passwd",
      "/relative/object",
    ]) {
      expect(() =>
        validateObjectDownloadUrl(unsafeDownload, env.KB_E2E_OBJECTS_ORIGIN),
      ).toThrow();
    }
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
      run_id: "acceptance-run-20260714",
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
    expect(Object.keys(evidence.target).sort()).toEqual([
      "content_fingerprint",
      "git_head",
      "run_id",
    ]);
    expect(evidence.target.run_id).toBe("acceptance-run-20260714");
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
    const wrongRun = {
      ...evidence,
      target: { ...evidence.target, run_id: "acceptance-run-20260715" },
    };
    expect(
      verify(
        null,
        signaturePayload(wrongRun, {
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
    const target = {
      git_head: "a".repeat(40),
      content_fingerprint: "b".repeat(64),
      run_id: "acceptance-run-20260714",
    };
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
        target: { ...target, run_id: "short" },
        artifacts: [validArtifact],
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
    const target = {
      git_head: "a".repeat(40),
      content_fingerprint: "b".repeat(64),
      run_id: "acceptance-run-20260714",
    };
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
      parseEvidenceChallenge(
        challenge,
        { ...target, run_id: "acceptance-run-20260715" },
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
