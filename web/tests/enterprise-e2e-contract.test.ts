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
  LOCAL_MOCK_AUTH_BACKEND_URL,
  resolveEnterpriseTestTimeoutMs,
  resolveWebServerConfig,
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
const signingKeyPath = path.resolve("trust", "browser-e2e.pem");
const challengePath = path.resolve("trust", "browser-challenge.json");
const enterpriseFixtures = readFileSync(
  path.join(process.cwd(), "e2e/support/enterprise-fixtures.ts"),
  "utf8",
);
const enterpriseBusinessSpec = readFileSync(
  path.join(process.cwd(), "e2e/enterprise-business.spec.ts"),
  "utf8",
);
const enterpriseConfigSource = readFileSync(
  path.join(process.cwd(), "e2e/support/enterprise-config.ts"),
  "utf8",
);
const standaloneLauncherSource = readFileSync(
  path.join(process.cwd(), "e2e/support/start-standalone.mjs"),
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

  test("requires a real bounded audit dataset, safe CSV and fail-closed permission revocation", () => {
    expect(REQUIRED_CHECKS).toContain("audit_log_query_export");
    expect(enterpriseBusinessSpec).toContain(
      'annotate(testInfo, "audit_log_query_export")',
    );
    expect(enterpriseBusinessSpec).toContain("requireAuditFixturePage(");
    expect(enterpriseBusinessSpec).toContain("enterprise.auditPageAction,");
    expect(enterpriseBusinessSpec).toContain("50,");
    expect(enterpriseBusinessSpec).toContain("5,");
    expect(enterpriseBusinessSpec).toContain("csvRows).toHaveLength(56)");
    expect(enterpriseBusinessSpec).toContain("csvRow.length === 8");
    expect(enterpriseBusinessSpec).toContain("Buffer.from([0xef, 0xbb, 0xbf])");
    expect(enterpriseBusinessSpec).toContain('not.toContain("details")');
    expect(enterpriseBusinessSpec).toContain('not.toContain("ip_address")');
    expect(enterpriseBusinessSpec).toContain("enterprise.auditRedactionSentinel");
    expect(enterpriseBusinessSpec).toContain(
      "E2E_BLOCKED: dedicated >5000 audit fixture is unavailable",
    );
    expect(enterpriseBusinessSpec).toContain(
      "E2E_BLOCKED: dedicated >5000 audit fixture does not exceed the export limit",
    );
    expect(enterpriseBusinessSpec).toContain('response.status() === 403');
    expect(enterpriseBusinessSpec).toContain('name: "重试导出"');
    expect(enterpriseBusinessSpec).not.toContain("page.route(");
  });

  test("requires a successful grounded answer from every configured model provider", () => {
    for (const check of [
      "model_deepseek_success",
      "model_qwen_success",
      "model_minimax_success",
    ]) {
      expect(REQUIRED_CHECKS).toContain(check);
      expect(enterpriseBusinessSpec).toContain(`annotate(testInfo, "${check}")`);
    }
    expect(enterpriseBusinessSpec).toContain("expect(generatedBody.provider).toBe(provider)");
    expect(enterpriseBusinessSpec).toContain(
      "expect(generatedBody.model).toBe(configuredProvider.model)",
    );
    expect(enterpriseBusinessSpec).toContain('expect(generatedBody.mode).toBe("rag")');
    expect(enterpriseBusinessSpec).toContain('reason: "semantic_verified"');
    expect(enterpriseBusinessSpec).toContain('reason: "llm_generated"');
    expect(enterpriseBusinessSpec).toContain(
      "expect(sourceStatus.citation_count).toBe(citations.length)",
    );
    expect(enterpriseBusinessSpec).toContain(
      "expect(restoredBody.default_provider).toBe(original.provider)",
    );
  });

  test("supports short-lived TLS leaves and binds renewal claims to formal host evidence", () => {
    for (const check of [
      "tls_ca_trust",
      "tls_san_identity",
      "tls_validity_and_renewal",
      "tls_strict_client",
    ]) {
      expect(REQUIRED_CHECKS).toContain(check);
      expect(enterpriseBusinessSpec).toContain(`annotate(testInfo, "${check}")`);
    }
    expect(enterpriseBusinessSpec).toContain('["web", enterprise.baseUrl]');
    expect(enterpriseBusinessSpec).toContain('["api", enterprise.publicApiOrigin]');
    expect(enterpriseBusinessSpec).toContain('["objects", enterprise.objectsOrigin]');
    expect(enterpriseBusinessSpec).toContain("await probeEnterpriseTlsOrigin(origin)");
    expect(enterpriseConfigSource).toContain("rejectUnauthorized: true");
    expect(enterpriseConfigSource).toContain('minVersion: "TLSv1.2"');
    expect(enterpriseConfigSource).toContain('maxVersion: "TLSv1.3"');
    expect(enterpriseConfigSource).toContain("checkServerIdentity(hostname, certificate)");
    expect(enterpriseConfigSource).toContain("certificate.subjectaltname?.trim()");
    expect(enterpriseConfigSource).toContain("MINIMUM_TLS_REMAINING_VALIDITY_MS");
    expect(enterpriseConfigSource).toContain("MAXIMUM_TLS_NOT_BEFORE_SKEW_MS");
    expect(enterpriseConfigSource).toContain("issuerCertificate");
    expect(enterpriseConfigSource).not.toContain("30 * 24 * 60 * 60 * 1_000");
    expect(enterpriseConfigSource).toContain("scheduler.schedule(() =>");
    expect(enterpriseConfigSource).toContain("const closedSockets = new WeakSet<object>()");
    expect(enterpriseConfigSource).not.toContain("socket.setTimeout(");
    expect(enterpriseConfigSource).not.toContain("queueMicrotask(");
    expect(enterpriseBusinessSpec).toContain('evidence_id: "EXT-LINUX-HOST-001"');
    expect(enterpriseBusinessSpec).toContain(
      'assertion_source: "formal_host_evidence_not_socket_probe"',
    );
    expect(enterpriseBusinessSpec).toContain('"caddy_ca_persistent_storage"');
    expect(enterpriseBusinessSpec).toContain('"caddy_renewal_health"');
  });

  test("approves converted files through the visible file-center control", () => {
    expect(enterpriseBusinessSpec).toContain('name: `审批文件：${fixture.filename}`');
    expect(enterpriseBusinessSpec).toContain("await approveButton.click()");
    expect(enterpriseBusinessSpec).toContain("approve ${fixture.extension} through UI");
    expect(enterpriseBusinessSpec).not.toMatch(
      /bffRequest\(\s*page,\s*`\/api\/v1\/files\/\$\{String\(file\.id\)\}\/approve`/,
    );
  });

  test("downloads every approved fixture through the visible file-center control", () => {
    expect(enterpriseBusinessSpec).toContain(
      'fileRow.getByRole("button", { name: "下载", exact: true })',
    );
    expect(enterpriseBusinessSpec).toContain("await downloadButton.click()");
    expect(enterpriseBusinessSpec).toContain('page.waitForEvent("download")');
    expect(enterpriseBusinessSpec).toContain(
      "const observedObjectUrl = validateObjectDownloadUrl(",
    );
    expect(enterpriseBusinessSpec).toContain("objectResponse.url(),");
    expect(enterpriseBusinessSpec).toContain("browserDownload.createReadStream()");
    expect(enterpriseBusinessSpec).not.toMatch(
      /request\.get\(downloadUrl/,
    );
  });

  test("renders real 401, 403, backend failure and timeout states with retry controls", () => {
    expect(enterpriseBusinessSpec).not.toContain("page.route(");
    expect(enterpriseBusinessSpec).toContain('verifyVisibleBackendFailure("backend_5xx", 503)');
    expect(enterpriseBusinessSpec).toContain('verifyVisibleBackendFailure("backend_timeout", 504)');
    expect(enterpriseBusinessSpec).toContain('response.status() === 403');
    expect(enterpriseBusinessSpec).toContain('response.status() === 401');
    expect(enterpriseBusinessSpec).toContain(
      'forbiddenAlert.getByRole("button", { name: "重试" })',
    );
    expect(enterpriseBusinessSpec).toContain(
      'unauthorizedAlert.getByRole("button", { name: "重试" })',
    );
    expect(enterpriseBusinessSpec).toContain(
      'alert.getByRole("button", { name: "重试" }).click()',
    );
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
        KB_E2E_SIGNING_KEY_PATH: signingKeyPath,
        KB_E2E_CHALLENGE_PATH: challengePath,
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
    expect(enterprise.signingKeyPath).toBe(signingKeyPath);
    expect(enterprise.challengePath).toBe(challengePath);
    expect(
      enterprise.evidenceOutput
        .replaceAll("\\", "/")
        .endsWith("/artifacts/acceptance/functional/browser-e2e.json"),
    ).toBe(true);
  });

  test("runs smoke through the production standalone server and keeps mocks local-only", () => {
    expect(resolveWebServerConfig(true)).toBeUndefined();
    const localServers = resolveWebServerConfig(false);
    expect(localServers).toHaveLength(2);
    expect(localServers?.[0]).toMatchObject({
      command: "node e2e/support/mock-auth-backend.mjs",
      url: `${LOCAL_MOCK_AUTH_BACKEND_URL}/healthz`,
      reuseExistingServer: false,
    });
    expect(localServers?.[1]).toMatchObject({
      command: "npm run build && node e2e/support/start-standalone.mjs",
      reuseExistingServer: false,
      env: {
        FASTAPI_URL: LOCAL_MOCK_AUTH_BACKEND_URL,
        HOSTNAME: "127.0.0.1",
        PORT: "3100",
      },
    });
    expect(localServers?.[1]?.command).not.toContain("next start");
    expect(standaloneLauncherSource).toContain('path.join(standaloneRoot, "server.js")');
    expect(standaloneLauncherSource).toContain("cp(publicSource, publicTarget");
    expect(standaloneLauncherSource).toContain("cp(staticSource, staticTarget");
    expect(standaloneLauncherSource).toContain("process.chdir(standaloneRoot)");
    expect(standaloneLauncherSource).toContain("await import(pathToFileURL(serverEntry).href)");
  });

  test("keeps formal collection policy, runtime profile, and evidence reporter projects aligned", () => {
    const enterprise = resolvePlaywrightProfile(
      { KB_E2E_PROFILE: "enterprise" },
      path.resolve(process.cwd()),
    );
    const runtimeProjects = enterprise.projects.map((project) => project.name);
    const reporterProjects = [...REQUIRED_PROJECTS];

    for (const contract of readFormalBrowserCollectionContracts()) {
      expect(contract.expected_collected_tests).toBe(26);
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
      KB_E2E_SIGNING_KEY_PATH: signingKeyPath,
      KB_E2E_CHALLENGE_PATH: challengePath,
      KB_E2E_RUN_ID: "acceptance-run-20260714",
      KB_E2E_AUDIT_PAGE_ACTION: "e2e.audit.page.fixture",
      KB_E2E_AUDIT_OVERSIZED_ACTION: "e2e.audit.oversized.fixture",
      KB_E2E_AUDIT_REDACTION_SENTINEL: "E2E_REDACT_SENTINEL",
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
      KB_E2E_SIGNING_KEY_PATH: signingKeyPath,
      KB_E2E_CHALLENGE_PATH: challengePath,
      KB_E2E_RUN_ID: "acceptance-run-20260714",
      KB_E2E_AUDIT_PAGE_ACTION: "e2e.audit.page.fixture",
      KB_E2E_AUDIT_OVERSIZED_ACTION: "e2e.audit.oversized.fixture",
      KB_E2E_AUDIT_REDACTION_SENTINEL: "E2E_REDACT_SENTINEL",
      KB_E2E_DOCUMENT_FIXTURE_ROOT: "C:/trust/document-fixtures",
      KB_E2E_DOCUMENT_FIXTURE_MANIFEST:
        "C:/trust/document-fixtures/document-fixtures-v1.json",
    };
    expect(REQUIRED_ENTERPRISE_ENV).toContain("KB_E2E_OBJECTS_ORIGIN");
    expect(REQUIRED_ENTERPRISE_ENV).toContain("KB_E2E_RUN_ID");
    expect(REQUIRED_ENTERPRISE_ENV).toContain("KB_E2E_AUDIT_PAGE_ACTION");
    expect(REQUIRED_ENTERPRISE_ENV).toContain("KB_E2E_AUDIT_OVERSIZED_ACTION");
    expect(
      inspectEnterpriseConfig({ ...env, KB_E2E_OBJECTS_ORIGIN: undefined }).missing,
    ).toContain("KB_E2E_OBJECTS_ORIGIN");
    expect(inspectEnterpriseConfig(env)).toEqual({ missing: [], invalid: [] });
    expect(requireEnterpriseConfig(env).runId).toBe("acceptance-run-20260714");
    expect(
      inspectEnterpriseConfig({ ...env, KB_E2E_RUN_ID: "short" }).invalid,
    ).toContain("KB_E2E_RUN_ID");
    expect(requireEnterpriseConfig(env).objectsOrigin).toBe("https://objects.invalid");

    for (const loopbackOrigin of [
      "http://127.0.0.1:3198",
      "http://127.255.10.9:3198",
      "http://localhost:3198",
      "http://[::1]:3198",
    ]) {
      expect(
        inspectEnterpriseConfig({ ...env, KB_E2E_FAULT_CONTROL_ORIGIN: loopbackOrigin }),
      ).toEqual({ missing: [], invalid: [] });
    }
    for (const plaintextOrigin of [
      "http://fault.invalid",
      "http://10.0.14.55:3198",
      "http://192.168.1.10:3198",
      "http://0.0.0.0:3198",
    ]) {
      expect(
        inspectEnterpriseConfig({ ...env, KB_E2E_FAULT_CONTROL_ORIGIN: plaintextOrigin }).invalid,
      ).toContain("KB_E2E_FAULT_CONTROL_ORIGIN");
      expect(() =>
        requireEnterpriseConfig({ ...env, KB_E2E_FAULT_CONTROL_ORIGIN: plaintextOrigin }),
      ).toThrow(/KB_E2E_FAULT_CONTROL_ORIGIN/);
    }
    const faultControlSource = enterpriseBusinessSpec.slice(
      enterpriseBusinessSpec.indexOf("async function setFaultMode"),
      enterpriseBusinessSpec.indexOf("async function uploadMultipartFixture"),
    );
    expect(faultControlSource).toContain(
      "headers: { authorization: `Bearer ${enterprise.faultControlToken}` }",
    );
    expect(faultControlSource).toContain("data: { mode }");
    expect(faultControlSource).not.toContain("faultControlToken}/");
    expect(faultControlSource).not.toContain("data: { mode, token");

    for (const unsafeOrigin of [
      "http://objects.invalid",
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
    for (const name of ["KB_E2E_BASE_URL", "KB_E2E_PUBLIC_API_ORIGIN"] as const) {
      expect(inspectEnterpriseConfig({ ...env, [name]: "http://plain.invalid" }).invalid)
        .toContain(name);
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
