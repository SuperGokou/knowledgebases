import http from "k6/http";
import execution from "k6/execution";
import { check, sleep } from "k6";
import { SharedArray } from "k6/data";
import { Counter, Rate, Trend } from "k6/metrics";


const PROFILE = (__ENV.KB_LOAD_PROFILE || "smoke").trim();
const FORMAL = PROFILE === "formal";
const BASE_URL = (__ENV.KB_LOAD_BASE_URL || "").replace(/\/+$/, "");
const KNOWLEDGE_BASE_ID = (__ENV.KB_LOAD_KNOWLEDGE_BASE_ID || "").trim();
const USERS_FILE = (__ENV.KB_LOAD_USERS_FILE || "").trim();
const QUOTA_FILE = (__ENV.KB_LOAD_QUOTA_FILE || "").trim();
const MANIFEST_FILE = (__ENV.KB_LOAD_MANIFEST_FILE || "").trim();
const MANIFEST_SHA256 = (__ENV.KB_LOAD_MANIFEST_SHA256 || "").trim();
const CHAT_MODE = (__ENV.KB_LOAD_CHAT_MODE || "retrieval_only").trim();
const ISOLATED_ACCEPTANCE = (__ENV.KB_LOAD_ISOLATED_ACCEPTANCE || "0") === "1";
const MULTIPART_ENABLED = (__ENV.KB_LOAD_ENABLE_MULTIPART || "0") === "1";
const STEADY_DURATION = __ENV.KB_LOAD_STEADY_DURATION || (FORMAL ? "30m" : "20s");
const IDENTITY_MAX_DURATION = __ENV.KB_LOAD_IDENTITY_MAX_DURATION || (FORMAL ? "10m" : "30s");
const STEADY_START = __ENV.KB_LOAD_STEADY_START || (FORMAL ? "10m" : "30s");
const CONTROL_VUS = integerEnvironment("KB_LOAD_CONTROL_VUS", FORMAL ? 32 : 2, 1, 1_000);
const RETRIEVAL_VUS = integerEnvironment("KB_LOAD_RETRIEVAL_VUS", FORMAL ? 20 : 2, 1, 1_000);
const CHAT_RATE = integerEnvironment("KB_LOAD_CHAT_RATE", FORMAL ? 55 : 2, 1, 10_000);
const CHAT_PREALLOCATED_VUS = integerEnvironment(
  "KB_LOAD_CHAT_PREALLOCATED_VUS",
  FORMAL ? 64 : 4,
  1,
  5_000,
);
const CHAT_MAX_VUS = integerEnvironment(
  "KB_LOAD_CHAT_MAX_VUS",
  FORMAL ? 256 : 16,
  CHAT_PREALLOCATED_VUS,
  10_000,
);
const CONTROL_PAUSE_SECONDS = numberEnvironment(
  "KB_LOAD_CONTROL_PAUSE_SECONDS",
  FORMAL ? 1 : 0.2,
  0,
  60,
);
const RETRIEVAL_PAUSE_SECONDS = numberEnvironment(
  "KB_LOAD_RETRIEVAL_PAUSE_SECONDS",
  FORMAL ? 1 : 0.2,
  0,
  60,
);
const MULTIPART_SIZE_BYTES = integerEnvironment(
  "KB_LOAD_MULTIPART_SIZE_BYTES",
  100 * 1024 * 1024 + 1,
  FORMAL ? 100 * 1024 * 1024 + 1 : 5 * 1024 * 1024,
  1024 * 1024 * 1024,
);

const manifest = MANIFEST_FILE ? JSON.parse(open(MANIFEST_FILE)) : null;

validateConfiguration();

const evidenceBinding = manifest === null ? null : {
  manifest_sha256: MANIFEST_SHA256,
  run_id: manifest.run_id,
  project: manifest.project,
  git_commit: manifest.git_commit,
  compose_sha256: manifest.fingerprints?.compose_sha256,
  non_secret_config_sha256: manifest.fingerprints?.non_secret_config_sha256,
  host_sha256: manifest.fingerprints?.host_sha256,
  image_inventory_sha256: manifest.fingerprints?.image_inventory_sha256,
};

const users = new SharedArray("capacity-users", () => {
  const parsed = JSON.parse(open(USERS_FILE));
  if (!Array.isArray(parsed)) throw new Error("KB_LOAD_USERS_FILE must contain a JSON array");
  const normalized = parsed.map((item) => {
    if (
      item === null
      || typeof item !== "object"
      || typeof item.email !== "string"
      || typeof item.password !== "string"
      || !item.email.trim()
      || !item.password
    ) {
      throw new Error("each synthetic identity must contain non-empty email and password fields");
    }
    return { email: item.email.trim().toLowerCase(), password: item.password };
  });
  if (new Set(normalized.map((item) => item.email)).size !== normalized.length) {
    throw new Error("synthetic identity emails must be unique");
  }
  if (FORMAL && normalized.length < 1_000) {
    throw new Error("formal capacity acceptance requires at least 1000 unique identities");
  }
  return normalized;
});

const quotaConfiguration = QUOTA_FILE ? JSON.parse(open(QUOTA_FILE)) : null;

const identityAttempts = new Counter("identity_attempts");
const identitySuccesses = new Counter("identity_successes");
const controlPlaneLatency = new Trend("control_plane_latency", true);
const controlPlaneSuccess = new Rate("control_plane_success");
const retrievalLatency = new Trend("retrieval_latency", true);
const retrievalSuccess = new Rate("retrieval_success");
const stubRagLatency = new Trend("stub_rag_latency", true);
const stubRagSuccess = new Rate("stub_rag_success");
const backpressureSafe = new Rate("backpressure_safe");
const requestRateLimitContract = new Rate("request_rate_limit_contract");
const uploadLimitContract = new Rate("upload_limit_contract");
const downloadLimitContract = new Rate("download_limit_contract");
const unexpectedFiveXx = new Rate("unexpected_5xx");
const multipartAttempts = new Counter("multipart_attempts");
const multipartLatency = new Trend("multipart_latency", true);
const multipartSuccess = new Rate("multipart_success");

const scenarios = {
  identity_wave: {
    executor: "shared-iterations",
    exec: "identityWave",
    vus: FORMAL ? 64 : Math.min(users.length, 4),
    iterations: users.length,
    maxDuration: IDENTITY_MAX_DURATION,
    gracefulStop: "10s",
  },
  control_plane: {
    executor: "constant-vus",
    exec: "controlPlane",
    vus: CONTROL_VUS,
    duration: STEADY_DURATION,
    startTime: STEADY_START,
    gracefulStop: "15s",
  },
  retrieval: {
    executor: "constant-vus",
    exec: "retrieval",
    vus: RETRIEVAL_VUS,
    duration: STEADY_DURATION,
    startTime: STEADY_START,
    gracefulStop: "15s",
  },
};

if (CHAT_MODE === "stub") {
  scenarios.stub_rag = {
    executor: "constant-arrival-rate",
    exec: "stubRag",
    rate: CHAT_RATE,
    timeUnit: "1s",
    duration: STEADY_DURATION,
    startTime: STEADY_START,
    preAllocatedVUs: CHAT_PREALLOCATED_VUS,
    maxVUs: CHAT_MAX_VUS,
    gracefulStop: "30s",
  };
  scenarios.backpressure = {
    executor: "shared-iterations",
    exec: "backpressure",
    vus: FORMAL ? 8 : 2,
    iterations: FORMAL ? 80 : 4,
    maxDuration: FORMAL ? "2m" : "30s",
    startTime: STEADY_START,
    gracefulStop: "15s",
  };
}

if (quotaConfiguration !== null) {
  scenarios.quota_contracts = {
    executor: "shared-iterations",
    exec: "quotaContracts",
    vus: 1,
    iterations: 1,
    maxDuration: "3m",
    startTime: STEADY_START,
    gracefulStop: "10s",
  };
}
if (MULTIPART_ENABLED) {
  scenarios.multipart = {
    executor: "shared-iterations",
    exec: "multipartUpload",
    vus: FORMAL ? 8 : 1,
    iterations: FORMAL ? 8 : 1,
    maxDuration: FORMAL ? "10m" : "3m",
    startTime: STEADY_START,
    gracefulStop: "30s",
  };
}

const thresholds = {
  identity_successes: [`count>=${FORMAL ? 1_000 : users.length}`],
  control_plane_latency: ["p(95)<=500", "p(99)<=1500"],
  control_plane_success: ["rate>=0.999"],
  retrieval_latency: ["p(95)<=2000", "p(99)<=5000"],
  retrieval_success: ["rate>=0.999"],
  unexpected_5xx: ["rate<=0.001"],
};
if (CHAT_MODE === "stub") {
  thresholds.stub_rag_latency = ["p(95)<=5000", "p(99)<=10000"];
  thresholds.stub_rag_success = ["rate>=0.999"];
  thresholds.backpressure_safe = ["rate>=0.999"];
}
if (quotaConfiguration !== null) {
  thresholds.request_rate_limit_contract = ["rate==1"];
  thresholds.upload_limit_contract = ["rate==1"];
  thresholds.download_limit_contract = ["rate==1"];
}
if (MULTIPART_ENABLED) {
  thresholds.multipart_attempts = [`count>=${FORMAL ? 8 : 1}`];
  thresholds.multipart_latency = ["p(95)<=120000"];
  thresholds.multipart_success = ["rate==1"];
}

export const options = {
  scenarios,
  thresholds,
  noConnectionReuse: false,
  userAgent: "heyi-enterprise-capacity-gate/1.0",
  discardResponseBodies: false,
  setupTimeout: "30s",
  teardownTimeout: "30s",
  summaryTrendStats: ["min", "avg", "med", "p(90)", "p(95)", "p(99)", "max"],
};

let authenticatedEmail = null;

function integerEnvironment(name, fallback, minimum, maximum) {
  const raw = __ENV[name];
  const value = raw === undefined || raw === "" ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function numberEnvironment(name, fallback, minimum, maximum) {
  const raw = __ENV[name];
  const value = raw === undefined || raw === "" ? fallback : Number(raw);
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

function durationSeconds(value) {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value);
  if (!match) throw new Error(`unsupported k6 duration: ${value}`);
  const multiplier = { ms: 0.001, s: 1, m: 60, h: 3_600 }[match[2]];
  return Number(match[1]) * multiplier;
}

function validateConfiguration() {
  if (!USERS_FILE) throw new Error("KB_LOAD_USERS_FILE is required");
  if (!BASE_URL) throw new Error("KB_LOAD_BASE_URL is required");
  let parsed;
  try {
    parsed = new URL(BASE_URL);
  } catch {
    throw new Error("KB_LOAD_BASE_URL must be an absolute URL");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new Error("KB_LOAD_BASE_URL must be a credential-free origin");
  }
  if (parsed.protocol !== "https:") {
    if (FORMAL || __ENV.KB_LOAD_ALLOW_HTTP !== "1") {
      throw new Error("formal and default load tests require a trusted HTTPS origin");
    }
  }
  if (!/^[0-9a-fA-F-]{36}$/.test(KNOWLEDGE_BASE_ID)) {
    throw new Error("KB_LOAD_KNOWLEDGE_BASE_ID must be a UUID");
  }
  if (!new Set(["retrieval_only", "stub"]).has(CHAT_MODE)) {
    throw new Error("KB_LOAD_CHAT_MODE must be retrieval_only or stub");
  }
  if (FORMAL) {
    if (!ISOLATED_ACCEPTANCE) {
      throw new Error("formal load requires KB_LOAD_ISOLATED_ACCEPTANCE=1");
    }
    if (!MULTIPART_ENABLED) {
      throw new Error("formal load requires the disposable multipart scenario");
    }
    if (manifest === null || typeof manifest !== "object") {
      throw new Error("formal load requires KB_LOAD_MANIFEST_FILE");
    }
    if (!/^[0-9a-f]{64}$/.test(MANIFEST_SHA256)) {
      throw new Error("formal load requires an exact manifest SHA-256");
    }
    if (
      manifest.schema_version !== 1
      || manifest.classification !== "isolated_capacity_acceptance"
      || manifest.evidence_classification !== "not_model_capacity"
      || manifest.acceptance?.isolated !== true
      || manifest.acceptance?.cleanup_required !== true
      || manifest.secret_material_included !== false
      || manifest.identity_material_included !== false
    ) {
      throw new Error("formal load manifest is not isolated acceptance evidence");
    }
    if (
      typeof manifest.run_id !== "string"
      || manifest.project !== `heyi-kb-acceptance-${manifest.run_id}`
      || manifest.project === "heyi-kb-offline"
      || __ENV.KB_LOAD_ACCEPTANCE_PROJECT !== manifest.project
    ) {
      throw new Error("formal load project is not the manifest-bound acceptance project");
    }
    if (manifest.resource_sampling?.duration_seconds !== durationSeconds(STEADY_DURATION)) {
      throw new Error("k6 steady duration differs from the capacity manifest");
    }
    const exactDigests = [
      manifest.git_commit,
      manifest.fingerprints?.compose_sha256,
      manifest.fingerprints?.non_secret_config_sha256,
      manifest.fingerprints?.host_sha256,
      manifest.fingerprints?.image_inventory_sha256,
    ];
    if (!/^[0-9a-f]{40}$/.test(exactDigests[0])) {
      throw new Error("manifest git commit is not an exact revision");
    }
    if (!exactDigests.slice(1).every((value) => /^[0-9a-f]{64}$/.test(value))) {
      throw new Error("manifest fingerprints are incomplete");
    }
    if (!QUOTA_FILE) {
      throw new Error("formal multipart and quota checks require an external credential fixture");
    }
  }
  if (FORMAL && quotaConfigurationRequired() && !QUOTA_FILE) {
    throw new Error("formal quota acceptance requires KB_LOAD_QUOTA_FILE");
  }
}

function quotaConfigurationRequired() {
  return (__ENV.KB_LOAD_REQUIRE_QUOTA_CONTRACTS || "0") === "1";
}

function credential(index) {
  return users[index % users.length];
}

function currentCredential() {
  return credential(execution.vu.idInTest - 1);
}

function originHeaders(extra = {}) {
  return { Origin: BASE_URL, ...extra };
}

function responseJson(response) {
  try {
    return response.json();
  } catch {
    return null;
  }
}

function header(response, requestedName) {
  const lower = requestedName.toLowerCase();
  for (const [name, value] of Object.entries(response.headers)) {
    if (name.toLowerCase() === lower) return value;
  }
  return undefined;
}

function trackUnexpectedFiveXx(response, expectedStatuses = []) {
  const expected = expectedStatuses.includes(response.status);
  unexpectedFiveXx.add(response.status >= 500 && response.status <= 599 && !expected);
}

function login(identity, tag) {
  http.cookieJar().clear(BASE_URL);
  const response = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({ email: identity.email, password: identity.password }),
    {
      headers: originHeaders({ "Content-Type": "application/json" }),
      tags: { operation: tag },
      redirects: 0,
      timeout: "15s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(response);
  if (response.status !== 200) {
    authenticatedEmail = null;
    return false;
  }
  authenticatedEmail = identity.email;
  return true;
}

function ensureSession(identity, tag) {
  if (authenticatedEmail === identity.email) return true;
  return login(identity, tag);
}

function getMe(tag) {
  const response = http.get(`${BASE_URL}/api/backend/api/v1/auth/me`, {
    headers: { Accept: "application/json" },
    tags: { operation: tag },
    timeout: "15s",
    responseType: "text",
  });
  trackUnexpectedFiveXx(response);
  const body = responseJson(response);
  return response.status === 200 && body !== null && typeof body.id === "string";
}

export function identityWave() {
  const index = execution.scenario.iterationInTest;
  const identity = credential(index);
  identityAttempts.add(1);
  const authenticated = login(identity, "identity_login");
  const resolved = authenticated && getMe("identity_me");
  identitySuccesses.add(resolved ? 1 : 0);
  check(resolved, { "synthetic identity can login and resolve its principal": (value) => value });
}

export function controlPlane() {
  const identity = currentCredential();
  if (!ensureSession(identity, "control_login")) {
    controlPlaneSuccess.add(false);
    sleep(CONTROL_PAUSE_SECONDS);
    return;
  }
  const response = http.get(
    `${BASE_URL}/api/backend/api/v1/knowledge-bases?limit=50&offset=0`,
    {
      headers: { Accept: "application/json" },
      tags: { operation: "control_knowledge_catalog" },
      timeout: "15s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(response);
  const body = responseJson(response);
  const succeeded = response.status === 200 && Array.isArray(body);
  controlPlaneLatency.add(response.timings.duration);
  controlPlaneSuccess.add(succeeded);
  sleep(CONTROL_PAUSE_SECONDS);
}

export function retrieval() {
  const identity = currentCredential();
  if (!ensureSession(identity, "retrieval_login")) {
    retrievalSuccess.add(false);
    sleep(RETRIEVAL_PAUSE_SECONDS);
    return;
  }
  const response = http.post(
    `${BASE_URL}/api/backend/api/v1/knowledge-bases/${KNOWLEDGE_BASE_ID}/search`,
    JSON.stringify({ query: __ENV.KB_LOAD_SEARCH_QUERY || "企业 产品 信息", limit: 10 }),
    {
      headers: originHeaders({ "Content-Type": "application/json" }),
      tags: { operation: "knowledge_retrieval" },
      timeout: "15s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(response);
  const body = responseJson(response);
  const succeeded = response.status === 200 && body !== null && Array.isArray(body.items);
  retrievalLatency.add(response.timings.duration);
  retrievalSuccess.add(succeeded);
  sleep(RETRIEVAL_PAUSE_SECONDS);
}

function chatRequest(message, operation) {
  return http.post(
    `${BASE_URL}/api/backend/api/v1/chat/query`,
    JSON.stringify({ knowledge_base_id: KNOWLEDGE_BASE_ID, message, limit: 5 }),
    {
      headers: originHeaders({
        "Content-Type": "application/json",
        "Idempotency-Key": [
          "capacity",
          operation,
          execution.vu.idInTest,
          execution.scenario.iterationInTest,
          Date.now(),
        ].join("-"),
      }),
      tags: { operation },
      timeout: "115s",
      responseType: "text",
    },
  );
}

export function stubRag() {
  const identity = currentCredential();
  if (!ensureSession(identity, "stub_rag_login")) {
    stubRagSuccess.add(false);
    return;
  }
  const response = chatRequest(
    __ENV.KB_LOAD_CHAT_QUERY || "请根据企业知识说明核心产品",
    "stub_rag",
  );
  trackUnexpectedFiveXx(response);
  const body = responseJson(response);
  const succeeded = response.status === 200
    && body !== null
    && body.mode === "rag"
    && body.answer_review?.status === "passed"
    && body.source_status?.reason === "llm_generated"
    && Array.isArray(body.citations)
    && body.citations.length > 0;
  stubRagLatency.add(response.timings.duration);
  stubRagSuccess.add(succeeded);
}

export function backpressure() {
  const identity = currentCredential();
  if (!ensureSession(identity, "backpressure_login")) {
    backpressureSafe.add(false);
    return;
  }
  const query = (__ENV.KB_LOAD_BACKPRESSURE_QUERY || "企业 产品 信息")
    + " __capacity_stub_429__";
  const response = chatRequest(query, "stub_backpressure_429");
  trackUnexpectedFiveXx(response, [503]);
  const body = responseJson(response);
  const safeFallback = response.status === 200
    && body !== null
    && body.mode !== "rag"
    && new Set([
      "provider_unavailable",
      "usage_governance_unavailable",
      "usage_metering_unavailable",
    ]).has(body.source_status?.reason);
  const boundedRejection = response.status === 429 || response.status === 503;
  backpressureSafe.add((safeFallback || boundedRejection) && response.timings.duration <= 10_000);
}

function requireQuotaIdentity(name) {
  const value = quotaConfiguration?.[name];
  if (
    value === null
    || typeof value !== "object"
    || typeof value.email !== "string"
    || typeof value.password !== "string"
  ) {
    throw new Error(`quota configuration is missing ${name} identity`);
  }
  return value;
}

function rateLimitQuotaContract() {
  const value = requireQuotaIdentity("rate_limit");
  if (!Number.isInteger(value.expected_limit) || value.expected_limit < 1 || value.expected_limit > 100) {
    return false;
  }
  if (!login(value, "quota_rate_login")) return false;
  let observed429 = false;
  let observedLimit = false;
  for (let index = 0; index < value.expected_limit + 3; index += 1) {
    const response = http.get(
      `${BASE_URL}/api/backend/api/v1/knowledge-bases?limit=1&offset=0`,
      { tags: { operation: "quota_rate_probe" }, timeout: "15s", responseType: "text" },
    );
    trackUnexpectedFiveXx(response);
    observed429 = observed429 || response.status === 429;
    observedLimit = observedLimit || Number(header(response, "X-RateLimit-Limit")) === value.expected_limit;
  }
  return observed429 && observedLimit;
}

function uploadQuotaContract() {
  const value = requireQuotaIdentity("upload_limit");
  if (!Number.isInteger(value.max_upload_bytes) || value.max_upload_bytes < 1) return false;
  if (!login(value, "quota_upload_login")) return false;
  const response = http.post(
    `${BASE_URL}/api/backend/api/v1/files/uploads`,
    JSON.stringify({
      filename: "capacity-quota.txt",
      size_bytes: value.max_upload_bytes + 1,
      content_type: "text/plain",
      idempotency_key: `capacity-quota-${Date.now()}`,
      knowledge_base_id: KNOWLEDGE_BASE_ID,
      custom_metadata: {},
    }),
    {
      headers: originHeaders({ "Content-Type": "application/json" }),
      tags: { operation: "quota_upload_probe" },
      timeout: "15s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(response);
  const body = responseJson(response);
  return response.status === 413 && body?.error?.code === "file_policy_violation";
}

function downloadQuotaContract() {
  const value = requireQuotaIdentity("download_limit");
  if (
    !Number.isInteger(value.daily_limit)
    || value.daily_limit < 1
    || value.daily_limit > 100
    || typeof value.file_id !== "string"
  ) return false;
  if (!login(value, "quota_download_login")) return false;
  let observed429 = false;
  for (let index = 0; index < value.daily_limit + 1; index += 1) {
    const response = http.post(
      `${BASE_URL}/api/backend/api/v1/files/${value.file_id}/download`,
      null,
      {
        headers: originHeaders(),
        tags: { operation: "quota_download_probe" },
        timeout: "15s",
        responseType: "text",
      },
    );
    trackUnexpectedFiveXx(response);
    const body = responseJson(response);
    observed429 = observed429 || (
      response.status === 429 && body?.error?.code === "quota_exceeded"
    );
  }
  return observed429;
}

export function quotaContracts() {
  requestRateLimitContract.add(rateLimitQuotaContract());
  uploadLimitContract.add(uploadQuotaContract());
  downloadLimitContract.add(downloadQuotaContract());
}

const multipartBodies = new Map();

function bodyWithSize(sizeBytes) {
  let body = multipartBodies.get(sizeBytes);
  if (body === undefined) {
    body = new Uint8Array(sizeBytes).buffer;
    multipartBodies.set(sizeBytes, body);
  }
  return body;
}

function multipartFlow() {
  const identity = requireQuotaIdentity("multipart");
  if (!login(identity, "multipart_login")) return false;
  const runId = manifest?.run_id || "smoke";
  const suffix = [runId, execution.vu.idInTest, execution.scenario.iterationInTest].join("-");
  const initiate = http.post(
    `${BASE_URL}/api/backend/api/v1/files/uploads`,
    JSON.stringify({
      filename: `capacity-${suffix}.txt`,
      size_bytes: MULTIPART_SIZE_BYTES,
      content_type: "text/plain",
      idempotency_key: `capacity-multipart-${suffix}`,
      knowledge_base_id: KNOWLEDGE_BASE_ID,
      custom_metadata: {
        capacity_run_id: runId,
        evidence_classification: "not_model_capacity",
      },
    }),
    {
      headers: originHeaders({ "Content-Type": "application/json" }),
      tags: { operation: "multipart_initiate" },
      timeout: "30s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(initiate);
  const initiated = responseJson(initiate);
  if (
    initiate.status !== 201
    || initiated?.mode !== "multipart"
    || typeof initiated.upload_session_id !== "string"
    || !Number.isInteger(initiated.part_count)
    || initiated.part_count < 2
    || initiated.part_count > 100
  ) return false;

  const partNumbers = Array.from({ length: initiated.part_count }, (_value, index) => index + 1);
  const urlsResponse = http.post(
    `${BASE_URL}/api/backend/api/v1/files/uploads/${initiated.upload_session_id}/parts`,
    JSON.stringify({ part_numbers: partNumbers }),
    {
      headers: originHeaders({ "Content-Type": "application/json" }),
      tags: { operation: "multipart_part_urls" },
      timeout: "30s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(urlsResponse);
  const urls = responseJson(urlsResponse);
  if (urlsResponse.status !== 200 || !Array.isArray(urls?.parts)) return false;

  const completedParts = [];
  for (const part of urls.parts) {
    if (
      !Number.isInteger(part?.part_number)
      || !Number.isInteger(part?.size_bytes)
      || part.size_bytes < 1
      || typeof part?.url !== "string"
    ) return false;
    const uploaded = http.put(part.url, bodyWithSize(part.size_bytes), {
      tags: { operation: "multipart_part_put" },
      timeout: "120s",
      responseType: "text",
    });
    trackUnexpectedFiveXx(uploaded);
    const etag = header(uploaded, "ETag");
    if (uploaded.status !== 200 || typeof etag !== "string" || !etag) return false;
    completedParts.push({ part_number: part.part_number, etag });
  }

  const complete = http.post(
    `${BASE_URL}/api/backend/api/v1/files/uploads/${initiated.upload_session_id}/complete`,
    JSON.stringify({ parts: completedParts }),
    {
      headers: originHeaders({ "Content-Type": "application/json" }),
      tags: { operation: "multipart_complete" },
      timeout: "120s",
      responseType: "text",
    },
  );
  trackUnexpectedFiveXx(complete);
  const completed = responseJson(complete);
  return complete.status === 200
    && completed?.id === initiated.file_id
    && completed?.size_bytes === MULTIPART_SIZE_BYTES;
}

export function multipartUpload() {
  multipartAttempts.add(1);
  const started = Date.now();
  let succeeded = false;
  try {
    succeeded = multipartFlow();
  } finally {
    multipartLatency.add(Date.now() - started);
    multipartSuccess.add(succeeded);
  }
}

function normalizedMetric(data, name) {
  const values = data.metrics[name]?.values || {};
  return {
    count: values.count ?? null,
    rate: values.rate ?? null,
    p95: values["p(95)"] ?? null,
    p99: values["p(99)"] ?? null,
  };
}

export function handleSummary(data) {
  const metricNames = [
    "identity_attempts",
    "identity_successes",
    "control_plane_latency",
    "control_plane_success",
    "retrieval_latency",
    "retrieval_success",
    "unexpected_5xx",
  ];
  if (CHAT_MODE === "stub") {
    metricNames.push("stub_rag_latency", "stub_rag_success", "backpressure_safe");
  }
  if (quotaConfiguration !== null) {
    metricNames.push(
      "request_rate_limit_contract",
      "upload_limit_contract",
      "download_limit_contract",
    );
  }
  if (MULTIPART_ENABLED) {
    metricNames.push("multipart_attempts", "multipart_latency", "multipart_success");
  }
  const metrics = Object.fromEntries(metricNames.map((name) => [name, normalizedMetric(data, name)]));
  const thresholdsPassed = Object.values(data.metrics).every((metric) => (
    metric.thresholds === undefined
    || Object.values(metric.thresholds).every((threshold) => threshold.ok)
  ));
  const summary = {
    schema_version: 1,
    profile: PROFILE,
    classification: "not_model_capacity",
    isolated_acceptance: ISOLATED_ACCEPTANCE,
    credential_material_included: false,
    evidence_binding: evidenceBinding,
    configuration: {
      identity_count: users.length,
      steady_duration_seconds: durationSeconds(STEADY_DURATION),
      identity_max_duration_seconds: durationSeconds(IDENTITY_MAX_DURATION),
      steady_start_seconds: durationSeconds(STEADY_START),
      control_vus: CONTROL_VUS,
      retrieval_vus: RETRIEVAL_VUS,
      chat_mode: CHAT_MODE,
      stub_chat_arrival_rate_per_second: CHAT_MODE === "stub" ? CHAT_RATE : null,
      quota_contracts_enabled: quotaConfiguration !== null,
      multipart_enabled: MULTIPART_ENABLED,
      multipart_size_bytes: MULTIPART_ENABLED ? MULTIPART_SIZE_BYTES : null,
      multipart_concurrency: MULTIPART_ENABLED ? (FORMAL ? 8 : 1) : null,
    },
    metrics,
    k6_thresholds_passed: thresholdsPassed,
    run_duration_ms: data.state?.testRunDurationMs ?? null,
    explicit_non_claims: [
      "No stub result certifies five billion real tokens per day.",
      "No 300 GB run certifies a ten-terabyte storage cluster.",
      "No request count certifies model quality, provider quota, residency, or cost.",
    ],
  };
  return {
    stdout: `${JSON.stringify({ verdict: thresholdsPassed ? "K6_THRESHOLDS_PASS" : "K6_THRESHOLDS_FAIL" })}\n`,
    "capacity-k6-summary.json": `${JSON.stringify(summary, null, 2)}\n`,
  };
}
