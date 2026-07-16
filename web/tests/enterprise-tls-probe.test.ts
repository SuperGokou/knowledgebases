import type { ConnectionOptions, DetailedPeerCertificate } from "node:tls";

import { describe, expect, test } from "vitest";

import {
  probeEnterpriseTlsOrigin,
  validateEnterpriseTlsEvidence,
  type EnterpriseTlsConnector,
  type EnterpriseTlsDeadlineScheduler,
  type EnterpriseTlsProbeSocket,
} from "../e2e/support/enterprise-config";

const DAY_MS = 24 * 60 * 60 * 1_000;
const NOW_MS = Date.parse("2026-07-15T12:00:00.000Z");

function certificate({
  hostname = "kb.example.test",
  remainingValidityMs = 365 * DAY_MS,
  validFromOffsetMs = -5 * 60 * 1_000,
  includeSan = true,
  includeIssuerChain = true,
}: {
  readonly hostname?: string;
  readonly remainingValidityMs?: number;
  readonly validFromOffsetMs?: number;
  readonly includeSan?: boolean;
  readonly includeIssuerChain?: boolean;
} = {}): DetailedPeerCertificate {
  const issuerCertificate = {
    subject: { CN: "E2E Issuing CA" },
    issuer: { CN: "E2E Root CA" },
    valid_from: new Date(NOW_MS - DAY_MS).toUTCString(),
    valid_to: new Date(NOW_MS + 1_000 * DAY_MS).toUTCString(),
  } as unknown as DetailedPeerCertificate;
  issuerCertificate.issuerCertificate = issuerCertificate;
  return {
    ...(includeSan ? { subjectaltname: `DNS:${hostname}` } : {}),
    subject: { CN: hostname },
    issuer: { CN: "E2E Issuing CA" },
    valid_from: new Date(NOW_MS + validFromOffsetMs).toUTCString(),
    valid_to: new Date(NOW_MS + remainingValidityMs).toUTCString(),
    ...(includeIssuerChain ? { issuerCertificate } : {}),
  } as unknown as DetailedPeerCertificate;
}

class ManualDeadlineScheduler implements EnterpriseTlsDeadlineScheduler {
  private callback: (() => void) | undefined;
  private readonly handle = Object.freeze({ kind: "hard-deadline" });
  scheduledTimeoutMs: number | undefined;
  cancelCalls = 0;

  schedule(callback: () => void, timeoutMs: number): unknown {
    this.callback = callback;
    this.scheduledTimeoutMs = timeoutMs;
    return this.handle;
  }

  cancel(handle: unknown): void {
    expect(handle).toBe(this.handle);
    this.cancelCalls += 1;
  }

  fire(): void {
    if (!this.callback) throw new Error("deadline callback is unavailable");
    this.callback();
  }
}

class FakeTlsSocket implements EnterpriseTlsProbeSocket {
  private errorCallback: ((error: Error) => void) | undefined;
  endCalls = 0;
  destroyCalls = 0;

  constructor(
    readonly authorized: boolean,
    private readonly peerCertificate: DetailedPeerCertificate,
    private readonly protocol: string | null,
  ) {}

  getPeerCertificate(): DetailedPeerCertificate {
    return this.peerCertificate;
  }

  getProtocol(): string | null {
    return this.protocol;
  }

  once(event: "error", callback: (error: Error) => void): this {
    expect(event).toBe("error");
    this.errorCallback = callback;
    return this;
  }

  end(): this {
    this.endCalls += 1;
    return this;
  }

  destroy(): this {
    this.destroyCalls += 1;
    return this;
  }

  fireError(error = new Error("private network details")): void {
    this.errorCallback?.(error);
  }

  emitDripActivity(): void {
    // Deliberately inert: traffic must not reset the independent wall-clock deadline.
  }
}

function connectorHarness(socket: FakeTlsSocket): {
  readonly connector: EnterpriseTlsConnector;
  readonly options: () => ConnectionOptions;
  readonly secure: () => void;
} {
  let observedOptions: ConnectionOptions | undefined;
  let onSecureConnect: ((connectedSocket: EnterpriseTlsProbeSocket) => void) | undefined;
  return {
    connector(options, callback) {
      observedOptions = options;
      onSecureConnect = callback;
      return socket;
    },
    options() {
      if (!observedOptions) throw new Error("connector was not called");
      return observedOptions;
    },
    secure() {
      if (!onSecureConnect) throw new Error("secure callback is unavailable");
      onSecureConnect(socket);
    },
  };
}

describe("enterprise TLS evidence", () => {
  test("accepts a trusted Caddy-style 12-hour leaf with a safe renewal window", () => {
    expect(
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate({ remainingValidityMs: 12 * 60 * 60 * 1_000 }),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toEqual({
      ca_trusted: true,
      san_identity: true,
      currently_valid: true,
      issuer_chain_present: true,
      remaining_validity_seconds: 12 * 60 * 60,
      certificate_lifetime_seconds: 12 * 60 * 60 + 5 * 60,
      protocol: "TLSv1.3",
    });
    expect(
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate(),
        "TLSv1.2",
        NOW_MS,
      ).protocol,
    ).toBe("TLSv1.2");
  });

  test("rejects unsafe identity, validity, lifetime, issuer chain, and protocol", () => {
    expect(() =>
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate({ includeSan: false }),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toThrow("TLS SAN identity mismatch");
    expect(() =>
      validateEnterpriseTlsEvidence(
        "other.example.test",
        certificate(),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toThrow("TLS SAN identity mismatch");
    expect(() =>
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate({ remainingValidityMs: 59 * 60 * 1_000 }),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toThrow("less than one hour");
    expect(() =>
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate({ validFromOffsetMs: 6 * 60 * 1_000 }),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toThrow("clock-skew allowance");
    expect(() =>
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate({ remainingValidityMs: 399 * DAY_MS }),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toThrow("lifetime is outside the safe range");
    expect(() =>
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate({ includeIssuerChain: false }),
        "TLSv1.3",
        NOW_MS,
      ),
    ).toThrow("issuer chain is unavailable");
    expect(() =>
      validateEnterpriseTlsEvidence(
        "kb.example.test",
        certificate(),
        "TLSv1.1",
        NOW_MS,
      ),
    ).toThrow("TLS 1.2 or TLS 1.3");
  });

  test("requires platform CA authorization, SNI, and TLS 1.2 through 1.3", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const harness = connectorHarness(socket);
    const pending = probeEnterpriseTlsOrigin(
      "https://kb.example.test:9443",
      2_000,
      harness.connector,
      scheduler,
    );
    harness.secure();

    await expect(pending).resolves.toMatchObject({ ca_trusted: true, san_identity: true });
    expect(harness.options()).toMatchObject({
      host: "kb.example.test",
      port: 9443,
      servername: "kb.example.test",
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.3",
    });
    expect(scheduler.scheduledTimeoutMs).toBe(2_000);
    expect(scheduler.cancelCalls).toBe(1);
    expect(socket.endCalls).toBe(1);
    expect(socket.destroyCalls).toBe(0);
  });

  test("fails closed when neither secure nor error events ever arrive", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const harness = connectorHarness(socket);
    const pending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      harness.connector,
      scheduler,
    );
    const assertion = expect(pending).rejects.toThrow(
      "E2E_BLOCKED: TLS identity probe timed out",
    );

    scheduler.fire();
    await assertion;
    expect(socket.destroyCalls).toBe(1);
    expect(socket.endCalls).toBe(0);
    expect(scheduler.cancelCalls).toBe(1);
  });

  test("drip activity cannot extend the hard wall-clock deadline", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const harness = connectorHarness(socket);
    const pending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      harness.connector,
      scheduler,
    );
    const assertion = expect(pending).rejects.toThrow("TLS identity probe timed out");

    for (let index = 0; index < 100; index += 1) socket.emitDripActivity();
    scheduler.fire();
    socket.fireError(new Error("https://secret.internal/path?token=credential"));
    harness.secure();

    await assertion;
    expect(socket.destroyCalls).toBe(1);
    expect(socket.endCalls).toBe(0);
  });

  test("settles once for deadline-first and error-first races", async () => {
    const deadlineSocket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const deadlineScheduler = new ManualDeadlineScheduler();
    const deadlineHarness = connectorHarness(deadlineSocket);
    const deadlinePending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      deadlineHarness.connector,
      deadlineScheduler,
    );
    const deadlineAssertion = expect(deadlinePending).rejects.toThrow("timed out");
    deadlineScheduler.fire();
    deadlineSocket.fireError();
    deadlineHarness.secure();
    await deadlineAssertion;
    expect(deadlineSocket.destroyCalls).toBe(1);

    const errorSocket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const errorScheduler = new ManualDeadlineScheduler();
    const errorHarness = connectorHarness(errorSocket);
    const errorPending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      errorHarness.connector,
      errorScheduler,
    );
    const errorAssertion = expect(errorPending).rejects.toThrow(
      "E2E_BLOCKED: TLS certificate validation failed",
    );
    errorSocket.fireError(new Error("https://secret.internal/path?token=credential"));
    errorScheduler.fire();
    errorHarness.secure();
    await errorAssertion;
    expect(errorSocket.destroyCalls).toBe(1);
  });

  test("destroys a socket returned after the hard deadline fires inside the connector", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const connector: EnterpriseTlsConnector = () => {
      scheduler.fire();
      return socket;
    };
    const pending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      connector,
      scheduler,
    );

    await expect(pending).rejects.toThrow("TLS identity probe timed out");
    expect(socket.destroyCalls).toBe(1);
    expect(socket.endCalls).toBe(0);
  });

  test("handles a synchronous secure callback without a microtask loop", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const connector: EnterpriseTlsConnector = (options, callback) => {
      void options;
      callback(socket);
      return socket;
    };

    await expect(
      probeEnterpriseTlsOrigin(
        "https://kb.example.test",
        2_000,
        connector,
        scheduler,
      ),
    ).resolves.toMatchObject({ ca_trusted: true });
    await Promise.resolve();
    expect(socket.endCalls).toBe(1);
    expect(socket.destroyCalls).toBe(0);
    expect(scheduler.cancelCalls).toBe(1);
  });

  test("fails closed when a connector throws after a synchronous secure callback", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const connector: EnterpriseTlsConnector = (options, callback) => {
      void options;
      callback(socket);
      throw new Error("https://secret.internal/path?token=credential");
    };

    await expect(
      probeEnterpriseTlsOrigin(
        "https://kb.example.test",
        2_000,
        connector,
        scheduler,
      ),
    ).rejects.toThrow("E2E_BLOCKED: TLS certificate validation failed");
    await Promise.resolve();
    expect(socket.destroyCalls).toBe(1);
    expect(socket.endCalls).toBe(0);
    expect(scheduler.cancelCalls).toBe(1);
  });

  test("fails closed on an unauthorized peer without leaking peer details", async () => {
    const socket = new FakeTlsSocket(false, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const harness = connectorHarness(socket);
    const pending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      harness.connector,
      scheduler,
    );
    const assertion = expect(pending).rejects.toThrow(
      "E2E_BLOCKED: TLS certificate authority is not trusted",
    );
    harness.secure();
    await assertion;
    expect(socket.destroyCalls).toBe(1);
    expect(socket.endCalls).toBe(0);
  });

  test("sanitizes transport errors and rejects unsafe timeout values", async () => {
    const socket = new FakeTlsSocket(true, certificate(), "TLSv1.3");
    const scheduler = new ManualDeadlineScheduler();
    const harness = connectorHarness(socket);
    const pending = probeEnterpriseTlsOrigin(
      "https://kb.example.test",
      2_000,
      harness.connector,
      scheduler,
    );
    const assertion = expect(pending).rejects.toThrow(
      "E2E_BLOCKED: TLS certificate validation failed",
    );
    socket.fireError(new Error("https://secret.internal/path?token=credential"));
    scheduler.fire();
    harness.secure();
    await assertion;
    expect(socket.destroyCalls).toBe(1);
    expect(socket.endCalls).toBe(0);

    for (const timeoutMs of [0, 99, 60_001, Number.NaN]) {
      await expect(
        probeEnterpriseTlsOrigin(
          "https://kb.example.test",
          timeoutMs,
          harness.connector,
          scheduler,
        ),
      ).rejects.toThrow("TLS identity probe timeout is outside the safe range");
    }
  });
});
