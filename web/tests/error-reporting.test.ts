import { describe, expect, it } from "vitest";

import {
  workspaceErrorCode,
  workspaceErrorLogRecord,
} from "../src/lib/error-reporting";

describe("workspace error reporting", () => {
  it("uses a valid framework digest as the user-visible error number", () => {
    const error = Object.assign(new Error("sensitive message"), { digest: "digest-123" });

    expect(workspaceErrorCode(error, () => "fallback")).toBe("WEB-digest-123");
  });

  it("does not expose messages, stacks, or unsafe digests in log records", () => {
    const error = Object.assign(new Error("database password"), {
      digest: "unsafe digest\nsecret",
    });
    const errorCode = workspaceErrorCode(error, () => "fallback-456");
    const record = workspaceErrorLogRecord(error, errorCode);

    expect(errorCode).toBe("WEB-fallback-456");
    expect(record).toEqual({
      event: "workspace_render_error",
      error_code: "WEB-fallback-456",
      digest: null,
      error_name: "Error",
    });
    expect(record).not.toHaveProperty("message");
    expect(record).not.toHaveProperty("stack");
  });
});
