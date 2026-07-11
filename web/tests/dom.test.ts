import { describe, expect, it, vi } from "vitest";

import { scrollIntoViewIfSupported } from "../src/lib/dom";

describe("scrollIntoViewIfSupported", () => {
  it("always returns undefined when an extension-patched method returns an object", () => {
    const scrollIntoView = vi.fn(() => ({ patched: true }));

    const result = scrollIntoViewIfSupported({ scrollIntoView }, { behavior: "smooth" });

    expect(result).toBeUndefined();
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth" });
  });

  it("does nothing when the browser does not implement scrollIntoView", () => {
    expect(scrollIntoViewIfSupported({})).toBeUndefined();
    expect(scrollIntoViewIfSupported(null)).toBeUndefined();
  });
});
