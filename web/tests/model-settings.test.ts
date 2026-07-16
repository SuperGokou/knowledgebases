import { describe, expect, it } from "vitest";

import { buildProviderUpdate, microUsdToUsd, usdToMicroUsd } from "../src/lib/model-settings";

describe("model provider pricing settings", () => {
  it("converts an operator-friendly USD price without floating point drift", () => {
    expect(usdToMicroUsd("0.80")).toBe(800_000);
    expect(usdToMicroUsd("2")).toBe(2_000_000);
    expect(microUsdToUsd(800_000)).toBe("0.8");
    expect(microUsdToUsd(null)).toBe("");
  });

  it("rejects incomplete or invalid price pairs", () => {
    expect(() => usdToMicroUsd("-1")).toThrow("价格不能为负数");
    expect(() => buildProviderUpdate({
      model: "qwen-plus",
      baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      apiKey: "",
      inputPriceUsd: "0.8",
      outputPriceUsd: "",
    })).toThrow("输入与输出价格必须同时填写");
  });

  it("builds the API payload using integer micro-dollars per million tokens", () => {
    expect(buildProviderUpdate({
      model: "qwen-plus",
      baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      apiKey: "secret-key",
      inputPriceUsd: "0.8",
      outputPriceUsd: "2",
    })).toEqual({
      model: "qwen-plus",
      base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      make_default: true,
      api_key: "secret-key",
      input_micro_usd_per_million_tokens: 800_000,
      output_micro_usd_per_million_tokens: 2_000_000,
    });
  });
});
